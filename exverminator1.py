#!/usr/bin/env python3
"""
Defense Module

This script runs on the defense VM and does the following:
  - Listens on port 9000 for Falco alerts (forwarded as JSON objects).
  - Appends each Falco alert to /var/log/falco_alerts.jsonl.
  - Tails the Snort alerts log (/var/log/snort_alerts.log) for structured alerts.
  - Aggregates alerts per host over a sliding window.
  - When a host’s aggregated alert count exceeds the threshold, it extracts the most common
    parent command and worm executable path from the aggregated alerts.
  - It then kills the malicious process using the aggregated parent command and cleans up
    any files in the same directory whose modification times are within ±1 second of the worm file.
  - Finally, it resets the alert aggregation for that host.
"""

import re
import time
import json
import threading
import queue
import os
import subprocess
import paramiko
import ipaddress
from datetime import datetime
from collections import defaultdict, Counter
from flask import Flask, request, jsonify

# Configuration parameters
ALERT_THRESHOLD = 4            # Number of alerts in sliding window required to trigger an action
TIME_WINDOW = 60               # Sliding window in seconds
# SSH credentials mapping for target hosts:
SSH_CREDENTIALS = {
    "10.0.0.10": {"username": "user", "password": "password1"},
    "10.0.0.12": {"username": "user", "password": "password2"},
    "10.0.1.10": {"username": "user", "password": "password3"},
}
DEFENSE_IP = "10.0.1.14"
DEFAULT_PROCESS_IDENTIFIER = "python"  # Fallback identifier if none is found

# Global structures: store full alert objects per host.
alerts_db = defaultdict(list)  
falco_alert_queue = queue.Queue()  

app = Flask(__name__)
FALCO_ALERTS_FILE = "/var/log/falco_alerts.jsonl"  # File to store Falco alerts

##################
# Helper functions
##################

def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except Exception:
        return False

def get_local_ip():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

####################################
# Core worm defense module functions
####################################

@app.route("/alerts", methods=["POST"])
def receive_alert():
    try:
        alert = request.get_json(force=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    alert["timestamp"] = time.time()
    # Ensure we have a valid host IP
    if not alert.get("host") or not is_valid_ip(alert.get("host", "")):
        if alert.get("hostname") and is_valid_ip(alert.get("hostname", "")):
            alert["host"] = alert["hostname"]
        else:
            alert["host"] = request.remote_addr
    falco_alert_queue.put(alert)
    try:
        with open(FALCO_ALERTS_FILE, "a") as f:
            f.write(json.dumps(alert) + "\n")
    except Exception as e:
        print(f"Failed to write Falco alert to file: {e}")
    return jsonify({"status": "received"}), 200

def aggregate_alert(alert):
    """
    Append alert to alerts_db[host] and remove any alerts older than TIME_WINDOW.
    Return the current count of alerts for that host.
    """
    host = alert.get("host", "unknown")
    now = time.time()
    alerts_db[host].append(alert)
    alerts_db[host] = [a for a in alerts_db[host] if a.get("timestamp", 0) > now - TIME_WINDOW]
    return len(alerts_db[host]), host

def most_common_parent_command(alerts):
    """
    Extract parent command from the output_fields of each alert. 
    Return the most common value.
    """
    parent_cmds = []
    for alert in alerts:
        of = alert.get("output_fields", {})
        parent_cmd = of.get("parent_cmd")
        if parent_cmd:
            parent_cmds.append(parent_cmd)
    if parent_cmds:
        common, _ = Counter(parent_cmds).most_common(1)[0]
        return common
    return DEFAULT_PROCESS_IDENTIFIER

def most_common_worm_filepath(alerts):
    """
    Extract the worm file path from the output_fields key 'proc.exepath' and return the most common one.
    """
    paths = []
    for alert in alerts:
        of = alert.get("output_fields", {})
        worm_path = of.get("proc.exepath")
        if worm_path:
            paths.append(worm_path)
    if paths:
        common, _ = Counter(paths).most_common(1)[0]
        return common
    return None

def cleanup_worm_files_local(worm_filepath):
    """
    Scan the directory containing worm_filepath and remove files whose modification times are within 1 second of worm_filepath's mtime.
    """
    directory = os.path.dirname(worm_filepath)
    try:
        worm_mtime = os.path.getmtime(worm_filepath)
    except Exception as e:
        print(f"Could not get modification time for {worm_filepath}: {e}")
        return
    margin = 1.0  
    for entry in os.scandir(directory):
        if entry.is_file():
            try:
                mtime = entry.stat().st_mtime
                if abs(mtime - worm_mtime) <= margin:
                    os.remove(entry.path)
                    print(f"Removed file {entry.path}")
            except Exception as e:
                print(f"Error processing file {entry.path}: {e}")

def cleanup_worm_files_remote(ssh, worm_filepath):
    """
    Use SSH to remove files in the worm file's directory that have modification times within 1 second of the worm file's mtime.
    """
    directory = os.path.dirname(worm_filepath)
    remote_cmd = f"""
WORM_MTIME=$(stat -c %Y '{worm_filepath}');
for file in $(find '{directory}' -maxdepth 1 -type f); do
    FILE_MTIME=$(stat -c %Y "$file");
    DIFF=$(echo "$FILE_MTIME - $WORM_MTIME" | bc);
    ABS_DIFF=$(echo "if ($DIFF < 0) -1 * $DIFF else $DIFF" | bc);
    if [ $(echo "$ABS_DIFF < 2" | bc -l) -eq 1 ]; then
       rm -f "$file";
       echo "Removed $file";
    fi;
done
"""
    try:
        _, stdout, stderr = ssh.exec_command(remote_cmd)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        if out:
            print(f"Remote cleanup output: {out}")
        if err:
            print(f"Remote cleanup error: {err}")
    except Exception as e:
        print(f"Failed remote cleanup: {e}")

def cleanup_worm_files(host, worm_filepath):
    """
    Determine if cleanup should be performed locally or remotely, and execute the appropriate cleanup function.
    """
    if worm_filepath is None:
        print("No worm file path provided, skipping cleanup.")
        return
    if host == DEFENSE_IP or host == get_local_ip():
        print(f"Running local cleanup for worm file {worm_filepath}")
        cleanup_worm_files_local(worm_filepath)
    else:
        creds = SSH_CREDENTIALS.get(host)
        if not creds:
            print(f"No SSH credentials for host {host}. Cannot perform remote cleanup.")
            return
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(host, username=creds["username"], password=creds["password"], timeout=5)
            print(f"Running remote cleanup for worm file {worm_filepath} on host {host}")
            cleanup_worm_files_remote(ssh, worm_filepath)
        except Exception as e:
            print(f"SSH connection failed for remote cleanup on {host}: {e}")
        finally:
            ssh.close()

def kill_malicious_process(host, aggregated_alerts):
    """
    Extract the most common parent command and worm file path from aggregated alerts.
    Issue the kill command for the process identified by the parent command,
    then perform cleanup of associated worm files, and finally reset the alerts for the host.
    """
    
    parent_cmd = most_common_parent_command(aggregated_alerts)
    worm_filepath = most_common_worm_filepath(aggregated_alerts)
    print(f"Triggering kill on host {host} using parent command: {parent_cmd}")
    
    # Determine if target is local:
    if host == DEFENSE_IP or host == get_local_ip():
        print(f"Local host {host} detected; executing local kill command for process '{parent_cmd}'")
        ret = os.system(f"pkill -f '{parent_cmd}'")
        if ret == 0:
            print(f"Local process '{parent_cmd}' killed on {host}.")
        else:
            print(f"Local kill command failed on {host}.")
    else:
        creds = SSH_CREDENTIALS.get(host)
        if not creds:
            print(f"No SSH credentials for host {host}. Cannot kill process.")
            return
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(host, username=creds["username"], password=creds["password"], timeout=5)
            cmd = f"pkill -f '{parent_cmd}'"
            stdin, stdout, stderr = ssh.exec_command(cmd)
            out = stdout.read().decode().strip()
            err = stderr.read().decode().strip()
            if err:
                print(f"Error killing process on {host}: {err}")
            else:
                print(f"Process '{parent_cmd}' killed on {host}.")
        except Exception as e:
            print(f"SSH connection failed for host {host}: {e}")
        finally:
            ssh.close()
    
    # Clean up worm files in the worm's directory
    print(f"Attempting cleanup on host {host} for worm file {worm_filepath}")
    cleanup_worm_files(host, worm_filepath)
    
    # Reset the aggregated alerts for this host
    alerts_db[host] = []

def process_falco_alerts():
    """Continuously process Falco alerts received via HTTP."""
    while True:
        try:
            alert = falco_alert_queue.get(timeout=1)
            count, host = aggregate_alert(alert)
            print(f"[Falco] Aggregated {count} alerts for host {host}")
            if count >= ALERT_THRESHOLD:
                candidate_alerts = alerts_db[host]
                kill_malicious_process(host, candidate_alerts)
        except queue.Empty:
            continue

def tail_file(file_path):
    """Generator that yields new lines appended to a file."""
    with open(file_path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.strip()

def parse_snort_alert(line):
    """
    Parse a Snort alert line.
    Attempt JSON parsing first; if that fails, use regex to extract connection details.
    For scanning alerts, use the source IP as the host.
    """
    try:
        alert = json.loads(line)
        return alert
    except json.JSONDecodeError:
        pass
    alert = {}
    match = re.search(r"\{TCP\}\s+(\d+\.\d+\.\d+\.\d+):\d+\s+->\s+(\d+\.\d+\.\d+\.\d+):\d+", line)
    if match:
        src_ip = match.group(1)
        alert["host"] = src_ip 
    else:
        alert["host"] = "unknown"
    alert["raw"] = line
    alert["timestamp"] = time.time()
    return alert

def process_snort_alerts():
    """Continuously tail the Snort alerts log and process alerts."""
    SNORT_ALERTS_FILE = "/var/log/snort_alerts.log"
    for line in tail_file(SNORT_ALERTS_FILE):
        alert = parse_snort_alert(line)
        count, host = aggregate_alert(alert)
        print(f"[Snort] Aggregated {count} alerts for host {host}")
        if count >= ALERT_THRESHOLD:
            candidate_alerts = alerts_db[host]
            kill_malicious_process(host, candidate_alerts)

def run_http_server(port):
    """Start the Flask HTTP server on the given port."""
    app.run(host="0.0.0.0", port=port)

def main():
    PORT = 9000  # Port for Falco alert streaming
    http_thread = threading.Thread(target=run_http_server, args=(PORT,))
    http_thread.daemon = True
    http_thread.start()
    print(f"HTTP server for Falco alerts running on port {PORT}")

    falco_thread = threading.Thread(target=process_falco_alerts)
    falco_thread.daemon = True
    falco_thread.start()

    snort_thread = threading.Thread(target=process_snort_alerts)
    snort_thread.daemon = True
    snort_thread.start()

    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
