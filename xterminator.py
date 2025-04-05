#!/usr/bin/env python3
"""
Alert Aggregation and Automated Response Module

This script runs on the defense VM and does the following:
  - Listens on port 9000 for Falco alerts (forwarded via Falco as JSON).
  - Appends each Falco alert to /var/log/falco_alerts.jsonl.
  - Tails the Snort alerts log (/var/log/snort_alerts.log) for structured alerts.
  - Aggregates alerts per host over a sliding window.
  - When a host’s aggregated alert count exceeds the threshold, it connects via SSH
    (using per-host credentials) and kills the malicious process.
"""
import re
import time
import json
import threading
import queue
import os
import paramiko
import ipaddress
from collections import defaultdict
from flask import Flask, request, jsonify

# Configuration parameters
ALERT_THRESHOLD = 8            # Number of alerts in sliding window required to trigger an action
TIME_WINDOW = 60               # Sliding window in seconds
# SSH credentials mapping for target hosts:
SSH_CREDENTIALS = {
    "10.0.0.10": {"username": "user", "password": "password1"},
    "10.0.0.12": {"username": "user", "password": "password2"},
    "10.0.1.10": {"username": "user", "password": "password3"},
}
DEFENSE_IP = "10.0.1.14"

DEFAULT_PROCESS_IDENTIFIER = "python"  # Fallback process identifier if not provided

alert_db = defaultdict(list)     # { host: [timestamp, ...] }
falco_alert_queue = queue.Queue()  # Queue for Falco alerts received via HTTP

# Flask app to receive Falco alerts from Sidekick
app = Flask(__name__)
FALCO_ALERTS_FILE = "/var/log/falco_alerts.jsonl"

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

@app.route("/alerts", methods=["POST"])
def receive_alert():
    try:
        alert = request.get_json(force=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    alert["timestamp"] = time.time()
    # If "host" is not present or not a valid IP, use the sender's IP.
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
    """Store the alert timestamp in alert_db and return current count for the host."""
    host = alert.get("host", "unknown")
    now = time.time()
    alert_db[host].append(now)
    alert_db[host] = [ts for ts in alert_db[host] if ts > now - TIME_WINDOW]
    return len(alert_db[host]), host

def kill_malicious_process(host, process_identifier):
    """
    If the target host is the local defense VM, execute the kill command locally.
    Otherwise, connect via SSH using the stored credentials.
    """
    if host == DEFENSE_IP or host == get_local_ip():
        print(f"Local host {host} detected; executing local kill command for process '{process_identifier}'")
        ret = os.system(f"pkill -f '{process_identifier}'")
        if ret == 0:
            print(f"Local process '{process_identifier}' killed on {host}.")
        else:
            print(f"Local kill command failed on {host}.")
        return

    creds = SSH_CREDENTIALS.get(host)
    if not creds:
        print(f"No SSH credentials for host {host}. Cannot kill process.")
        return

    print(f"Attempting to kill process '{process_identifier}' on host {host} via SSH")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, username=creds["username"], password=creds["password"], timeout=5)
        cmd = f"pkill -f '{process_identifier}'"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        if err:
            print(f"Error killing process on {host}: {err}")
        else:
            print(f"Process '{process_identifier}' killed on {host}.")
    except Exception as e:
        print(f"SSH connection failed for {host}: {e}")
    finally:
        ssh.close()

def process_falco_alerts():
    """Continuously process Falco alerts received via HTTP."""
    while True:
        try:
            alert = falco_alert_queue.get(timeout=1)
            count, host = aggregate_alert(alert)
            print(f"[Falco] Aggregated {count} alerts for host {host}")
            if count >= ALERT_THRESHOLD:
                kill_malicious_process(host, alert.get("process", DEFAULT_PROCESS_IDENTIFIER))
                alert_db[host] = []
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
    First, attempt to parse as JSON.
    If that fails, use regex to extract connection details.
    """
    try:
        alert = json.loads(line)
        return alert
    except json.JSONDecodeError:
        pass

    alert = {}
    # Look for a pattern like: {TCP} <src_ip>:<src_port> -> <dst_ip>:<dst_port>
    match = re.search(r"\{TCP\}\s+(\d+\.\d+\.\d+\.\d+):\d+\s+->\s+(\d+\.\d+\.\d+\.\d+):\d+", line)
    if match:
        src_ip = match.group(1)
        dst_ip = match.group(2)
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
            kill_malicious_process(host, alert.get("process", DEFAULT_PROCESS_IDENTIFIER))
            alert_db[host] = []

def run_http_server(port):
    """Start the Flask HTTP server on the given port."""
    app.run(host="0.0.0.0", port=port)

def main():
    PORT = 9000  # Port for Falco alert streaming
    http_thread = threading.Thread(target=run_http_server, args=(PORT,))
    http_thread.daemon = True
    http_thread.start()
    print(f"HTTP server for Falco alerts running on port {PORT}")

    # Start thread to process Falco alerts.
    falco_thread = threading.Thread(target=process_falco_alerts)
    falco_thread.daemon = True
    falco_thread.start()

    # Start thread to process Snort alerts.
    snort_thread = threading.Thread(target=process_snort_alerts)
    snort_thread.daemon = True
    snort_thread.start()

    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
