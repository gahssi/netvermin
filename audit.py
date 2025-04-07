#!/usr/bin/env python3
"""
Audit Script

This script audits the worm's activity on a target Ubuntu machine by reading the
dmsg.log file (located in the user's home directory).
A summary report is printed to the console.
"""

import os
import re
import subprocess
from datetime import datetime

def check_file_exists(path):
    return os.path.exists(path)

def read_file_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, 'r') as f:
        return f.readlines()

def count_log_entries(lines, pattern):
    regex = re.compile(pattern, re.IGNORECASE)
    return sum(1 for line in lines if regex.search(line))

def count_errors(lines):
    return sum(1 for line in lines if "error" in line.lower())

def count_scanning_events(lines, pattern):
    regex = re.compile(pattern, re.IGNORECASE)
    return sum(1 for line in lines if regex.search(line))

def get_successful_ssh_logins(lines):
    """
    Extract successful SSH login events.
    Expects log lines matching:
      "SSH login succeeded on <ip> with <username>:<password>"
    Returns a list of tuples: (ip, username, password)
    """
    regex = re.compile(r"SSH login succeeded on (\d+\.\d+\.\d+\.\d+)\s+with\s+(\S+):(\S+)", re.IGNORECASE)
    results = []
    for line in lines:
        match = regex.search(line)
        if match:
            ip = match.group(1)
            username = match.group(2)
            password = match.group(3)
            results.append((ip, username, password))
    return results

def get_infected_hosts(log_path):
    """Parse the infected log file for unique IP addresses."""
    lines = read_file_lines(log_path)
    hosts = set()
    for line in lines:
        line = line.strip()
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
            hosts.add(line)
    return hosts

def check_worm_process_running():
    """Check for any running process whose name includes 'netvermin_'."""
    try:
        output = subprocess.check_output(["pgrep", "-f", "netvermin_"], text=True).strip()
        if output:
            pids = output.splitlines()
            return True, pids
    except subprocess.CalledProcessError:
        return False, []
    return False, []

def parse_timestamp(line):
    """
    Extract and parse the timestamp from a log line.
    Assumes the log line starts with a timestamp followed by " - ".
    The timestamp format is:
      YYYY-MM-DD HH:MM:SS,ffffff
    """
    try:
        ts_str = line.split(" - ")[0]
        return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S,%f")
    except Exception:
        return None

def calculate_scan_duration(lines):
    """
    Calculate the duration (in seconds) from the first line containing
    "Scanning subnets for new targets" to the first subsequent line containing "Discovered hosts:".
    """
    start_time = None
    end_time = None
    for line in lines:
        if "Scanning subnets for new targets" in line and start_time is None:
            start_time = parse_timestamp(line)
        elif start_time and "Discovered hosts:" in line:
            end_time = parse_timestamp(line)
            break
    if start_time and end_time:
        return (end_time - start_time).total_seconds()
    else:
        return None
    
def calculate_dict_attack_duration(lines):
    """
    Calculate the duration (in seconds) from the first "Attempting SSH connection"
    log line to the last "SSH login succeeded on" log line.
    """
    start_time = None
    end_time = None
    for line in lines:
        if "Attempting SSH connection" in line and start_time is None:
            start_time = parse_timestamp(line)
        if "SSH login succeeded on" in line:
            end_time = parse_timestamp(line)
    if start_time and end_time:
        return (end_time - start_time).total_seconds()
    else:
        return None

def main():
    home = os.path.expanduser("~")
    log_file = os.path.join(home, "dmsg.log")
    temp_dir = os.path.join(home, "Temp")
    openme_file = os.path.join(home, "openme.txt")
    infected_log = os.path.join(home, "Temp", "infected.log")
    
    lines = read_file_lines(log_file)
    
    zap_success = any("Ransomware operation completed on this host" in line for line in lines)
    mutation_events = count_log_entries(lines, r"Worm file mutated to")
    shredding_events = count_log_entries(lines, r"Securely shredded and removed")
    error_count = count_errors(lines)
    
    discovered_hosts_events = count_scanning_events(lines, r"Discovered hosts:")
    ssh_attempt_events = count_scanning_events(lines, r"Attempting SSH connection:")
    
    successful_ssh = get_successful_ssh_logins(lines)
    
    openme_exists = check_file_exists(openme_file)
    temp_exists = check_file_exists(temp_dir)
    
    infected_hosts = get_infected_hosts(infected_log)
    
    worm_running, worm_pids = check_worm_process_running()
    
    scan_duration = calculate_scan_duration(lines)
    dict_attack_duration = calculate_dict_attack_duration(lines)

    print("----- Worm Evaluation Report -----")

    print(f"Log file: {log_file}")
    
    print(f"Zap operation: {'Successful' if zap_success else 'Not detected'}")
    
    print(f"Worm mutation events: {mutation_events}")
    
    print(f"File shredding events: {shredding_events}")
    
    print(f"Error messages in log: {error_count}")
    
    print(f"Scanning events - 'Discovered hosts:': {discovered_hosts_events}")
    
    print(f"Scanning events - 'Attempting SSH connection:': {ssh_attempt_events}")
    
    print(f"Successful SSH logins: {len(successful_ssh)}")
    
    if successful_ssh:
        for ip, user, pwd in successful_ssh:
            print(f"  - SSH login succeeded on {ip} with {user}:{pwd}")
    
    if scan_duration is not None:
        print(f"Network scan duration: {scan_duration:.2f} seconds")
    else:
        print("Network scan duration: Not available")
        
    if dict_attack_duration is not None:
        print(f"Dictionary attack duration: {dict_attack_duration:.2f} seconds")
    else:
        print("Dictionary attack duration: Not available")

    print(f"'openme.txt' exists: {'Yes' if openme_exists else 'No'}")
    
    print(f"Temp directory exists: {'Yes' if temp_exists else 'No'}")
    
    print(f"Infected hosts (from infected.log): {', '.join(infected_hosts) if infected_hosts else 'None'}")
    
    if worm_running:
        print("netvermin still running with PIDs: " + ", ".join(worm_pids))
    else:
        print("No netvermin process running; exverminator possibly killed it.")

if __name__ == "__main__":
    main()
