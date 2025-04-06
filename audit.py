#!/usr/bin/env python3
"""
Audit Script

This script audits the worm's activity on a target Ubuntu machine by reading the
dmsg.log file created in the user's home directory, checking for key events such as:
  - Ransomware operation completion
  - Worm mutation events 
  - File shredding events
It also checks for the existence of critical files/directories (like openme.txt and ~/Temp)
and whether any worm process (matching "netvermin_") is still running.
A summary report is printed to the console.
"""

import os
import re
import subprocess

def check_file_exists(path):
    return os.path.exists(path)

def read_log_file(log_path):
    if not os.path.exists(log_path):
        return []
    with open(log_path, 'r') as f:
        return f.readlines()

def count_log_entries(lines, pattern):
    regex = re.compile(pattern)
    count = sum(1 for line in lines if regex.search(line))
    return count

def count_errors(lines):
    return sum(1 for line in lines if "error" in line.lower())

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

def main():
    home = os.path.expanduser("~")
    log_file = os.path.join(home, "dmsg.log")
    temp_dir = os.path.join(home, "Temp")
    openme_file = os.path.join(home, "openme.txt")
    
    lines = read_log_file(log_file)
    
    ransomware_success = any("Ransomware operation completed on this host" in line for line in lines)
    mutation_events = count_log_entries(lines, r"Worm file mutated to")
    shredding_events = count_log_entries(lines, r"Securely shredded and removed")
    error_count = count_errors(lines)
    
    openme_exists = check_file_exists(openme_file)
    temp_exists = check_file_exists(temp_dir)
    
    worm_running, worm_pids = check_worm_process_running()
    
    print("----- Worm Evaluation Report -----")
    print(f"Log file path: {log_file}")
    print(f"Ransomware operation: {'Successful' if ransomware_success else 'Not detected'}")
    print(f"Worm mutation events detected: {mutation_events}")
    print(f"File shredding events detected: {shredding_events}")
    print(f"Error messages detected: {error_count}")
    print(f"'openme.txt' exists: {'Yes' if openme_exists else 'No'}")
    print(f"Temp directory exists: {'Yes' if temp_exists else 'No'}")
    
    if worm_running:
        print("Worm process is still running with PIDs: " + ", ".join(worm_pids))
    else:
        print("No worm process running; exverminator might have killed it.")
    
if __name__ == "__main__":
    main()
