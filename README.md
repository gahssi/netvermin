# netvermin
Proof-of-concept network worm written in Python. Developed for CMPT 783 final project.

> **PLEASE READ:** This project is for **educational and research purposes only**. It is intended to demonstrate malware development techniques in a controlled test environment. **Do not deploy or use this code on production systems or any network without proper authorization.**

### Features

- **Network scanning.** Uses `nmap` and `ip route` parsing to discover hosts on the local network.
- **SSH-based propagation.** Attempts dictionary attacks to crack target machines' weak SSH credentials.
  - **SMB-based propagation** is in progress.
- **Payload simulation.** Encrypts infected user's files using AES-GCM and leaves a note regarding the attack scenario.
- **Polymorphism.** Each mutation creates a new worm variant with unique encryption parameters.
- **Logging.** Detailed logging is implemented using a custom colorized formatter.

---

### Prerequisites
  
- VirtualBox or any other virtualization software (for creating isolated test environments)
- Linux (for the VM operating system)
  - Porting worm to Windows is in progress - looking into `pyinstaller` to package worm script into a Windows executable
- Python (recommended Python 3.10 or later)
  
Install the required packages on all VMs:
```bash
sudo apt install python3 python3-pip nmap
pip3 install --user netifaces python-nmap netaddr
```

Execute the worm via:
```bash
chmod +x netvermin.py
python3 netvermin.py
```

### Disclaimer

This code is provided "as-is" without any warranty. The authors and contributors shall not be liable for any damages resulting from the use of this code. Use it only in a legal, ethical, and controlled environment.
