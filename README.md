# netvermin
Proof-of-concept network worm written in Python. Developed for CMPT 783 final project.

> **PLEASE READ:** This project is for **educational and research purposes only**. It is intended to demonstrate malware development techniques in a controlled test environment. **Do not deploy or use this code on production systems or any network without proper authorization.**

### Features

- **Network scanning.** Uses `socket` library and system route parsing to discover hosts on the local network. Comparable in speed to using `nmap` with aggressive timing.
- **SSH-based propagation.** Attempts a dictionary attack to crack hosts' SSH credentials.
  - **SMB-based propagation** is a work in progress.
- **Payload simulation.** Encrypts infected user's files using AES-GCM and leaves a note regarding the attack scenario.
- **Polymorphism.** Each mutation creates a new worm variant with unique encryption parameters.
- **Logging.** Detailed logging is implemented using a custom colorized formatter.

---

### Prerequisites
  
- VirtualBox or any other virtualization software (for creating isolated test environments)
- Linux / Windows (for the VM operating system)
- Python (recommended Python 3.10 or later)
- OpenSSH Server
  
Install the required packages on all VMs:
```bash
sudo apt install python3 python3-pip openssh-server
pip3 install --user netifaces netaddr paramiko cryptography
```
For Windows VMs, install Microsoft Visual C++ 14.0 or greater via [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (required for building `netifaces` package).

Execute the worm via:
```bash
chmod +x netvermin.py
python3 netvermin.py
```

### Disclaimer

This code is provided "as-is" without any warranty. The authors and contributors shall not be liable for any damages resulting from the use of this code. Use it only in a legal, ethical, and controlled environment.
