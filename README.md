# netvermin
Proof-of-concept network worm written in Python

> **PLEASE READ:** This project is for **educational and research purposes only**. It is intended to demonstrate malware development techniques in a controlled test environment. **Do not deploy or use this code on production systems or any network without proper authorization.**

### Features

- **Network scanning.** Uses `nmap` and `ip route` parsing to discover hosts on the local network.
- **SSH-based propagation.** Attempts dictionary attacks on SSH-enabled machines using pre-defined lists of usernames and passwords.
  - **SMB-based propagation** is a WIP.
- **Payload simulation.** Encrypts infected user's files using AES-GCM and leaves a note as explanation.
- **Polymorphism.** Each mutation creates a new worm variant with unique encryption parameters.
- **Logging.** Detailed logging is implemented using a custom colorized formatter.

---

## Prerequisites

To run the worm in your test environment, you will need:

- **Operating System:** Linux
  - Windows compatibility is a WIP. Currently looking into `pyinstaller` to convert worm to a .exe file.
- **Python:** Python 3.6+ (recommended Python 3.10 or later)
- **Required Python Packages:**  
  - `netifaces`
  - `nmap`
  - `netaddr`
  
You can install the required packages using `pip`:

```bash
pip3 install --user netifaces nmap netaddr
```

### Disclaimer

This code is provided "as-is" without any warranty. The authors and contributors shall not be liable for any damages resulting from the use of this code. Use it only in a legal, ethical, and controlled environment.
