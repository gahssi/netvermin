# netvermin
Proof-of-concept network worm written in Python. Developed for CMPT 783 final project.

> **PLEASE READ:** This project is for **educational and research purposes only**. It is intended to demonstrate malware development techniques in a controlled test environment. Do not deploy or use this code on production systems or any network without proper authorization.

### Features

- **Network scanning.** Uses `socket` library and system route parsing to discover hosts on the local network. Paired with thread-pooling, comparable in speed to using `nmap` with aggressive timing.
- **SSH-based propagation.** Attempts a dictionary attack to crack hosts' SSH credentials.
  - **SMB-based propagation** is a work in progress.
- **Payload simulation.** Encrypts infected user's files using AES-GCM and leaves a text note regarding the attack scenario.
- **Polymorphism.** Each mutation creates a new worm variant with unique encryption parameters.
- **Logging.** Detailed logging is implemented using a colorized formatter.

## exverminator

Worm defense implementation responsible for Snort and Falco alert aggregation and automated response

---

### Repository Contents
- VM images folder: https://1sfu-my.sharepoint.com/:f:/g/personal/aya119_sfu_ca/EiXP9f_qqlJKorVUc3mPux0Bd4S3hBx_cUjb0T9BSKU3Pg?e=cmnnvY 
  - router-test, 
  - ubuntu-test-attacker, 
  - ubuntu-test-2, 
  - ubuntu-test-3, 
  - ubuntu-test-4, 
  - ubuntu-test-defense, 
  - Windows10
  
- netvermin.py – worm script

- exverminator.py – defense aggregator script

- attacker_run.sh – shell script for the attacker machine to launch the worm

- attacker_cleanup.sh – shell script for the attacker machine to clean up worm-related files after execution

- target_cleanup.sh – shell script for target Linux machines to remove worm traces and restore original directories


### Environment and Dependencies
  
- VirtualBox or any other virtualization software (for creating isolated test environments)
- Linux / Windows (for the VM operating system)
- Python (recommended Python 3.10 or later)
- OpenSSH Server
  
The VM images are pre-packaged with all the required dependencies including:
```bash
sudo apt install python3 python3-pip openssh-server
pip3 install --user netifaces netaddr paramiko cryptography
pip3 install flask # only on defense VM
```

The Windows VMs is pre-installed with Microsoft Visual C++ 14.0 from [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (required for building `netifaces` package).

## Setup and Execution Instructions

#### 1. Attacker Machine Setup
On the attacker machine, the worm is located in the ~/worm directory. Two helper shell scripts are provided for running the worm and cleaning up after execution.

To run the worm:
```bash
./attacker_run.sh
```

The script performs the following actions:
- Changes into the ~/worm directory.
- Copies netvermin.py from the parent directory.
- Sets executable permissions.
- Executes the worm using Python 3.

After the worm run, you may clean up the worm-related files by running:
```bash
./attacker_cleanup.sh
```

This script removes any infection log files and mutated worm copies (files matching `netvermin_*.py`) from the home directory.

#### 2. Target Machine Setup
On each target machine, a script is provided to remove the worm traces and restore the system to a pre-infection state.

Run the following on each target machine:
```bash
./target_cleanup.sh
```

This script performs the following:
- Deletes Documents.tar.enc, openme.txt, and dmsg.log.
- Removes the ~/Temp directory.
- Recreates the ~/Documents directory.

#### 3. Defense VM Setup

On the defense VM, perform the following steps:

Start Snort to capture alerts:

```bash
sudo snort -A console -i enp0s3 -c /etc/snort/snort.conf
```

In a separate terminal, start the exverminator:
```bash
sudo python3 exverminator.py
```

The exverminator aggregates alerts from both Snort and Falco and automates the response (including process termination and cleanup) once the infection threshold is exceeded.

## Test Cases

We have designed three primary test cases:

**Test Case 1:**  
- Configuration: Run the worm from a Linux attacker machine. Target network includes one Linux VM in LAN 1 and two Linux VMs in LAN 2. (No defense sensor.)
- Expected Outcome: The worm propagates from the attacker machine to all target Linux machines.

**Test Case 2:**  
- Configuration: Run the worm from a Linux attacker machine. Target network includes one Linux VM in LAN 1 and one Linux VM and one Windows VM in LAN 2. (No defense sensor.)
- Expected Outcome: The worm infects the Linux targets and the Windows target.

**Test Case 3:**  
- Configuration: Similar to test case 1, except after you run the worm from a Linux attacker machine, start the defense sensor and run the exverminator defense program.
- Expected Outcome: The exverminator defense system aggregates alerts from IDS sensors, reaches the configured alert threshold, and promptly terminates and cleans up the worm on the infected target machines.


### Disclaimer

This code is provided "as-is" without any warranty. The authors and contributors shall not be liable for any damages resulting from the use of this code. Use it only in a legal, ethical, and controlled environment.
