#!/usr/bin/env python3
import sys
import os
import platform
import subprocess
from pathlib import Path


def ensure_compatible_environment():
    """Smart environment setup - only creates venv when dependencies are missing or incompatible."""

    def check_dependencies():
        missing_deps = []
        try:
            import paramiko
            paramiko.SSHClient()
        except ImportError:
            missing_deps.append("paramiko")
        except Exception as e:
            print(f"⚠️  paramiko available but may have compatibility issues: {e}")

        try:
            import prettytable
            prettytable.PrettyTable()
        except ImportError:
            missing_deps.append("prettytable")
        except Exception as e:
            print(f"⚠️  prettytable available but may have compatibility issues: {e}")

        return missing_deps

    missing_deps = check_dependencies()

    if not missing_deps:
        print("✅ All required dependencies are available in current environment")
        return

    print(f"📦 Missing dependencies: {', '.join(missing_deps)}")
    print("🔄 Attempting to set up isolated environment...")

    arch = platform.machine()
    script_dir = Path(__file__).parent
    venv_path = script_dir / f".venv_{arch}"
    venv_python = venv_path / "bin" / "python"

    if sys.prefix == str(venv_path):
        return

    if venv_python.exists():
        try:
            result = subprocess.run(
                [str(venv_python), "-c",
                 "import paramiko, prettytable; paramiko.SSHClient(); prettytable.PrettyTable()"],
                capture_output=True,
                timeout=10
            )
            if result.returncode == 0:
                print("✅ Found existing compatible virtual environment")
                os.execv(str(venv_python), [str(venv_python)] + sys.argv)
        except Exception as e:
            print(f"⚠️  Existing venv test failed: {e}")

    print(f"🔧 Creating virtual environment for {arch} architecture...")

    try:
        import venv
        venv.create(venv_path, with_pip=True)
        print("✅ Virtual environment created successfully")

        pip_path = venv_path / "bin" / "pip"
        print("📦 Installing dependencies...")
        subprocess.run([str(pip_path), "install", "--upgrade", "pip"], check=True, capture_output=True, timeout=60)
        subprocess.run([str(pip_path), "install", "paramiko", "prettytable"], check=True, capture_output=True,
                       timeout=120)
        print("✅ Dependencies installed successfully")
        print("🔄 Restarting script with virtual environment...\n")
        os.execv(str(venv_python), [str(venv_python)] + sys.argv)

    except ImportError:
        print("❌ Virtual environment module not available on this system")
        print("💡 Install with: sudo apt-get install python3-venv")
        print("🔄 Continuing with system Python...")
    except subprocess.CalledProcessError as e:
        print(f"❌ Virtual environment setup failed: {e}")
        print("💡 This might be due to missing system packages:")
        print("   - Ubuntu/Debian: sudo apt-get install python3-venv python3-pip")
        print("   - CentOS/RHEL: sudo yum install python3-venv python3-pip")
        print("🔄 Continuing with system Python...")
    except Exception as e:
        print(f"❌ Virtual environment setup failed: {e}")
        print("🔄 Continuing with system Python...")

    final_missing = check_dependencies()
    if final_missing:
        print(f"\n❌ Still missing dependencies: {', '.join(final_missing)}")
        print(f"📦 Install with: pip3 install {' '.join(final_missing)}")

        user_choice = input("Continue anyway? This may cause script failures. (Y/N): ").lower()
        if user_choice not in ['y', 'yes']:
            print("Script execution cancelled.")
            sys.exit(1)
        print("⚠️  Proceeding with missing dependencies - expect potential failures...\n")
    else:
        print("✅ All dependencies now available. Continuing...\n")


ensure_compatible_environment()

__author__ = "Pronoy Dasgupta"
__copyright__ = "Copyright 2024 (C) Cisco Systems, Inc."
__credits__ = "Pronoy Dasgupta"
__version__ = "3.0.0"
__maintainer__ = "Pronoy Dasgupta"
__email__ = "prongupt@cisco.com"
__status__ = "production"

import paramiko
import glob
from prettytable import PrettyTable
import time
import getpass
import re
import logging
import datetime
from typing import List, Tuple, Dict, Any, Optional

# === CONFIGURATION ===
SSH_TIMEOUT_SECONDS = 15
PROMPT_PATTERNS = [r'#\s*$', r'>\s*$', r'\]\s*$', r'\)\s*$', r'\$\s*$']
REMOTE_PATH = '/misc/disk1/'
LOCAL_FILE_PATTERN = os.path.expanduser('~/monitor*')

FAN_IMPACTED_VERSIONS = {
    "8804-FAN": {"Not Impacted": ["V03"], "Impacted": ["V01", "V02"]},
    "8808-FAN": {"Not Impacted": ["V03"], "Impacted": ["V01", "V02"]},
    "8812-FAN": {"Not Impacted": ["V02"], "Impacted": ["V01"]},
    "8818-FAN": {"Not Impacted": ["V03"], "Impacted": ["V01", "V02"]},
}

CLI_PRECHECK_RESULTS = {}
PYTHON_PRECHECK_RESULTS = {}
PYTHON_PHASE2_ERRORS_DETECTED = False


# === EXCEPTIONS ===
class DeviceError(Exception):
    pass


class FileUploadError(Exception):
    pass


class SSHConnectionError(Exception):
    pass


class RouterCommandError(Exception):
    pass


class PlatformStatusError(DeviceError):
    pass


class FabricReachabilityError(DeviceError):
    pass


class FabricLinkDownError(DeviceError):
    pass


class NpuLinkError(DeviceError):
    pass


class NpuStatsError(DeviceError):
    pass


class NpuDriverError(DeviceError):
    pass


class FabricPlaneStatsError(DeviceError):
    pass


class AsicErrorsError(DeviceError):
    pass


class InterfaceStatusError(DeviceError):
    pass


class AlarmError(DeviceError):
    pass


class LcAsicErrorsError(DeviceError):
    pass


class FanTrayError(DeviceError):
    pass


class EnvironmentError(DeviceError):
    pass


class FpdStatusError(DeviceError):
    pass


class FileProcessingError(Exception):
    pass


class ScriptExecutionError(Exception):
    pass


class HostnameRetrievalError(Exception):
    pass


# === OUTPUT COORDINATION ===
class Tee:
    def __init__(self, stdout_stream, file_object):
        self.stdout = stdout_stream
        self.file_object = file_object

    def write(self, data):
        self.stdout.write(data)
        self.stdout.flush()
        self.file_object.write(data)
        self.file_object.flush()

    def flush(self):
        self.stdout.flush()
        self.file_object.flush()


# === OUTPUT COORDINATION ===
class CompactFormatter(logging.Formatter):
    """Custom formatter to add color to success and failure messages."""

    def __init__(self):
        super().__init__(datefmt='%Y-%m-%d %H:%M:%S')

    FORMATS = {
        logging.ERROR: '%(asctime)s - %(levelname)s - \033[1;91m%(message)s\033[0m',
        logging.WARNING: '%(asctime)s - %(levelname)s - \033[1;93m%(message)s\033[0m',
        logging.INFO: '%(asctime)s - %(levelname)s - %(message)s',
        logging.CRITICAL: '%(asctime)s - %(levelname)s - \033[1;91m%(message)s\033[0m',
        logging.DEBUG: '%(asctime)s - %(levelname)s - %(message)s',
    }

    def format(self, record):
        msg = record.getMessage()

        # Condition to color all success messages green
        if msg.startswith('✅') or msg.startswith('✓'):
            return f'{self.formatTime(record, self.datefmt)} - \033[92m{record.levelname}\033[0m - \033[1;92m{msg}\033[0m'

        # --- FIX: Broaden the condition to catch all failure/cross mark messages ---
        elif msg.startswith('❌') or msg.startswith('✗'):
            # This now covers "✗ ... failed:", "✗ ... errors detected", etc.
            return f'{self.formatTime(record, self.datefmt)} - \033[91m{record.levelname}\033[0m - \033[1;91m{msg}\033[0m'
        # --- END OF FIX ---

        else:
            log_fmt = self.FORMATS.get(record.levelno, self.FORMATS[logging.INFO])
            formatter = logging.Formatter(log_fmt, datefmt=self.datefmt)
            return formatter.format(record)


# === SSH UTILITIES ===
def connect_with_retry(client, router_ip, username, password, max_retries=3):
    """Retry SSH connection with increasing delays"""
    for attempt in range(max_retries):
        try:
            logging.info(f"Connection attempt {attempt + 1} of {max_retries}...")
            client.connect(
                router_ip, port=22, username=username, password=password,
                timeout=SSH_TIMEOUT_SECONDS, look_for_keys=False, allow_agent=False,
                banner_timeout=120, auth_timeout=120,
                disabled_algorithms={'keys': ['rsa-sha2-256', 'rsa-sha2-512']}
            )
            time.sleep(2)
            logging.info(f"✅ Connection successful on attempt {attempt + 1}")
            return True
        except Exception as e:
            logging.warning(f"⚠️  Connection attempt {attempt + 1} failed: {type(e).__name__}")
            if attempt < max_retries - 1:
                wait_time = (attempt + 1) * 5
                logging.info(f"⏳ Waiting {wait_time} seconds before retry...")
                time.sleep(wait_time)
            else:
                logging.error(f"❌ All {max_retries} connection attempts failed")
                raise e
    return False


def read_and_print_realtime(shell_obj: paramiko.Channel, timeout_sec: int = 60, print_real_time: bool = True) -> Tuple[
    str, bool]:
    full_output_buffer = ""
    start_time = time.time()
    prompt_found = False
    prompt_check_buffer = ""

    while time.time() - start_time < timeout_sec:
        if shell_obj.recv_ready():
            try:
                data = shell_obj.recv(65535).decode('utf-8', errors='ignore')
                if data:
                    if print_real_time:
                        print(f"{data}", end='')
                    full_output_buffer += data
                    prompt_check_buffer += data
                    if len(prompt_check_buffer) > 500:
                        prompt_check_buffer = prompt_check_buffer[-500:]
                    lines = prompt_check_buffer.strip().splitlines()
                    if lines:
                        last_line = lines[-1]
                        for pattern in PROMPT_PATTERNS:
                            if re.search(pattern, last_line):
                                prompt_found = True
                                if print_real_time and not data.endswith('\n'):
                                    print()
                                return full_output_buffer, prompt_found
            except Exception as e:
                logging.error(f"Error receiving data: {e}")
                break
        else:
            time.sleep(0.1)

    if print_real_time and full_output_buffer and not full_output_buffer.endswith('\n'):
        print()
    return full_output_buffer, prompt_found


def execute_command_in_shell(shell: paramiko.Channel, command: str, command_description: str,
                             timeout: int = 60, print_real_time_output: bool = False, cli_output_file=None) -> str:
    logging.info(f"Sending '{command_description}' ('{command}')...")

    if cli_output_file:
        cli_output_file.write(f"\n--- Command: {command} ---\n")
        cli_output_file.flush()

    pre_command_flush_output = ""
    pre_flush_start_time = time.time()
    while time.time() - pre_flush_start_time < 0.5:
        if shell.recv_ready():
            data = shell.recv(65535).decode('utf-8', errors='ignore')
            if data:
                pre_command_flush_output += data
            else:
                break
        else:
            time.sleep(0.01)

    if pre_command_flush_output:
        logging.debug(f"Flushed {len(pre_command_flush_output)} characters from buffer BEFORE '{command_description}'.")
        if cli_output_file:
            cli_output_file.write(f"\n--- Pre-command Buffer Flush before '{command_description}' ---\n")
            cli_output_file.write(pre_command_flush_output)
            cli_output_file.flush()

    shell.send(command + "\n")
    time.sleep(0.5)
    output, prompt_found = read_and_print_realtime(shell, timeout_sec=timeout, print_real_time=print_real_time_output)

    if cli_output_file:
        cli_output_file.write(output)
        cli_output_file.flush()

    if not prompt_found:
        logging.warning(f"Prompt not detected after '{command_description}'. Attempting to send newline and re-check.")
        shell.send("\n")
        output_retry, prompt_found_retry = read_and_print_realtime(shell, timeout_sec=5,
                                                                   print_real_time=print_real_time_output)
        if cli_output_file:
            cli_output_file.write(output_retry)
            cli_output_file.flush()
        output += output_retry
        prompt_found = prompt_found_retry
        if not prompt_found:
            raise RouterCommandError(f"Failed to reach prompt after '{command_description}' re-check. Output: {output}")

    logging.debug(f"Performing post-command buffer flush after '{command_description}'.")
    post_command_flush_output = ""
    post_flush_start_time = time.time()
    while time.time() - post_flush_start_time < 5:
        if shell.recv_ready():
            data = shell.recv(65535).decode('utf-8', errors='ignore')
            if data:
                post_command_flush_output += data
            else:
                break
        else:
            time.sleep(0.05)

    if post_command_flush_output:
        logging.debug(f"Flushed {len(post_command_flush_output)} characters from buffer AFTER '{command_description}'.")
        if cli_output_file:
            cli_output_file.write(f"\n--- Post-command Buffer Flush after '{command_description}' ---\n")
            cli_output_file.write(post_command_flush_output)
            cli_output_file.flush()

    return output


def format_execution_time(seconds):
    """Format execution time in human-readable format"""
    hours, remainder = divmod(int(seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours > 0:
        return f"{hours:02d}h {minutes:02d}m {seconds:02d}s"
    elif minutes > 0:
        return f"{minutes:02d}m {seconds:02d}s"
    else:
        return f"{seconds:02d}s"


def countdown_timer(seconds, console_stream):
    """Enhanced countdown timer matching Part II"""
    logging.info(f'Countdown Timer: Starting for {seconds // 60:02d}:{seconds % 60:02d}.')
    while seconds:
        mins, secs = divmod(seconds, 60)
        timer = f'{mins:02d}:{secs:02d}'
        console_stream.write(f'\rCountdown Timer: {timer}')
        console_stream.flush()
        time.sleep(1)
        seconds -= 1
    console_stream.write('\r' + ' ' * 30 + '\r')
    console_stream.flush()
    logging.info('Countdown Timer: 00:00 - Time is up!')


# === FILE UPLOAD UTILITIES ===
def upload_monitor_files_to_router(existing_client: paramiko.SSHClient, router_ip: str) -> bool:
    """Upload monitor Python files using the existing SSH client connection"""
    try:
        logging.info("--- Starting Monitor File Upload ---")
        print(f"📤 Uploading monitor scripts to {router_ip}...")

        transport = existing_client.get_transport()
        if not transport or not transport.is_active():
            raise FileUploadError("Existing SSH connection is not active")

        sftp = paramiko.SFTPClient.from_transport(transport)

        try:
            sftp.chdir(REMOTE_PATH)
            logging.info(f"Successfully accessed remote directory: {REMOTE_PATH}")
        except IOError:
            logging.error(f"Remote path {REMOTE_PATH} not accessible on {router_ip}")
            raise FileUploadError(f"Cannot access remote directory {REMOTE_PATH}")

        files_to_upload = glob.glob(LOCAL_FILE_PATTERN)
        if not files_to_upload:
            logging.warning(f"No monitor files found matching pattern: {LOCAL_FILE_PATTERN}")
            raise FileUploadError(f"No monitor files found in {os.path.dirname(LOCAL_FILE_PATTERN)}")

        uploaded_count = 0
        for file_path in files_to_upload:
            filename = os.path.basename(file_path)
            try:
                logging.info(f"Uploading {filename}...")
                sftp.put(file_path, filename)
                logging.info(f"✅ Uploaded {filename} successfully")
                uploaded_count += 1
            except Exception as e:
                logging.error(f"Failed to upload {filename}: {e}")

        sftp.close()

        if uploaded_count > 0:
            logging.info(f"✅ Successfully uploaded {uploaded_count} monitor files")
            return True
        else:
            raise FileUploadError("No files were uploaded successfully")

    except Exception as e:
        logging.error(f"File upload operation failed: {e}")
        raise FileUploadError(f"Monitor file upload failed: {e}")


def check_and_upload_monitor_files(shell: paramiko.Channel, router_ip: str, username: str, password: str,
                                   cli_output_file=None, existing_client=None) -> bool:
    """Check for monitor files on router and upload only if needed"""
    try:
        logging.info("--- Checking Monitor Files on Router ---")
        logging.info("Checking for existing monitor files on device...")

        output = execute_command_in_shell(shell, "dir harddisk: | i .py", "check for monitor files",
                                          timeout=30, print_real_time_output=False, cli_output_file=cli_output_file)

        required_files = [
            "monitor_8800_system_v2_3_msft_bash_group0.py",
            "monitor_8800_system_v2_3_msft_bash_group1.py",
            "monitor_8800_system_v2_3_msft_bash_group2.py",
            "monitor_8800_system_v2_3_msft_bash_group3.py"
        ]

        files_found = []
        for required_file in required_files:
            if required_file in output:
                files_found.append(required_file)

        files_exist = len(files_found) >= 4

        if files_exist:
            logging.info("✅ Files already on hard drive...skipping upload")
            files_display = ", ".join(
                [f.replace("monitor_8800_system_v2_3_msft_bash_group", "group") for f in files_found])
            print(f"📁 Monitor files detected on device: {files_display}")
            return True
        else:
            logging.info("📤 Files not available...uploading to HD first")
            if files_found:
                logging.info(f"Found {len(files_found)} of 4 required files, uploading missing files")
            return upload_monitor_files_to_router(existing_client, router_ip)

    except Exception as e:
        logging.error(f"Error during file check: {e}. Attempting upload...")
        return upload_monitor_files_to_router(existing_client, router_ip)


def get_hostname(shell: paramiko.Channel, cli_output_file=None) -> str:
    logging.info("Attempting to retrieve hostname using 'show running-config | i hostname'...")
    output = execute_command_in_shell(shell, "show running-config | i hostname", "get hostname", timeout=10,
                                      print_real_time_output=False, cli_output_file=cli_output_file)
    for line in output.splitlines():
        match = re.search(r"^\s*hostname\s+(\S+)", line)
        if match:
            hostname = match.group(1)
            hostname = hostname.replace('.', '-')
            logging.info(f"Full hostname detected: {hostname}")
            return hostname
    logging.warning("Could not parse hostname from 'show running-config | i hostname' output. Using 'unknown_host'.")
    return "unknown_host"


def get_hostname_from_router(router_ip, username, password):
    """Enhanced hostname retrieval"""
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        logging.info(f"Attempting to connect to {router_ip} to retrieve hostname...")
        connect_with_retry(client, router_ip, username, password)
        logging.info(f"Successfully connected to {router_ip} for hostname retrieval.")

        stdin, stdout, stderr = client.exec_command("show running | i hostname", timeout=30)
        output = stdout.read().decode('utf-8', errors='ignore')
        error_output = stderr.read().decode('utf-8', errors='ignore')

        if error_output:
            logging.error(f"Error during hostname retrieval command: {error_output}")
            raise HostnameRetrievalError(f"Command execution failed: {error_output}")

        lines = output.strip().splitlines()
        if not lines:
            raise HostnameRetrievalError("No output received for hostname command.")

        hostname = None
        for line in lines:
            line = line.strip()
            if line.startswith("hostname "):
                hostname = line.split(" ", 1)[1].strip()
                break

        if not hostname:
            raise HostnameRetrievalError(f"Hostname not found in command output")

        sanitized_hostname = hostname.replace('.', '-')
        logging.info(f"Retrieved full hostname: {hostname}, Sanitized for directory: {sanitized_hostname}")
        return sanitized_hostname

    except paramiko.AuthenticationException as e:
        raise HostnameRetrievalError(f"Authentication failed during hostname retrieval. Error: {e}")
    except paramiko.SSHException as e:
        raise HostnameRetrievalError(f"SSH error during hostname retrieval: {e}")
    except Exception as e:
        raise HostnameRetrievalError(f"An unexpected error occurred during hostname retrieval: {e}")
    finally:
        if client:
            client.close()
            logging.info(f"Temporary SSH connection for hostname retrieval closed.")


def get_chassis_model(shell: paramiko.Channel, cli_output_file=None) -> str:
    output = execute_command_in_shell(shell, "show inventory chassis", "get chassis model from inventory", timeout=30,
                                      print_real_time_output=False, cli_output_file=cli_output_file)
    match = re.search(r"PID:\s*(\S+)\s*,", output)
    if match:
        chassis_model = match.group(1).strip()
        logging.info(f"Chassis model (PID) detected: {chassis_model}")
        return chassis_model
    logging.warning(
        "Could not parse chassis model (PID) from 'show inventory chassis' output. Using 'unknown_chassis'.")
    return "unknown_chassis"


# === PARSING UTILITIES ===
def parse_inventory_for_serial_numbers(inventory_output: str) -> Dict[str, Dict[str, str]]:
    card_info = {}
    lines = inventory_output.splitlines()
    current_location = None
    for line in lines:
        name_match = re.search(r'NAME: "(\d+/\S+)",', line)
        if name_match:
            current_location = name_match.group(1)
        pid_vid_sn_match = re.search(r'PID:\s*([^,]+?)\s*,\s*VID:\s*([^,]+?)\s*,\s*SN:\s*(\S+)', line)
        if pid_vid_sn_match and current_location:
            card_info[current_location] = {
                "PID": pid_vid_sn_match.group(1),
                "VID": pid_vid_sn_match.group(2),
                "SN": pid_vid_sn_match.group(3)
            }
            current_location = None
    return card_info


def parse_inventory_optics_from_string(output: str) -> Dict[str, Dict[str, str]]:
    optics_info = {}
    lines = output.splitlines()
    current_location = None
    intf_pattern = re.compile(r'NAME: "((?:Gi|Te|Hu|Fo|Eth|Fa|Se|POS|Ce|nve|Vxlan|FH)\S+)",', re.IGNORECASE)
    pid_pattern = re.compile(r'PID: (\S+)\s*,\s*VID: (\S+),\s*SN: (\S+)')

    for line in lines:
        name_match = intf_pattern.search(line)
        if name_match:
            current_location = name_match.group(1)
            continue
        pid_match = pid_pattern.search(line)
        if pid_match and current_location:
            optics_info[current_location] = {
                "PID": pid_match.group(1),
                "VID": pid_match.group(2),
                "SN": pid_match.group(3)
            }
            current_location = None
    if not optics_info:
        logging.debug("No optics inventory items parsed from 'show inventory' output.")
    return optics_info


def parse_inventory_lcfc_from_string(output: str) -> Dict[str, Dict[str, str]]:
    lcfc_info = {}
    lines = output.splitlines()
    current_location = None
    card_pattern = re.compile(r'NAME: "(0/\d+(?:/\d+)?(?:/CPU0)?|0/(?:RP|LC|FC|RSP)\d*(?:/\d+)?(?:/CPU0)?)",')
    pid_pattern = re.compile(r'PID: (\S+)\s*,\s*VID: (\S+),\s*SN: (\S+)')

    for line in lines:
        name_match = card_pattern.search(line)
        if name_match:
            current_location = name_match.group(1)
            continue
        pid_match = pid_pattern.search(line)
        if pid_match and current_location:
            lcfc_info[current_location] = {
                "PID": pid_match.group(1),
                "VID": pid_match.group(2),
                "SN": pid_match.group(3)
            }
            current_location = None
    if not lcfc_info:
        logging.warning("No LC/FC/RP inventory items parsed from 'show inventory' output.")
    return lcfc_info


def parse_interface_status_from_strings(summary_output: str, brief_output: str) -> Dict[str, Dict[str, str]]:
    interface_statuses: Dict[str, Dict[str, str]] = {}

    if brief_output:
        brief_line_pattern = re.compile(
            r"^\s*(\S+)\s+(up|down|admin-down|not connect|unknown|--)\s+(up|down|admin-down|not connect|unknown|--)\s+.*$",
            re.IGNORECASE
        )

        brief_lines = [
            line for line in brief_output.splitlines()
            if not re.match(
                r"^\s*(Intf|Name|State|LineP|Encap|MTU|BW|---|\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+|RP/\d+/\S+#|show interface brief)\s*$",
                line.strip())
               and line.strip()
        ]

        for line in brief_lines:
            match = brief_line_pattern.match(line)
            if match:
                intf_name = match.group(1).strip()
                brief_admin_status = match.group(2).strip()
                brief_protocol_status = match.group(3).strip()

                interface_statuses.setdefault(intf_name, {})["brief_status"] = brief_admin_status.lower()
                interface_statuses.setdefault(intf_name, {})["brief_protocol"] = brief_protocol_status.lower()
            else:
                logging.debug(f"Skipping brief line (no regex match): '{line}'")
    else:
        logging.debug("No 'show interface brief' output section found for parsing.")

    return interface_statuses


def parse_fpd_status_from_string(fpd_output: str) -> Dict[Tuple[str, str], Dict[str, str]]:
    fpd_statuses: Dict[Tuple[str, str], Dict[str, str]] = {}

    fpd_line_pattern = re.compile(
        r"^\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S*?)\s*(\S+)\s+(\S+)\s+(\S*)\s+(\S*)\s+(\S+)\s*$"
    )

    lines = fpd_output.splitlines()
    data_table_started = False
    for line in lines:
        stripped_line = line.strip()
        if not stripped_line:
            continue

        if "Location   Card type" in stripped_line and "HWver FPD device" in stripped_line:
            data_table_started = True
            continue

        if data_table_started and "--------------------------------" in stripped_line:
            continue

        if not data_table_started:
            continue

        match = fpd_line_pattern.match(stripped_line)
        if match:
            location = match.group(1)
            fpd_device = match.group(4)
            status = match.group(6)

            key = (location, fpd_device)
            fpd_statuses[key] = {
                "Location": location,
                "FPD_Device": fpd_device,
                "Status": status
            }
        else:
            logging.debug(f"Skipping FPD line (no regex match): '{stripped_line}'")

    if not fpd_statuses:
        logging.warning("No FPD status items parsed from 'show hw-module fpd' output.")
    return fpd_statuses


# === CHECK DECORATORS ===
def _run_section_check(section_name: str, check_func: callable, section_statuses: Dict[str, str],
                       overall_script_failed_ref: List[bool], *args, **kwargs):
    try:
        logging.info(f"--- Running {section_name} ---")
        result = check_func(*args, **kwargs)
        logging.info(f"✓ {section_name} passed")
        section_statuses[section_name] = "Good"
        return result if result is not None else ""
    except (RouterCommandError, FileUploadError, PlatformStatusError, FabricReachabilityError,
            FabricLinkDownError, NpuLinkError, NpuStatsError, NpuDriverError,
            FabricPlaneStatsError, AsicErrorsError, InterfaceStatusError,
            AlarmError, LcAsicErrorsError, FanTrayError, EnvironmentError, FpdStatusError) as e:
        logging.critical(f"✗ {section_name} failed: {e}")
        overall_script_failed_ref[0] = True
        section_statuses[section_name] = "Bad"
        return ""
    except Exception as e:
        logging.critical(f"✗ {section_name} failed: An unexpected error occurred: {e}", exc_info=True)
        overall_script_failed_ref[0] = True
        section_statuses[section_name] = "Bad"
        return ""


# === HEALTH CHECKS ===
def check_ios_xr_version(shell: paramiko.Channel, cli_output_file=None) -> str:
    logging.info(f"Retrieving IOS-XR Version...")
    version_output = execute_command_in_shell(shell, "show version", "show version", timeout=60,
                                              print_real_time_output=False, cli_output_file=cli_output_file)
    ios_xr_version = "N/A"
    match = re.search(r"Cisco IOS XR Software, Version (\d+\.\d+\.\d+(?:\.\w+)?)", version_output)
    if match:
        ios_xr_version = match.group(1)
        logging.info(f"IOS-XR Version detected: {ios_xr_version}")
    else:
        logging.warning("Could not parse IOS-XR version from 'show version' output.")
    version_table = PrettyTable()
    version_table.field_names = ["Information", "Value"]
    version_table.add_row(["IOS-XR Version", ios_xr_version])
    print(version_table)
    return version_output


def check_platform_and_serial_numbers(shell: paramiko.Channel,
                                      all_card_inventory_info: Dict[str, Dict[str, str]],
                                      all_cpu_locations_from_platform: List[str],
                                      ft_locations_from_platform: List[str],
                                      cli_output_file=None, framework_instance=None):
    logging.info(f"Retrieving Platform Status and Serial Numbers...")
    platform_output = execute_command_in_shell(shell, "show platform", "show platform", timeout=60,
                                               print_real_time_output=False, cli_output_file=cli_output_file)
    fc_inventory_output = execute_command_in_shell(shell, "show inventory | utility egrep 0/FC -A1 -B1",
                                                   "show inventory for FCs", timeout=60,
                                                   print_real_time_output=False, cli_output_file=cli_output_file)
    cpu_inventory_output = execute_command_in_shell(shell, "show inventory | utility egrep /CPU0 -A1 -B1",
                                                    "show inventory for LCs/RPs", timeout=60,
                                                    print_real_time_output=False, cli_output_file=cli_output_file)
    ft_inventory_output = execute_command_in_shell(shell, "show inventory | utility egrep 0/FT -A1 -B1",
                                                   "show inventory for FTs", timeout=60,
                                                   print_real_time_output=False, cli_output_file=cli_output_file)

    all_card_inventory_info.update(parse_inventory_for_serial_numbers(fc_inventory_output))
    all_card_inventory_info.update(parse_inventory_for_serial_numbers(cpu_inventory_output))
    all_card_inventory_info.update(parse_inventory_for_serial_numbers(ft_inventory_output))

    all_cards_details = []
    platform_issues_found = False
    lines = platform_output.splitlines()
    card_pattern = re.compile(r"^\s*(\S+)\s+(\S+)\s+(.+?)\s{2,}(\S+).*$")

    for line in lines:
        match = card_pattern.match(line)
        if match:
            location, card_type, current_state_raw, config_state = match.groups()
            current_state = current_state_raw.strip()
            expected_state = None
            is_problematic = False

            if "CPU" in location:
                expected_state = "IOS XR RUN"
                all_cpu_locations_from_platform.append(location)
            elif "FC" in location:
                expected_state = "OPERATIONAL"
            elif "BMC" in location:
                expected_state = "OPERATIONAL"
            elif "FT" in location:
                expected_state = "OPERATIONAL"
                ft_locations_from_platform.append(location)
            elif "PT" in location:
                expected_state = "OPERATIONAL"

            if expected_state is not None:
                if current_state != expected_state:
                    is_problematic = True
                    platform_issues_found = True

                display_state = f"{current_state} (Expected: {expected_state})" if is_problematic else current_state
                inventory_data = all_card_inventory_info.get(location, {"SN": "N/A", "VID": "N/A", "PID": "N/A"})
                serial_num = inventory_data["SN"]
                vid = inventory_data["VID"]
                pid = inventory_data["PID"]

                all_cards_details.append({
                    "Location": location,
                    "State": display_state,
                    "Serial Number": serial_num,
                    "VID": vid,
                    "PID": pid
                })

    print(f"Platform Status:")
    platform_table = PrettyTable()
    platform_table.field_names = ["LC / FC / RP / FT Location", "State", "Serial Number", "VID", "PID"]
    if all_cards_details:
        for card in all_cards_details:
            platform_table.add_row([card["Location"], card["State"], card["Serial Number"], card["VID"], card["PID"]])
    else:
        platform_table.add_row(["N/A", "No relevant cards found in 'show platform' output", "N/A", "N/A", "N/A"])
    print(platform_table)

    # Store data for summary report
    if framework_instance:
        framework_instance.platform_cards_details = all_cards_details
        framework_instance.all_card_inventory_info = all_card_inventory_info

        # Get chassis serial number
        chassis_inventory_output = execute_command_in_shell(shell, "show inventory chassis", "show inventory chassis",
                                                            timeout=30, print_real_time_output=False,
                                                            cli_output_file=cli_output_file)
        chassis_match = re.search(r'PID:\s*([^,]+?)\s*,\s*VID:\s*([^,]+?)\s*,\s*SN:\s*(\S+)', chassis_inventory_output)
        if chassis_match:
            framework_instance.chassis_inventory_info = {
                "PID": chassis_match.group(1),
                "VID": chassis_match.group(2),
                "SN": chassis_match.group(3)
            }
        else:
            framework_instance.chassis_inventory_info = {"PID": "N/A", "VID": "N/A", "SN": "N/A"}

    if platform_issues_found:
        logging.error(
            f"One or more Line Cards, Fabric Cards, or Route Processors are not in the expected state. Please review the table above.")
        raise PlatformStatusError("Platform status check failed.")
    else:
        logging.info(f"All Line Cards, Fabric Cards, and Route Processors are in their expected states.")

    return platform_output


def check_fabric_reachability(shell: paramiko.Channel, cli_output_file=None, chassis_model: str = "unknown_chassis",
                              framework_instance=None):
    logging.info(f"Checking Fabric Reachability (show controller fabric fsdb-pla rack 0)...")
    fabric_output = execute_command_in_shell(shell, "show controller fabric fsdb-pla rack 0",
                                             "show controller fabric fsdb-pla rack 0", timeout=120,
                                             print_real_time_output=False, cli_output_file=cli_output_file)
    problematic_fabric_rows = []
    header_separator_found = False
    lines = fabric_output.splitlines()

    valid_reach_masks = ["4/4", "2/2"]
    if chassis_model.startswith("88") or "NCS-88" in chassis_model:
        valid_reach_masks.extend(["6/6", "8/8", "16/16"])

    for line in lines:
        if "----------------------------------------------------------------------------------------------" in line:
            header_separator_found = True
            continue
        if header_separator_found:
            if not line.strip() or re.match(r'Mon\s+\w+\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+',
                                            line.strip()) or re.match(r'RP/\d+/\S+#', line.strip()):
                continue
            parts = line.split()
            if len(parts) >= 12:
                reach_mask_value = parts[9].strip()
                if reach_mask_value not in valid_reach_masks and reach_mask_value != "----":
                    problematic_fabric_rows.append([
                        parts[0], parts[1], parts[2], parts[3], parts[4],
                        parts[5], parts[6], parts[7], parts[8],
                        parts[9], parts[11]
                    ])

    # ADD THIS CODE HERE (before the if statement):
    # Store fabric reachability errors for report
    if framework_instance:
        framework_instance.fabric_reachability_errors = problematic_fabric_rows

    if problematic_fabric_rows:
        logging.error(f"!!! FABRIC REACHABILITY ERRORS DETECTED !!!")
        fabric_table = PrettyTable()
        fabric_table.field_names = ["Destination Address", "p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7",
                                    "Reach-mask links/asic", "Oper Up links/asic"]
        for row in problematic_fabric_rows:
            fabric_table.add_row(row)
        print(fabric_table)
        raise FabricReachabilityError("Fabric reachability check failed. Unexpected Reach-mask values detected.")
    else:
        logging.info(f"Fabric Reachability check passed. No issues detected.")


def check_fabric_link_down_status(shell: paramiko.Channel, cli_output_file=None, framework_instance=None):
    logging.info(f"Checking Fabric Link Down Status...")
    commands_and_descriptions = {
        "show controller fabric link port s1 rx down": "Fabric S1 RX Down Links",
        "show controller fabric link port fia rx down": "Fabric FIA RX Down Links"
    }
    all_down_links_found = []

    for command, description in commands_and_descriptions.items():
        output = execute_command_in_shell(shell, command, description, timeout=60, print_real_time_output=False,
                                          cli_output_file=cli_output_file)

        if "s1 rx down" in command:
            link_pattern = re.compile(r'^\s*(\S+)\s+(\S+)\s+(?:NA\s+){4}(\S+)\s*$')
            headers = ["Interface", "Admin/Oper State", "Other End"]
        elif "fia rx down" in command:
            link_pattern = re.compile(r'^\s*(\S+)\s+(\S+)\s+(\S+)\s*$', re.MULTILINE)
            headers = ["Interface", "Admin/Oper State", "Other End"]
        else:
            logging.warning(f"Unknown command for parsing fabric link down status: {command}")
            continue

        lines = output.splitlines()
        for line in lines:
            stripped_line = line.strip()
            if not stripped_line: continue
            if re.match(r'^\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+$', stripped_line): continue
            if re.match(r'^RP/\d+/\S+:\S+#', stripped_line): continue
            if re.escape(command.strip()) in re.escape(stripped_line): continue
            if any(
                x in stripped_line for x in ['Description:', 'R/S/A/P', 'DN', 'SFE port', 'FIA Port', '----']): continue

            match = link_pattern.match(stripped_line)
            if match:
                all_down_links_found.append({
                    "Interface": match.group(1),
                    "Admin/Oper State": match.group(2),
                    "Other End": match.group(3)
                })

    # Store fabric links down for report
    if framework_instance:
        framework_instance.fabric_links_down = all_down_links_found

    if all_down_links_found:
        logging.error(f"!!! FABRIC LINK DOWN STATUS ERRORS DETECTED !!!")
        link_down_table = PrettyTable()
        link_down_table.field_names = headers
        for link_info in all_down_links_found:
            link_down_table.add_row([link_info["Interface"], link_info["Admin/Oper State"], link_info["Other End"]])
        print(link_down_table)
        raise FabricLinkDownError("Fabric link down status check failed. Down links reported.")
    else:
        logging.info(f"Fabric Link Down Status check passed. No issues detected.")


def check_npu_link_info(shell: paramiko.Channel, cli_output_file=None, framework_instance=None):
    logging.info(f"Checking NPU Link Information...")
    command = r'show controllers npu link-info rx 0 255 topo instance all location all | ex "EN/UP" | ex "NC              NC"'
    output = execute_command_in_shell(shell, command, "show controllers npu link-info", timeout=180,
                                      print_real_time_output=False, cli_output_file=cli_output_file)
    problematic_links = []
    lines = output.splitlines()
    location_pattern = re.compile(r'^\d+/\S+/\d+/\d+$')

    for line in lines:
        stripped_line = line.strip()
        if not stripped_line: continue
        if re.match(r'^\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+$', stripped_line): continue
        if re.match(r'^RP/\d+/\S+:\S+#', stripped_line): continue
        if re.escape(command.strip()) in re.escape(stripped_line): continue
        if re.match(r'^Node ID: (\S+)$', stripped_line): continue
        if re.match(r'^-+$', stripped_line): continue
        if re.match(r'^Link ID\s+Log\s+Link\s+Asic', stripped_line): continue

        parts = stripped_line.split()
        if len(parts) >= 7:
            link_id = parts[0]
            far_end_link_fsdb = parts[6]
            if location_pattern.match(link_id) and location_pattern.match(far_end_link_fsdb):
                problematic_links.append({
                    "Link ID": link_id,
                    "Far-End Link (FSDB)": far_end_link_fsdb
                })

    # Store NPU link errors for report
    if framework_instance:
        framework_instance.npu_link_errors = problematic_links

    if problematic_links:
        logging.error(f"!!! NPU LINK ERRORS DETECTED !!!")
        npu_table = PrettyTable()
        npu_table.field_names = ["Link ID", "Far-End Link (FSDB)"]
        for link in problematic_links:
            npu_table.add_row([link["Link ID"], link["Far-End Link (FSDB)"]])
        print(npu_table)
        raise NpuLinkError("NPU link info check failed. Links are reported as down.")
    else:
        logging.info(f"NPU Link Information check passed. No down links reported.")


def check_npu_stats_link(shell: paramiko.Channel, cli_output_file=None, framework_instance=None):
    logging.info(f"Checking NPU Stats Link for UCE/CRC Errors...")
    command = r'show controllers npu stats link all instance all location all | ex "0        0        0"'
    output = execute_command_in_shell(shell, command, "show controllers npu stats link", timeout=180,
                                      print_real_time_output=False, cli_output_file=cli_output_file)
    problematic_stats = []
    current_node_id = None
    lines = output.splitlines()

    for i, line in enumerate(lines):
        stripped_line = line.strip()
        if not stripped_line: continue
        if re.match(r'^\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+$', stripped_line): continue
        if re.match(r'^RP/\d+/\S+:\S+#', stripped_line) or \
                re.escape(command.strip()) in re.escape(stripped_line) or \
                re.match(r'^-+$', stripped_line) or \
                re.match(r'^In Data\s+Out Data\s+CE\s+UCE\s+CRC$', stripped_line): continue

        node_id_match = re.match(r'^Node ID: (\S+)$', stripped_line)
        if node_id_match:
            current_node_id = node_id_match.group(1)
            continue

        numbers = re.findall(r'\d+', stripped_line)
        if len(numbers) >= 5:
            try:
                uce_errors = int(numbers[-2])
                crc_errors = int(numbers[-1])
                if uce_errors > 0 or crc_errors > 0:
                    if current_node_id:
                        problematic_stats.append({
                            "Node ID": current_node_id,
                            "UCE Errors": uce_errors,
                            "CRC Errors": crc_errors
                        })
            except ValueError:
                pass

    # Store NPU stats errors for report
    if framework_instance:
        framework_instance.npu_stats_errors = problematic_stats

    if problematic_stats:
        logging.error(f"!!! NPU STATS ERRORS DETECTED (UCE/CRC) !!!")
        stats_table = PrettyTable()
        stats_table.field_names = ["Node ID", "UCE Errors", "CRC Errors"]
        for stat in problematic_stats:
            stats_table.add_row([stat["Node ID"], stat["UCE Errors"], stat["CRC Errors"]])
        print(stats_table)
        raise NpuStatsError("NPU stats link check failed. Non-zero UCE or CRC errors detected.")
    else:
        logging.info(f"NPU Stats Link check passed. No non-zero UCE or CRC errors detected.")


def check_npu_driver_status(shell: paramiko.Channel, cli_output_file=None):
    logging.info(f"Checking NPU Driver Status (Asic states)...")
    command = "show controllers npu driver location 0/RP0/CPU0"
    output = execute_command_in_shell(shell, command, "show controllers npu driver", timeout=120,
                                      print_real_time_output=False, cli_output_file=cli_output_file)
    problematic_asics = []
    asics_table_header_separator = "+------------------------------------------------------------------------------+"
    asics_table_end_marker = "SI Info :"
    parsing_asics_table_data = False
    header_separator_count = 0
    lines = output.splitlines()

    for line in lines:
        stripped_line = line.strip()
        if asics_table_end_marker in stripped_line:
            parsing_asics_table_data = False
            break
        if asics_table_header_separator in stripped_line:
            header_separator_count += 1
            if header_separator_count == 2:
                parsing_asics_table_data = True
                continue
        if parsing_asics_table_data:
            if not stripped_line or re.match(r'^\+---', stripped_line): continue
            parts = [p.strip() for p in stripped_line.split('|')]
            if not re.match(r'^\d+/\S+/\d+$', parts[1]): continue
            if len(parts) >= 13:
                asic_instance = parts[1]
                slice_state = parts[4]
                admin_state = parts[6]
                oper_state = parts[7]
                asic_state = parts[8]

                expected_slice_state = "UP"
                expected_admin_state = "UP"
                expected_oper_state = "UP"
                expected_asic_state = "NRML"

                current_asic_issues = []
                if slice_state != expected_slice_state:
                    current_asic_issues.append(f"Slice state: {slice_state} (Expected: {expected_slice_state})")
                if admin_state != expected_admin_state:
                    current_asic_issues.append(f"Admin state: {admin_state} (Expected: {expected_admin_state})")
                if oper_state != expected_oper_state:
                    current_asic_issues.append(f"Oper state: {oper_state} (Expected: {expected_oper_state})")
                if asic_state != expected_asic_state:
                    current_asic_issues.append(f"Asic state: {asic_state} (Expected: {expected_asic_state})")

                if current_asic_issues:
                    problematic_asics.append({
                        "Asic Instance": asic_instance,
                        "Issues": ", ".join(current_asic_issues)
                    })

    if problematic_asics:
        logging.error(f"!!! NPU DRIVER STATUS ERRORS DETECTED (Asic states) !!!")
        npu_driver_table = PrettyTable()
        npu_driver_table.field_names = ["Asic Instance", "Problematic States"]
        for asic in problematic_asics:
            npu_driver_table.add_row([asic["Asic Instance"], asic["Issues"]])
        print(npu_driver_table)
        raise NpuDriverError("NPU driver status check failed. Asic states are not as expected.")
    else:
        logging.info(f"NPU Driver Status check passed. All Asic states are as expected.")


def check_fabric_plane_stats(shell: paramiko.Channel, cli_output_file=None, framework_instance=None):
    logging.info(f"Checking Fabric Plane Statistics (CE/UCE/PE Packets)...")
    command = "show controllers fabric plane all statistics"
    output = execute_command_in_shell(shell, command, "show controllers fabric plane all statistics", timeout=120,
                                      print_real_time_output=False, cli_output_file=cli_output_file)
    problematic_planes = []
    data_start_marker = "--------------------------------------------------------------------------------"
    parsing_data = False
    lines = output.splitlines()

    for line in lines:
        stripped_line = line.strip()
        if data_start_marker in stripped_line:
            parsing_data = True
            continue
        if parsing_data:
            if not stripped_line or re.match(r'Mon\s+\w+\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+',
                                             line.strip()) or re.match(r'RP/\d+/\S+#', line.strip()):
                continue
            parts = stripped_line.split()
            if len(parts) >= 6:
                try:
                    plane_id = parts[0]
                    ce_packets = int(parts[3])
                    uce_packets = int(parts[4])
                    pe_packets = int(parts[5])
                    if ce_packets > 0 or uce_packets > 0 or pe_packets > 0:
                        problematic_planes.append({
                            "Plane ID": plane_id,
                            "CE Packets": ce_packets,
                            "UCE Packets": uce_packets,
                            "PE Packets": pe_packets
                        })
                except ValueError:
                    pass

    # Store fabric plane errors for report
    if framework_instance:
        framework_instance.fabric_plane_errors = problematic_planes

    if problematic_planes:
        logging.error(f"!!! FABRIC PLANE STATISTICS ERRORS DETECTED (Non-zero CE/UCE/PE Packets) !!!")
        stats_table = PrettyTable()
        stats_table.field_names = ["Plane ID", "CE Packets", "UCE Packets", "PE Packets"]
        for plane in problematic_planes:
            stats_table.add_row([plane["Plane ID"], plane["CE Packets"], plane["UCE Packets"], plane["PE Packets"]])
        print(stats_table)
        raise FabricPlaneStatsError("Fabric plane statistics check failed. Non-zero CE/UCE/PE packets detected.")
    else:
        logging.info(f"Fabric Plane Statistics check passed. No issues detected.")


def check_asic_errors(shell: paramiko.Channel, cli_output_file=None, framework_instance=None):
    logging.info(f"Checking ASIC Errors (rx_link_status_down, count, npu[])...")
    command = r'show asic-errors all detail location 0/RP0/CPU0 | inc "rx_link_status_down|count|npu\\["'
    output = execute_command_in_shell(shell, command, "show asic-errors", timeout=120, print_real_time_output=False,
                                      cli_output_file=cli_output_file)
    problematic_asic_errors = []
    current_fc_location = None
    current_npu_number = None
    lines = output.splitlines()

    for i, line in enumerate(lines):
        stripped_line = line.strip()
        if not stripped_line: continue
        if re.match(r'^\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+$', stripped_line): continue
        if re.match(r'^RP/\d+/\S+:\S+#', stripped_line): continue
        if re.escape(command.strip()) in re.escape(stripped_line): continue

        npu_info_match = re.match(r'^\s*\d+,\s*\S+,\s*(\d+/\S+),\s*npu\[(\d+)\]', stripped_line)
        error_count_match = re.search(r'Error count\s*:\s*(\d+)', stripped_line)

        if npu_info_match:
            current_fc_location = npu_info_match.group(1)
            current_npu_number = npu_info_match.group(2)
            continue

        if error_count_match and current_fc_location and current_npu_number:
            error_count = int(error_count_match.group(1))
            if error_count > 0:
                problematic_asic_errors.append({
                    "FC Location": current_fc_location,
                    "NPU number": current_npu_number,
                    "Error count": error_count
                })
            current_fc_location = None
            current_npu_number = None
            continue

        if re.search(r'Name\s*:', stripped_line) and current_fc_location and current_npu_number: continue

    # Store ASIC errors for report
    if framework_instance:
        framework_instance.asic_errors = problematic_asic_errors

    if problematic_asic_errors:
        logging.error(f"!!! ASIC ERRORS DETECTED (Non-zero Error Counts) !!!")
        asic_error_table = PrettyTable()
        asic_error_table.field_names = ["FC Location", "NPU number", "Error count"]
        for item in problematic_asic_errors:
            asic_error_table.add_row([item["FC Location"], item["NPU number"], item["Error count"]])
        print(asic_error_table)
        raise AsicErrorsError("ASIC errors check failed. Non-zero error counts detected.")
    else:
        logging.info(f"ASIC Errors check passed. No non-zero error counts detected.")


def run_show_inventory(shell: paramiko.Channel, cli_output_file=None) -> str:
    logging.info(f"Running show inventory (output captured silently)...")
    output = execute_command_in_shell(shell, "show inventory", "show inventory", timeout=120,
                                      print_real_time_output=False, cli_output_file=cli_output_file)
    logging.info("show inventory command executed and output captured.")
    return output


def check_interface_status(shell: paramiko.Channel, cli_output_file=None, framework_instance=None) -> Tuple[str, str]:
    logging.info(f"Checking Interface Status...")
    summary_output = execute_command_in_shell(shell, "show interface summary", "show interface summary", timeout=60,
                                              print_real_time_output=False, cli_output_file=cli_output_file)
    all_types_data = None
    lines = summary_output.splitlines()
    all_types_pattern = re.compile(r"^\s*ALL TYPES\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")

    for line in lines:
        stripped_line = line.strip()
        match = all_types_pattern.match(stripped_line)
        if match:
            try:
                all_types_data = {
                    "Total": int(match.group(1)),
                    "UP": int(match.group(2)),
                    "Down": int(match.group(3)),
                    "Admin Down": int(match.group(4))
                }
                break
            except ValueError:
                logging.warning(f"Could not parse numeric values from 'ALL TYPES' line: '{stripped_line}'")

    if all_types_data:
        print(f"Interface Summary (ALL TYPES):")
        summary_table = PrettyTable()
        summary_table.field_names = ["Total", "UP", "Down", "Admin Down"]
        summary_table.add_row([
            all_types_data["Total"],
            all_types_data["UP"],
            all_types_data["Down"],
            all_types_data["Admin Down"]
        ])
        print(summary_table)
        logging.info(f"Interface summary for ALL TYPES successfully retrieved.")
    else:
        logging.warning(
            f"Could not find or parse 'ALL TYPES' row in 'show interface summary'. Proceeding with other checks.")

    # Store interface summary for report
    if all_types_data and framework_instance:
        framework_instance.interface_summary_data = all_types_data

    brief_output = execute_command_in_shell(shell, "show interface brief", "show interface brief", timeout=120,
                                            print_real_time_output=False, cli_output_file=cli_output_file)
    logging.info("show interface brief executed silently.")

    execute_command_in_shell(shell, "show interface description | ex admin",
                             "show interface description (excluding admin)", timeout=120, print_real_time_output=False,
                             cli_output_file=cli_output_file)
    logging.info("show interface description | ex admin executed silently.")

    if not brief_output.strip():
        raise InterfaceStatusError(
            "No valid output received from 'show interface brief'. Cannot proceed with interface status checks.")

    return summary_output, brief_output


def check_hw_module_fpd_status(shell: paramiko.Channel, cli_output_file=None) -> str:
    logging.info(f"Checking HW Module FPD Status...")
    output = execute_command_in_shell(shell, "show hw-module fpd", "show hw-module fpd", timeout=120,
                                      print_real_time_output=False, cli_output_file=cli_output_file)
    logging.info("show hw-module fpd executed silently.")
    return output


def check_and_capture_alarms_and_logs(shell: paramiko.Channel, cli_output_file=None):
    logging.info(f"Checking Alarms and Capturing Install Logs...")
    execute_command_in_shell(shell, "show alarms brief system", "show alarms brief system", timeout=60,
                             print_real_time_output=False, cli_output_file=cli_output_file)
    logging.info("show alarms brief system executed and output captured.")

    alarm_command = r'show alarms brief system active | ex Optics | ex Coherent'
    alarm_output = execute_command_in_shell(shell, alarm_command, "show alarms brief system active (filtered)",
                                            timeout=60, print_real_time_output=False, cli_output_file=cli_output_file)

    cleaned_alarm_lines = []
    alarm_command_pattern = re.compile(re.escape(alarm_command.strip()))

    for line in alarm_output.splitlines():
        stripped_line = line.strip()
        if not stripped_line: continue
        if re.match(r'^\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+$', stripped_line): continue
        if re.match(r'^RP/\d+/\S+:\S+#', stripped_line): continue
        if alarm_command_pattern.search(stripped_line): continue
        if re.match(r'^-+$', stripped_line) or \
                re.match(r'Active Alarms', stripped_line) or \
                re.match(r'Location\s+Severity\s+Group\s+Set Time\s+Description', stripped_line): continue
        cleaned_alarm_lines.append(stripped_line)

    if cleaned_alarm_lines:
        logging.error(f"!!! ACTIVE ALARMS DETECTED (excluding Optics/Coherent) !!!")
        print(f"\nActive Alarms (excluding Optics/Coherent):")
        for alarm_line in cleaned_alarm_lines:
            print(f" {alarm_line}")
        raise AlarmError("Active alarms detected after filtering.")
    else:
        logging.info(f"No active alarms detected (excluding Optics/Coherent).")

    execute_command_in_shell(shell, "show install log detail", "show install log detail", timeout=300,
                             print_real_time_output=False, cli_output_file=cli_output_file)
    logging.info("show install log detail executed and output captured.")


def check_lc_asic_errors(shell: paramiko.Channel, lc_locations: List[str], cli_output_file=None, framework_instance=None):
    logging.info(f"Checking LC ASIC Errors...")
    problematic_lc_asic_errors = []

    for lc_location in lc_locations:
        command = f'show asic-errors all location {lc_location} | i "CPU|Bit|Reset|Parity" | ex ": 0"'
        description = f"show asic-errors for {lc_location}"
        output = execute_command_in_shell(shell, command, description, timeout=180, print_real_time_output=False,
                                          cli_output_file=cli_output_file)

        cleaned_lines = []
        command_pattern = re.compile(re.escape(command.strip()))

        for line in output.splitlines():
            stripped_line = line.strip()
            if not stripped_line: continue
            if re.match(r'^\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+$', stripped_line): continue
            if re.match(r'^RP/\d+/\S+:\S+#', stripped_line): continue
            if command_pattern.search(stripped_line): continue

            lc_marker_regex = re.compile(r'^\*\s+\d+_\d+_CPU\d+\s+\*$')
            if lc_marker_regex.search(stripped_line): continue
            if "No asics are registered with asic_errors on this node" in stripped_line: continue

            cleaned_lines.append(stripped_line)

        if cleaned_lines:
            problematic_lc_asic_errors.append({
                "LC Location": lc_location,
                "Error Output": "\n".join(cleaned_lines)
            })

    # --- FIX: STORE THE DETECTED ERRORS IN THE FRAMEWORK INSTANCE ---
    if framework_instance:
        framework_instance.lc_asic_errors = problematic_lc_asic_errors
    # --- END OF FIX ---

    if problematic_lc_asic_errors:
        logging.error(f"!!! LC ASIC ERRORS DETECTED !!!")
        asic_error_table = PrettyTable()
        asic_error_table.field_names = ["LC Location", "Error Output"]
        for item in problematic_lc_asic_errors:
            asic_error_table.add_row([item["LC Location"], item["Error Output"]])
        print(asic_error_table)
        raise LcAsicErrorsError("LC ASIC errors check failed. Non-blank output detected for some LCs.")
    else:
        logging.info(f"LC ASIC Errors check passed. No non-blank output detected.")


def check_fan_tray_status(shell: paramiko.Channel, ft_locations: List[str],
                          all_card_inventory_info: Dict[str, Dict[str, str]], cli_output_file=None,
                          framework_instance=None):
    logging.info(f"Checking Fan Tray Status...")

    ft_alarm_command = "show alarms brief system active | i FT"
    ft_alarm_output = execute_command_in_shell(shell, ft_alarm_command, "Fan Tray active alarms", timeout=60,
                                               print_real_time_output=False, cli_output_file=cli_output_file)

    ft_alarms_detected = []
    for line in ft_alarm_output.splitlines():
        stripped_line = line.strip()
        if not stripped_line:
            continue
        if re.match(r'^\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+$', stripped_line):
            continue
        if re.match(r'^RP/\d+/\S+:\S+#', stripped_line):
            continue
        if re.escape(ft_alarm_command.strip()) in re.escape(stripped_line):
            continue
        if any(keyword in stripped_line.lower() for keyword in
               ['voltage', 'current', 'sensor', 'absent', 'input_vol', 'input_cur']):
            ft_alarms_detected.append(stripped_line)

    if ft_alarms_detected:
        logging.warning(f"Fan Tray specific alarms detected (Field Notice indicators):")
        for alarm in ft_alarms_detected:
            logging.warning(f"  {alarm}")

    execute_command_in_shell(shell, "show environment fan", "show environment fan", timeout=60,
                             print_real_time_output=False, cli_output_file=cli_output_file)
    logging.info("show environment fan executed and output captured.")

    problematic_fan_trays = []

    for ft_location in ft_locations:
        logging.info(f"Checking fan tray: {ft_location}")
        command = f"show environment all location {ft_location}"
        output = execute_command_in_shell(shell, command, f"show environment for {ft_location}", timeout=60,
                                          print_real_time_output=False, cli_output_file=cli_output_file)
        issues = []
        field_notice_symptoms = []
        replacement_recommended = "No"

        missing_indicators = ["not present", "no such instance", "data not found", "absent"]
        if any(indicator in output.lower() for indicator in missing_indicators):
            issues.append("Fan Tray is missing or not detected.")
            field_notice_symptoms.append("Missing Fan Tray (Field Notice Condition 4)")
            replacement_recommended = "Yes (Missing)"
            problematic_fan_trays.append({
                "Fan Tray Location": ft_location,
                "Detected Issues": "\n".join(issues),
                "Field Notice Symptoms": "\n".join(field_notice_symptoms),
                "Replacement Recommended": replacement_recommended
            })
            continue

        voltage_line_match = re.search(r'(?:Input_Vol|Input Voltage)\s+(\S+)', output)
        if voltage_line_match:
            voltage_str = voltage_line_match.group(1).strip()
            if voltage_str == "-":
                issues.append("Invalid Sensor Read: Input Voltage is '-'.")
                field_notice_symptoms.append("Invalid read error for input voltage (Field Notice Condition 1B)")
            else:
                try:
                    input_voltage_mv = float(voltage_str)
                    input_voltage_volts = input_voltage_mv / 1000.0

                    if input_voltage_volts == 0:
                        issues.append("Voltage Issue: Input Voltage is 0V.")
                        field_notice_symptoms.append("0V Fan Tray voltage (Field Notice Condition 2B)")
                    elif input_voltage_volts > 60:
                        issues.append(f"Voltage Issue: Input Voltage is {input_voltage_volts:.2f}V (Greater than 60V).")
                        field_notice_symptoms.append(
                            f"High voltage {input_voltage_volts:.2f}V (Field Notice Condition 2A/2B)")
                    elif input_voltage_volts < 40:
                        issues.append(f"Voltage Issue: Input Voltage is {input_voltage_volts:.2f}V (Lower than 40V).")
                        field_notice_symptoms.append(
                            f"Low voltage {input_voltage_volts:.2f}V (Field Notice Condition 2A)")
                except ValueError:
                    issues.append(f"Invalid Sensor Read: Input Voltage '{voltage_str}' is not a valid number.")
                    field_notice_symptoms.append("Invalid voltage sensor data (Field Notice Condition 1A)")
        else:
            issues.append("Input Voltage reading not found.")

        current_line_match = re.search(r'(?:Input_Cur|Input Current)\s+(\S+)', output)
        if current_line_match:
            current_str = current_line_match.group(1).strip()
            if current_str == "-":
                issues.append("Invalid Sensor Read: Input Current is '-'.")
                field_notice_symptoms.append("Invalid read error for input current (Field Notice Condition 1B)")
            else:
                try:
                    input_current_ma = float(current_str)
                    if input_current_ma == 0:
                        issues.append("Current Issue: Input Current is 0A.")
                        field_notice_symptoms.append("0A Fan Tray current (Field Notice Condition 3)")
                except ValueError:
                    issues.append(f"Invalid Sensor Read: Input Current '{current_str}' is not a valid number.")
                    field_notice_symptoms.append("Invalid current sensor data (Field Notice Condition 1A)")
        else:
            issues.append("Input Current reading not found.")

        power_line_match = re.search(
            r'^\s*' + re.escape(ft_location) + r'\s+\S+\s+(\S+)\s+(\S+)\s+(ON|OFF|UNPOWERED|POWERED_OFF|SHUTDOWN)',
            output, re.MULTILINE
        )
        if power_line_match:
            power_used = power_line_match.group(2)
            status = power_line_match.group(3)

            if power_used == "-":
                issues.append("Power Used is reported as '-' (Not Available/Operational).")
                field_notice_symptoms.append("Power Used shows '-' (Field Notice Condition 1B)")

            if status != "ON":
                issues.append(f"Fan Tray Status is '{status}' (Expected: ON).")
        else:
            issues.append("Could not parse Power Used/Status information for fan tray.")

        fan_tray_inventory = all_card_inventory_info.get(ft_location, {})
        pid = fan_tray_inventory.get("PID", "N/A")
        vid = fan_tray_inventory.get("VID", "N/A")

        if pid in FAN_IMPACTED_VERSIONS:
            impacted_versions = FAN_IMPACTED_VERSIONS[pid].get("Impacted", [])
            if vid in impacted_versions:
                if issues:
                    replacement_recommended = f"Yes (Impacted Version {vid} with symptoms)"
                else:
                    replacement_recommended = f"Consider (Impacted Version {vid}, no current symptoms)"
            elif vid in FAN_IMPACTED_VERSIONS[pid].get("Not Impacted", []):
                replacement_recommended = f"No (Not Impacted Version {vid})"
            else:
                replacement_recommended = f"Unknown (PID: {pid}, VID: {vid} not in known versions)"
        else:
            replacement_recommended = f"Unknown (PID: {pid} not in known impacted list)"

        if issues:
            problematic_fan_trays.append({
                "Fan Tray Location": ft_location,
                "Detected Issues": "\n".join(issues),
                "Field Notice Symptoms": "\n".join(field_notice_symptoms) if field_notice_symptoms else "None",
                "Replacement Recommended": replacement_recommended,
                "PID": pid,
                "VID": vid
            })

    # Store fan tray errors for report
    if framework_instance:
        framework_instance.fan_tray_errors = problematic_fan_trays

    if problematic_fan_trays:
        logging.error(f"!!! FAN TRAY STATUS ERRORS DETECTED !!!")
        ft_table = PrettyTable()
        ft_table.field_names = ["Fan Tray Location", "Field Notice Symptoms", "Other Issues", "PID/VID",
                                "Replacement Recommended"]
        for ft_issue in problematic_fan_trays:
            ft_table.add_row([
                ft_issue["Fan Tray Location"],
                ft_issue["Field Notice Symptoms"],
                ft_issue["Detected Issues"],
                f"{ft_issue['PID']}/{ft_issue['VID']}",
                ft_issue["Replacement Recommended"]
            ])
        print(ft_table)
        raise FanTrayError("Fan tray status check failed. Issues detected.")
    else:
        logging.info(f"Fan Tray Status check passed. No issues detected.")


def check_environment_status(shell: paramiko.Channel, cli_output_file=None):
    logging.info(f"Checking Environment Status (Temperature, Voltage, Power Supply)...")
    command = "show environment"
    output = execute_command_in_shell(shell, command, "show environment", timeout=180, print_real_time_output=False,
                                      cli_output_file=cli_output_file)

    if "CRITICAL" in output or "MAJOR" in output:
        logging.error(f"!!! ENVIRONMENT ISSUES DETECTED !!!")
        raise EnvironmentError("Environment status check failed. Critical/Major issues detected.")
    else:
        logging.info(
            f"Environment Status check passed. No critical/major temperature/voltage alarms or power supply issues detected.")


# === COMPARISON UTILITIES ===
def natural_sort_key(s: str) -> list:
    """
    Create a key for natural sorting of network interface names.
    e.g., "Gi0/1/0/11" becomes ["gi", 0, 1, 0, 11]
    This ensures that Gi0/1/0/2 comes before Gi0/1/0/11.
    """
    return [int(text) if text.isdigit() else text.lower() for text in re.split(r'(\d+)', s)]


def extract_command_output_from_file(file_path: str, command_string: str) -> str:
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except FileNotFoundError:
        raise FileProcessingError(f"File not found: {file_path}")
    except Exception as e:
        raise FileProcessingError(f"Error reading file {file_path}: {e}")

    escaped_command = re.escape(command_string.strip())
    pattern = re.compile(
        rf"--- Command: {escaped_command} ---\n(?:{re.escape(command_string)}\s*\n)?(.*?)(?=\n--- Command:|\Z)",
        re.DOTALL)
    match = pattern.search(content)
    if match:
        output_lines = match.group(1).strip().splitlines()
        cleaned = [line for line in output_lines if line.strip()]
        return "\n".join(cleaned).strip()
    return ""


def find_earliest_file_as_permanent_baseline(hostname_prefix: str, output_directory: str) -> Optional[str]:
    pattern = re.compile(rf"^{re.escape(hostname_prefix)}_combined_cli_output_(\d{{8}}_\d{{6}})\.txt$")

    if not os.path.isdir(output_directory):
        return None

    files_to_check = []
    for filename in os.listdir(output_directory):
        full_path = os.path.join(output_directory, filename)
        match = pattern.match(filename)
        if match:
            files_to_check.append((match.group(1), full_path))

    files_to_check.sort(key=lambda x: datetime.datetime.strptime(x[0], '%Y%m%d_%H%M%S'))

    if files_to_check:
        earliest_file = files_to_check[0][1]
        logging.debug(f"Found earliest baseline file: {earliest_file}")
        return earliest_file
    else:
        logging.debug("No baseline CLI output files found matching known patterns.")
        return None


def compare_optics_inventory(current_optics: Dict[str, Dict[str, str]],
                             previous_optics: Dict[str, Dict[str, str]]) -> Tuple[str, bool]:
    logging.info("Comparing optics inventory...")
    differences_found = False
    comparison_table = PrettyTable()
    comparison_table.field_names = ["Interface", "Change Type", "Previous SN", "Current SN", "Details"]
    comparison_table.align = "l"

    prev_sn_to_intf = {data['SN']: intf for intf, data in previous_optics.items() if
                       data.get('SN') and data.get('SN') != 'N/A'}
    accounted_previous_sns = set()

    for current_intf, current_data in current_optics.items():
        current_sn = current_data.get('SN')
        if current_sn and current_sn != 'N/A' and current_sn in prev_sn_to_intf:
            previous_intf_for_sn = prev_sn_to_intf[current_sn]
            if previous_intf_for_sn != current_intf:
                previous_sn_for_current_intf = previous_optics.get(current_intf, {}).get('SN', 'N/A')
                comparison_table.add_row([
                    current_intf,
                    "Optic Moved/Incorrect Interface",
                    previous_sn_for_current_intf,
                    current_sn,
                    f"SN {current_sn} was previously on {previous_intf_for_sn}"
                ])
                differences_found = True
            accounted_previous_sns.add(current_sn)

    for previous_intf, previous_data in previous_optics.items():
        previous_sn = previous_data.get('SN')
        if previous_sn and previous_sn != 'N/A' and previous_sn not in accounted_previous_sns:
            current_sn_at_prev_intf = current_optics.get(previous_intf, {}).get('SN', 'N/A')
            if current_sn_at_prev_intf != previous_sn:
                comparison_table.add_row([
                    previous_intf,
                    "Optic Missing",
                    previous_sn,
                    current_sn_at_prev_intf,
                    "Was detected previously, now not found or replaced"
                ])
                differences_found = True

    for current_intf, current_data in current_optics.items():
        current_sn = current_data.get('SN')
        if current_sn and current_sn != 'N/A' and current_sn not in prev_sn_to_intf:
            comparison_table.add_row([
                current_intf,
                "Optic Added",
                "N/A",
                current_sn,
                "New optic detected"
            ])
            differences_found = True

    report_output = f"\n{'-' * 80}\n"
    report_output += f"{'OPTICS INVENTORY COMPARISON REPORT':^80}\n"
    report_output += f"{'-' * 80}\n"
    if differences_found:
        report_output += str(comparison_table) + "\n\nPlease review the optics inventory changes above.\n"
    else:
        report_output += "No optics inventory differences detected.\n"
    return report_output, differences_found


def compare_lcfc_inventory(current_lcfc: Dict[str, Dict[str, str]],
                           previous_lcfc: Dict[str, Dict[str, str]],
                           hostname: str,
                           chassis_model: str) -> Tuple[str, bool]:
    logging.info("Comparing LC/FC/RP inventory...")
    differences_found = False

    report_output_parts = []
    report_output_parts.append(f"{'-' * 80}")
    report_output_parts.append(f"{'LINE CARD / FABRIC CARD / ROUTE PROCESSOR INVENTORY COMPARISON REPORT':^80}")
    report_output_parts.append(f"{'-' * 80}")

    current_date_str = datetime.datetime.now().strftime('%m/%d/%Y')
    summary_header_table = PrettyTable()
    summary_header_table.field_names = ["Device", "Tile number", "Date", "Status"]
    summary_header_table.add_row([
        f"Device: {hostname}",
        f"Tile number: BN120",
        f"Date: {current_date_str}",
        "Status: Complete"
    ])
    summary_header_table.header = False
    summary_header_table.align = "l"

    report_output_parts.append(str(summary_header_table))

    comparison_table = PrettyTable()
    comparison_table.field_names = ["LC / FC / RP / FT Location", "OLD SERIAL", "OLD AT", "NEW SN", "NEW AT", "PID"]
    comparison_table.align = "l"

    # --- THIS IS THE CORRECTED LINE ---
    all_locations = sorted(list(set(current_lcfc.keys()) | set(previous_lcfc.keys())), key=natural_sort_key)

    for location in all_locations:
        current_sn = current_lcfc.get(location, {}).get('SN', 'N/A')
        previous_sn = previous_lcfc.get(location, {}).get('SN', 'N/A')
        current_pid = current_lcfc.get(location, {}).get('PID', 'N/A')
        previous_pid = previous_lcfc.get(location, {}).get('PID', 'N/A')

        display_pid = current_pid if current_pid != 'N/A' else previous_pid

        if (location in previous_lcfc and location in current_lcfc and current_sn != previous_sn) or \
                (location in current_lcfc and location not in previous_lcfc) or \
                (location in previous_lcfc and location not in current_lcfc):
            comparison_table.add_row([location, previous_sn, "", current_sn, "", display_pid])
            differences_found = True

    if not differences_found:
        no_diff_table = PrettyTable()
        no_diff_table.field_names = ["Message"]
        no_diff_table.add_row(["No LC/FC/RP inventory differences detected."])
        no_diff_table.align = "c"
        report_output_parts.append(str(no_diff_table))
        report_output_parts.append("\n")
    else:
        report_output_parts.append(str(comparison_table))
        report_output_parts.append("\n\nPlease review the LC/FC/RP inventory changes above.\n")

    return "\n".join(report_output_parts), differences_found


def compare_interface_statuses(current_statuses: Dict[str, Dict[str, str]],
                               previous_statuses: Dict[str, Dict[str, str]]) -> Tuple[str, bool]:
    differences_found = False
    comparison_table = PrettyTable()
    comparison_table.field_names = ["Interface", "Change Type", "Previous Intf/LineP State", "Current Intf/LineP State"]
    comparison_table.align = "l"

    # --- FIX: Use natural_sort_key for correct numerical sorting ---
    all_interfaces = sorted(list(set(current_statuses.keys()) | set(previous_statuses.keys())), key=natural_sort_key)
    # --- END OF FIX ---

    for intf in all_interfaces:
        physical_intf_pattern = re.compile(
            r"^(?:(?:GigabitEthernet|Gi|TenGigE|Te|FortyGigE|Fo|HundredGigE|Hu|FourHundredGigE|FH|Ethernet|Eth|FastEthernet|Fa|Serial|Se|POS|Cellular|Ce|MgmtEth|PTP|nve|Vxlan)\S+)",
            re.IGNORECASE
        )
        if not physical_intf_pattern.match(intf):
            logging.debug(f"Skipping logical interface '{intf}' for comparison.")
            continue

        current_data = current_statuses.get(intf, {})
        previous_data = previous_statuses.get(intf, {})

        current_adm_stat = current_data.get("brief_status", "N/A")
        current_prot_stat = current_data.get("brief_protocol", "N/A")
        previous_adm_stat = previous_data.get("brief_status", "N/A")
        previous_prot_stat = previous_data.get("brief_protocol", "N/A")

        current_full_status = f"Intf:{current_adm_stat}/LineP:{current_prot_stat}"
        previous_full_status = f"Intf:{previous_adm_stat}/LineP:{previous_prot_stat}"

        if intf not in previous_statuses and intf in current_statuses:
            comparison_table.add_row([intf, "Newly Appeared", "N/A", current_full_status])
            differences_found = True
            continue

        if intf in previous_statuses and intf not in current_statuses:
            comparison_table.add_row([intf, "Disappeared", previous_full_status, "N/A"])
            differences_found = True
            continue

        if intf in current_statuses and intf in previous_statuses:
            if current_adm_stat != previous_adm_stat or current_prot_stat != previous_prot_stat:
                change_type = "Status Change"
                if previous_adm_stat == "up" and previous_prot_stat == "up" and \
                        (current_adm_stat == "down" or current_prot_stat == "down" or current_adm_stat == "admin-down"):
                    change_type = "Interface Went Down"
                elif (previous_adm_stat in ["down", "admin-down"] or previous_prot_stat in ["down", "admin-down"]) and \
                        current_adm_stat == "up" and current_prot_stat == "up":
                    change_type = "Interface Came Up"

                comparison_table.add_row([intf, change_type, previous_full_status, current_full_status])
                differences_found = True

    report_output = f"\n{'-' * 80}\n"
    report_output += f"{'PHYSICAL INTERFACE STATUS COMPARISON REPORT':^80}\n"
    report_output += f"{'-' * 80}\n"
    if differences_found:
        report_output += str(comparison_table) + "\n\nPlease review the physical interface status changes above.\n"
    else:
        report_output += "No physical interface status differences detected between current and previous run.\n"
    return report_output, differences_found


def compare_fpd_statuses(current_statuses: Dict[Tuple[str, str], Dict[str, str]],
                         previous_statuses: Dict[Tuple[str, str], Dict[str, str]]) -> Tuple[str, bool]:
    logging.info("Comparing FPD statuses...")
    differences_found = False

    report_output = f"\n{'-' * 80}\n"
    report_output += f"{'FPD STATUS COMPARISON REPORT':^80}\n"
    report_output += f"{'-' * 80}\n"
    if differences_found:
        report_output += "FPD status changes detected.\n"
    else:
        report_output += "No FPD status differences detected between current and previous run.\n"
    return report_output, differences_found


def get_initially_down_physical_interfaces(interface_statuses: Dict[str, Dict[str, str]]) -> Tuple[str, bool]:
    down_interfaces = []
    for intf_name, status_data in interface_statuses.items():
        if re.match(r"^(?:(?:Gi|Te|Hu|Fo|Eth|Fa|Se|POS|Ce|nve|Vxlan|FH)\S+)", intf_name, re.IGNORECASE):
            brief_intf_state = status_data.get("brief_status")
            brief_linep_state = status_data.get("brief_protocol")

            if brief_intf_state == "down" and brief_linep_state == "down":
                down_interfaces.append(
                    f"{intf_name} (Intf State: {brief_intf_state}, LineP State: {brief_linep_state})")

    report_output = f"\n{'-' * 80}\n"
    report_output += f"{'INITIATING DOWN PHYSICAL INTERFACES (CURRENT RUN)':^80}\n"
    report_output += f"{'-' * 80}\n"
    if down_interfaces:
        report_output += "The following physical interfaces were found to be 'down' (operationally) during the current run's initial check:\n"
        for intf in down_interfaces:
            report_output += f"- {intf}\n"
    else:
        report_output += "No physical interfaces were found to be 'down' (operationally) during the current run's initial check.\n"
    return report_output, bool(down_interfaces)


def print_final_summary_table(statuses: Dict[str, str], total_execution_time: float):
    """Print final summary table exactly like Part I"""
    print(f"\n--- Final Script Summary ---")

    formatted_time = format_execution_time(total_execution_time)
    execution_time_text = f"Total time for execution: {formatted_time}"
    time_table_width = max(len(execution_time_text) + 4, 60)

    time_separator = "+" + "-" * (time_table_width - 2) + "+"
    time_content = f"| {execution_time_text:<{time_table_width - 4}} |"

    print(time_separator)
    print(time_content)
    print(time_separator)

    excluded_sections = {"Interface Status Check", "HW Module FPD Status Check"}
    filtered_statuses = {section: status for section, status in statuses.items()
                         if section not in excluded_sections}

    summary_table = PrettyTable()
    summary_table.field_names = ["Test #", "Section Name", "Status"]
    summary_table.align["Test #"] = "c"
    summary_table.align["Section Name"] = "l"
    summary_table.align["Status"] = "l"

    def colorize_status(status):
        if status == "Good":
            return f"\033[1;92m{status}\033[0m"
        elif status == "Bad":
            return f"\033[1;91m{status}\033[0m"
        elif "Collection Only" in status:
            return f"\033[1;94m{status}\033[0m"
        elif status == "Not Run":
            return f"\033[1;93m{status}\033[0m"
        else:
            return status

    test_number = 1
    for section, status in filtered_statuses.items():
        colored_status = colorize_status(status)
        summary_table.add_row([str(test_number), section, colored_status])
        test_number += 1

    print(summary_table)


# === PYTHON PRE-CHECK UTILITIES ===
def run_script_list_phase(shell, scripts_to_run, script_arg_option):
    """Execute scripts exactly like Part II"""
    all_scripts_raw_output = []

    for script_name in scripts_to_run:
        group_match = re.search(r'group(\d+)\.py', script_name)
        group_number = group_match.group(1) if group_match else "Unknown"

        script_arg_option_for_log = script_arg_option.strip("'")
        padding_len = 15
        logging.info(
            f"{'=' * padding_len}--- Running Group {group_number} with option {script_arg_option_for_log} ---{'=' * padding_len}")

        command_to_execute = f"python3 {script_name} {script_arg_option}"
        logging.info(f"Sending 'python3 script execution' ('{command_to_execute}')...")
        shell.send(command_to_execute + "\n")
        time.sleep(0.3)

        logging.info(f"Waiting for '{script_name}' to finish (up to 10 minutes) and printing output in real-time...")
        script_output, prompt_found = read_and_print_realtime(shell, timeout_sec=600, print_real_time=True)

        all_scripts_raw_output.append((script_name, script_output))

        if not prompt_found:
            logging.warning(f"Prompt not detected within 600 seconds after running '{script_name}'.")
        else:
            logging.info(f"✓ Prompt detected, '{script_name}' execution assumed complete.")

        logging.info(f"{'=' * padding_len}--- Finished execution for: {script_name} ---{'=' * padding_len}")

    return all_scripts_raw_output


def extract_link_components(part_string):
    """Extract LCx or FCx from a link component string"""
    lc_match = re.search(r'(\d+)/CPU(\d+)', part_string)
    if lc_match:
        return f"LC{lc_match.group(1)}"
    fc_match = re.search(r'FC(\d+)', part_string)
    if fc_match:
        return f"FC{fc_match.group(1)}"
    return part_string.strip()


def parse_and_print_errors(script_name, script_output):
    """Parse and print errors exactly like Part II"""
    global PYTHON_PHASE2_ERRORS_DETECTED

    errors_found = []
    lines = script_output.splitlines()

    group_number_match = re.search(r'group(\d+)\.py', script_name)
    group_number = group_number_match.group(1) if group_number_match else "N/A"

    BER_THRESHOLD_REFERENCE = "1e-08"
    FLR_THRESHOLD_REFERENCE = "1e-21"

    i = 0
    while i < len(lines):
        link_fault_match = re.search(
            r"Link .*? between (.*?)\s+and\s+(.*?)\s+is faulty -.*?"
            r"BER (\S+) FLR (\S+) RX Link Down Count (\d+)", lines[i]
        )
        if link_fault_match:
            part1_raw = link_fault_match.group(1).strip()
            part2_raw = link_fault_match.group(2).strip()
            ber_val_from_log = link_fault_match.group(3)
            flr_val_from_log = link_fault_match.group(4)
            rx_link_down_count_val = int(link_fault_match.group(5))

            formatted_part1 = extract_link_components(part1_raw)
            formatted_part2 = extract_link_components(part2_raw)
            link_connection = f"{formatted_part1} - {formatted_part2}"

            current_error = {
                "Link Connection": link_connection,
                "Group_number": group_number,
                "Codewords_status": "Good",
                "FLR_status": "Good",
                "FLR_value": flr_val_from_log,
                "BER_status": "Good",
                "BER_value": ber_val_from_log,
                "Link_flap": rx_link_down_count_val,
            }

            j = i + 1
            while j < len(lines) and j < i + 6:
                if "Codewords: BAD" in lines[j]:
                    current_error["Codewords_status"] = "Bad"
                if "BER: BAD" in lines[j]:
                    current_error["BER_status"] = "Bad"
                if "FLR: BAD" in lines[j]:
                    current_error["FLR_status"] = "Bad"
                j += 1

            if (current_error["Codewords_status"] == "Bad" or
                    current_error["BER_status"] == "Bad" or
                    current_error["FLR_status"] == "Bad" or
                    current_error["Link_flap"] > 0):
                errors_found.append(current_error)

            i = j
        else:
            i += 1

    # Build table output as single string (exactly like Part II)
    table_output_lines = []
    table_output_lines.append(f"\n--- Error Report for {script_name} ---")
    table_output_lines.append(f"Reference Thresholds: BER < {BER_THRESHOLD_REFERENCE}, FLR < {FLR_THRESHOLD_REFERENCE}")

    col_widths = {
        "Link Connection": 20,
        "Group_number": 15,
        "Codewords": 12,
        "FLR": 22,
        "BER": 22,
        "Link_flap": 12
    }

    header_cols = [
        f"{'Link Connection':<{col_widths['Link Connection']}}",
        f"{'Group_number':<{col_widths['Group_number']}}",
        f"{'Codewords':<{col_widths['Codewords']}}",
        f"{'FLR':<{col_widths['FLR']}}",
        f"{'BER':<{col_widths['BER']}}",
        f"{'Link_flap':<{col_widths['Link_flap']}}"
    ]
    header = f"| {' | '.join(header_cols)} |"

    separator_line_len = len(header)
    separator_line = f"{'+'}{'-' * (separator_line_len - 2)}{'+'}"

    table_output_lines.append(f"{separator_line}")
    table_output_lines.append(f"{header}")
    table_output_lines.append(f"{separator_line}")

    if errors_found:
        PYTHON_PHASE2_ERRORS_DETECTED = True
        for error in errors_found:
            codewords_display = error["Codewords_status"]

            if error["FLR_status"] == "Bad":
                flr_display = f"Bad ({error['FLR_value']})"
            else:
                flr_display = "Good"

            if error["BER_status"] == "Bad":
                ber_display = f"Bad ({error['BER_value']})"
            else:
                ber_display = "Good"

            link_flap_display = str(error["Link_flap"]) if error["Link_flap"] > 0 else ""

            row_cols = [
                f"{error['Link Connection']:<{col_widths['Link Connection']}}",
                f"{error['Group_number']:<{col_widths['Group_number']}}",
                f"{codewords_display:<{col_widths['Codewords']}}",
                f"{flr_display:<{col_widths['FLR']}}",
                f"{ber_display:<{col_widths['BER']}}",
                f"{link_flap_display:<{col_widths['Link_flap']}}"
            ]
            table_output_lines.append(f"| {' | '.join(row_cols)} |")
    else:
        blank_row_cols = [
            f"{'':<{col_widths['Link Connection']}}",
            f"{group_number:<{col_widths['Group_number']}}",
            f"{'':<{col_widths['Codewords']}}",
            f"{'':<{col_widths['FLR']}}",
            f"{'':<{col_widths['BER']}}",
            f"{'':<{col_widths['Link_flap']}}"
        ]
        table_output_lines.append(f"| {' | '.join(blank_row_cols)} |")

    table_output_lines.append(f"{separator_line}")

    # Print entire table as one block
    table_output = "\n".join(table_output_lines)
    print(table_output)

    if not errors_found:
        logging.info(f"✓ No errors detected for Group {group_number}.")
    else:
        PYTHON_PHASE2_ERRORS_DETECTED = True
        logging.error(f"✗ {len(errors_found)} errors detected for Group {group_number}.")


def print_python_final_summary_table(phase_results: Dict[str, str], total_execution_time: float):
    """Print Python final summary exactly like Part II"""
    print(f"\n--- Final Script Summary ---")

    formatted_time = format_execution_time(total_execution_time)
    execution_time_text = f"Total time for execution: {formatted_time}"
    time_table_width = max(len(execution_time_text) + 4, 60)

    time_separator = "+" + "-" * (time_table_width - 2) + "+"
    time_content = f"| {execution_time_text:<{time_table_width - 4}} |"

    print(time_separator)
    print(time_content)
    print(time_separator)

    summary_table = PrettyTable()
    summary_table.field_names = ["Test #", "Section Name", "Status"]
    summary_table.align["Test #"] = "c"
    summary_table.align["Section Name"] = "l"
    summary_table.align["Status"] = "l"

    def get_phase_status(section, original_status):
        global PYTHON_PHASE2_ERRORS_DETECTED

        if section == "Phase 1 Execution":
            if "Complete" in original_status:
                return "\033[1;94mCollection Only\033[0m"
            else:
                return f"\033[1;91m{original_status}\033[0m"
        elif section == "Phase 2 Execution":
            if "Complete" in original_status:
                if PYTHON_PHASE2_ERRORS_DETECTED:
                    return "\033[1;91mErrors Found\033[0m"
                else:
                    return "\033[1;92mSuccessful\033[0m"
            else:
                return f"\033[1;91m{original_status}\033[0m"
        else:
            if "Complete" in original_status or "Success" in original_status:
                return f"\033[1;92m{original_status}\033[0m"
            elif "Failed" in original_status or "Error" in original_status:
                return f"\033[1;91m{original_status}\033[0m"
            else:
                return original_status

    test_number = 1
    for section, status in phase_results.items():
        enhanced_status = get_phase_status(section, status)
        summary_table.add_row([str(test_number), section, enhanced_status])
        test_number += 1

    print(summary_table)
    logging.info(f"--- End Final Script Summary ---")


# === DISPLAY COMPLETE WORKFLOW RESULTS ===
def _display_complete_precheck_workflow_results(results: Dict[str, str], duration: float):
    """Display complete workflow results with combined summary"""

    print(f"\n{'#' * 80}")
    print(f"### COMPLETE PRE-CHECK WORKFLOW RESULTS ###")
    print(f"{'#' * 80}")

    print(f"Total Execution Time: {format_execution_time(duration)}")

    # Combined results table
    combined_table = PrettyTable()
    combined_table.field_names = ["Step #", "Pre-Check Operation", "Status", "Duration"]
    combined_table.align["Step #"] = "c"
    combined_table.align["Pre-Check Operation"] = "l"
    combined_table.align["Status"] = "l"
    combined_table.align["Duration"] = "r"

    def extract_status_and_duration(result_string):
        """Extract status and duration from result string"""
        if "(" in result_string and result_string.endswith(")"):
            parts = result_string.rsplit("(", 1)
            status = parts[0].strip()
            duration = parts[1].rstrip(")").strip()
            return status, duration
        return result_string, "N/A"

    def colorize_combined_status(status):
        if "Success" in status:
            return f"\033[1;92m{status}\033[0m"
        elif "Failed" in status:
            return f"\033[1;91m{status}\033[0m"
        elif "Issues Found" in status or "Degraded Links Found" in status:
            return f"\033[1;91m{status}\033[0m"
        else:
            return f"\033[1;94m{status}\033[0m"

    step_number = 1
    for operation, result in results.items():
        status, duration = extract_status_and_duration(result)
        colored_status = colorize_combined_status(status)
        combined_table.add_row([str(step_number), operation, colored_status, duration])
        step_number += 1

    print(combined_table)

    # Overall assessment
    print(f"\nPRE-CHECK WORKFLOW ASSESSMENT:")

    file_upload_ok = "Success" in results.get("File Upload", "")
    cli_checks_ok = "Success" in results.get("CLI Pre-Checks", "")
    python_checks_ok = "Success" in results.get("Python Pre-Checks", "") and not PYTHON_PHASE2_ERRORS_DETECTED

    print(f"   File Upload: {'Success' if file_upload_ok else 'Issues'}")
    print(f"   CLI Health Checks: {'Passed' if cli_checks_ok else 'Issues Detected'}")
    print(f"   Python Validation: {'Clean' if python_checks_ok else 'Degraded Links'}")

    # Final recommendation
    overall_success = file_upload_ok and cli_checks_ok and python_checks_ok

    if overall_success:
        print(f"\nFINAL ASSESSMENT: READY FOR REMEDIATION")
        print(f"   System validated and ready for fabric card remediation")
        print(f"   Proceed with fabric card installation/replacement")
        print(f"   Next step: Execute post-check framework after remediation")
    else:
        print(f"\nFINAL ASSESSMENT: REMEDIATION REQUIRED")
        print(f"   Address identified issues before fabric card work")
        print(f"   Do not proceed with remediation until issues resolved")
        print(f"   Re-run pre-checks after issue resolution")


# === INTERACTIVE FRAMEWORK MANAGER ===
class InteractivePreCheckManager:
    """Combined interactive pre-check manager"""

    def __init__(self):
        self.router_ip = None
        self.username = None
        self.password = None
        self.hostname = "unknown_host"
        self.chassis_model = "unknown_chassis"
        self.session_start_time = time.time()
        self.true_original_stdout = sys.stdout

        # Initialize data storage for summary report
        self.chassis_inventory_info = {}
        self.all_card_inventory_info = {}
        self.platform_cards_details = []
        self.interface_summary_data = {}
        self.npu_link_errors = []
        self.npu_stats_errors = []
        self.asic_errors = []
        self.fabric_reachability_errors = []
        self.fabric_plane_errors = []
        self.fabric_links_down = []
        self.fan_tray_errors = []

    # ADD THIS NEW METHOD
    def _setup_logging(self):
        """Centralized logging setup for the entire script session."""
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)

        # Clear any previously added handlers to prevent duplication
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
            handler.close()

        # Replace with this block
        # Configure the single CONSOLE handler for the entire session
        console_handler = logging.StreamHandler(self.true_original_stdout)
        # --- FIX: Use the new CompactFormatter for color ---
        console_handler.setFormatter(CompactFormatter())
        logger.addHandler(console_handler)

        # Get hostname for creating the output directory
        try:
            self.hostname = get_hostname_from_router(self.router_ip, self.username, self.password)
        except HostnameRetrievalError as e:
            # Use a temporary console logger just for this initial error
            temp_handler = logging.StreamHandler(self.true_original_stdout)
            temp_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            temp_handler.setFormatter(temp_formatter)
            logging.getLogger().addHandler(temp_handler)
            logging.warning(f"Could not retrieve hostname: {e}. Using IP address for log filenames.")
            logging.getLogger().removeHandler(temp_handler)
            self.hostname = self.router_ip.replace('.', '-')

        self.output_directory = os.path.join(os.getcwd(), self.hostname)
        os.makedirs(self.output_directory, exist_ok=True)

        # Configure the single CONSOLE handler for the entire session
        console_handler = logging.StreamHandler(self.true_original_stdout)
        console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

        logging.info(f"Logging initialized. Output will be saved in: {self.output_directory}")

    def initialize(self):
        """Initialize framework, get user input, and set up centralized logging."""

        # --- Step 1: Get user input FIRST ---
        self.router_ip = input(f"Enter Router IP address or Hostname: ")
        self.username = input(f"Enter SSH Username: ")
        self.password = getpass.getpass(f"Enter SSH Password for {self.username}@{self.router_ip}: ")

        # --- Step 2: Configure the logger BEFORE any function that makes a logging call ---
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)

        # Clear any previously added handlers to prevent duplication
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
            handler.close()

        # Replace with this block
        # Add the single, correctly formatted console handler for the entire session
        console_handler = logging.StreamHandler(self.true_original_stdout)
        # --- FIX: Use the new CompactFormatter for color ---
        console_handler.setFormatter(CompactFormatter())
        logger.addHandler(console_handler)

        # --- Step 3: NOW it is safe to call functions that use logging ---
        try:
            self.hostname = get_hostname_from_router(self.router_ip, self.username, self.password)
        except HostnameRetrievalError as e:
            logging.warning(f"Could not retrieve hostname: {e}. Using IP address for log filenames.")
            self.hostname = self.router_ip.replace('.', '-')

        # --- FIX: Step 4 - Create the 'output_directory' attribute that was missing ---
        self.output_directory = os.path.join(os.getcwd(), self.hostname)
        os.makedirs(self.output_directory, exist_ok=True)

        logging.info(f"Logging initialized. Output will be saved in: {self.output_directory}")

    def display_main_menu(self):
        """Display main menu with SecureCRT compatible formatting"""
        print(f"\n{'=' * 80}")
        print(f"{'IOS-XR Universal Pre-Check Interactive Framework v3.0':^80}")
        print(f"{'=' * 80}")

        print(f"\nRouter: {self.hostname} ({self.router_ip})")
        print(f"Session Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        print(f"\nPRE-CHECK OPERATIONS:")
        print(f"   [1] File Upload Only (Monitor Scripts) - ~2 min")
        print(f"   [2] CLI Pre-Checks Only (Health Assessment) - ~15 min")
        print(f"   [3] Python Pre-Checks Only (Dummy Script Validation) - ~60 min")
        print(f"   [4] Execute All Pre-Checks Sequentially - ~77 min")

        print(f"\nINDIVIDUAL COMPONENTS:")
        print(f"   [5] Monitor File Status Check")
        print(f"   [6] Quick Health Check")
        print(f"   [7] Baseline Comparison Only")

        print(f"\nUTILITIES:")
        print(f"   [status] View Previous Results")
        print(f"   [help]   Help & Documentation")
        print(f"   [exit]   Exit")

        print(f"\n{'=' * 80}")


    def get_user_choice(self):
        """Get user choice"""
        while True:
            choice = input(f"Select option: ").strip().lower()
            valid_choices = ["1", "2", "3", "4", "5", "6", "7", "status", "help", "exit", "quit", "q"]
            if choice in valid_choices:
                return choice
            else:
                print(f"Invalid choice '{choice}'. Please try again.")


    def confirm_action(self, message: str, default_yes: bool = False) -> bool:
        """Interactive confirmation"""
        default_choice = "Y/n" if default_yes else "y/N"
        response = input(f"{message} ({default_choice}): ").lower().strip()
        if not response:
            return default_yes
        return response.startswith('y')


    def run_interactive_framework(self):
        """Main interactive loop"""
        while True:
            try:
                self.display_main_menu()
                choice = self.get_user_choice()

                if choice == "1":
                    self.execute_file_upload_only()
                elif choice == "2":
                    self.execute_cli_precheck_only()
                elif choice == "3":
                    self.execute_python_precheck_only()
                elif choice == "4":
                    self.execute_all_prechecks_sequential()
                elif choice == "5":
                    self.check_monitor_file_status()
                elif choice == "6":
                    self.run_quick_health_check()
                elif choice == "7":
                    self.run_baseline_comparison_only()
                elif choice in ["status"]:
                    self.show_execution_status()
                elif choice in ["help"]:
                    self.show_help()
                elif choice in ["exit", "quit", "q"]:
                    if self.confirm_action("Are you sure you want to exit?"):
                        break

            except KeyboardInterrupt:
                print(f"\n\nOperation interrupted by user")
                if self.confirm_action("Do you want to exit the framework?"):
                    break
            except Exception as e:
                print(f"An error occurred: {e}")
                if not self.confirm_action("Continue?"):
                    break

        self.cleanup()

    def generate_device_summary_report(self):
        """Generate comprehensive device summary report"""

        print(f"\n{'#' * 80}")
        print(f"### DEVICE SUMMARY REPORT ###")
        print(f"{'#' * 80}")

        # Basic device information
        print(f"\nHostname: **{self.hostname}**")

        # Get chassis serial number from inventory
        chassis_sn = "N/A"
        if hasattr(self, 'chassis_inventory_info') and self.chassis_inventory_info:
            chassis_sn = self.chassis_inventory_info.get("SN", "N/A")

        print(f"Chassis SN: {chassis_sn}")

        # Get RP0 serial number
        rp0_sn = "N/A"
        if hasattr(self, 'all_card_inventory_info') and self.all_card_inventory_info:
            rp0_info = self.all_card_inventory_info.get("0/RP0/CPU0", {})
            rp0_sn = rp0_info.get("SN", "N/A")

        print(f"RP0 SN: {rp0_sn}")

        # Get first LC serial number (lowest LC number numerically)
        if hasattr(self, 'all_card_inventory_info') and self.all_card_inventory_info:
            # Find LC locations and sort numerically
            lc_locations = [loc for loc in self.all_card_inventory_info.keys() if re.match(r'0/\d+/CPU0', loc)]
            if lc_locations:
                # Sort numerically by LC number, not alphabetically
                def extract_lc_number(location):
                    match = re.search(r'0/(\d+)/CPU0', location)
                    return int(match.group(1)) if match else 999

                first_lc_location = sorted(lc_locations, key=extract_lc_number)[0]
                first_lc_info = self.all_card_inventory_info.get(first_lc_location, {})
                first_lc_sn = first_lc_info.get("SN", "N/A")
                first_lc_num = re.search(r'0/(\d+)/CPU0', first_lc_location).group(1) if re.match(r'0/\d+/CPU0',
                                                                                                  first_lc_location) else "X"
                print(f"LC{first_lc_num} SN: {first_lc_sn}")
            else:
                print(f"LC SN: N/A")
        else:
            print(f"LC SN: N/A")

        print(f"Tile number: ")
        print(f"GDCO: ")

        # Platform Status Table
        print(f"Platform Status:\n")

        # Recreate platform table with Asset Tag column
        if hasattr(self, 'platform_cards_details') and self.platform_cards_details:
            platform_report_table = PrettyTable()
            platform_report_table.field_names = ["LC / FC / RP / FT Location", "Asset Tag", "Serial Number", "VID",
                                                 "PID"]

            for card in self.platform_cards_details:
                platform_report_table.add_row([
                    card["Location"],
                    "",  # Asset Tag - left empty as requested
                    card["Serial Number"],
                    card["VID"],
                    card["PID"]
                ])

            print(platform_report_table)
        else:
            print("Platform status information not available")

        # Observations Section
        print(f"\n**Observations and Existing Issues:**")

        observations_found = False

        # Interface Summary
        if hasattr(self, 'interface_summary_data') and self.interface_summary_data:
            observations_found = True
            print(f"a) Interface status report:")
            interface_obs_table = PrettyTable()
            interface_obs_table.field_names = ["Total", "UP", "Down", "Admin Down"]
            interface_obs_table.add_row([
                self.interface_summary_data["Total"],
                self.interface_summary_data["UP"],
                self.interface_summary_data["Down"],
                self.interface_summary_data["Admin Down"]
            ])
            print(interface_obs_table)

        # NPU Link Errors
        if hasattr(self, 'npu_link_errors') and self.npu_link_errors:
            observations_found = True
            print(f"\nb) Fabric links down:")
            npu_obs_table = PrettyTable()
            npu_obs_table.field_names = ["Link ID", "Far-End Link (FSDB)"]
            for error in self.npu_link_errors[:10]:  # Show first 10
                npu_obs_table.add_row([error["Link ID"], error["Far-End Link (FSDB)"]])
            if len(self.npu_link_errors) > 10:
                npu_obs_table.add_row(["...", f"and {len(self.npu_link_errors) - 10} more"])
            print(npu_obs_table)

        # UCE/CRC Errors
        if hasattr(self, 'npu_stats_errors') and self.npu_stats_errors:
            observations_found = True
            print(f"\nc) UCE/CRC Errors:")
            uce_obs_table = PrettyTable()
            uce_obs_table.field_names = ["Node ID", "UCE Errors", "CRC Errors"]
            for error in self.npu_stats_errors:
                uce_obs_table.add_row([error["Node ID"], error["UCE Errors"], error["CRC Errors"]])
            print(uce_obs_table)

        # ASIC Errors
        if hasattr(self, 'asic_errors') and self.asic_errors:
            observations_found = True
            print(f"\nd) ASIC Errors:")
            asic_obs_table = PrettyTable()
            asic_obs_table.field_names = ["FC Location", "NPU Number", "Error Count"]
            for error in self.asic_errors:
                asic_obs_table.add_row([error["FC Location"], error["NPU number"], error["Error count"]])
            print(asic_obs_table)

        # Fabric Plane Statistics
        if hasattr(self, 'fabric_plane_errors') and self.fabric_plane_errors:
            observations_found = True
            print(f"\ne) Fabric Plane Statistics Errors:")
            fabric_obs_table = PrettyTable()
            fabric_obs_table.field_names = ["Plane ID", "CE Packets", "UCE Packets", "PE Packets"]
            for error in self.fabric_plane_errors:
                fabric_obs_table.add_row(
                    [error["Plane ID"], error["CE Packets"], error["UCE Packets"], error["PE Packets"]])
            print(fabric_obs_table)

        # Fan Tray Field Notice Issues
        if hasattr(self, 'fan_tray_errors') and self.fan_tray_errors:
            observations_found = True
            print(f"\nf) Fan Tray Field Notice Issues:")
            ft_obs_table = PrettyTable()
            ft_obs_table.field_names = ["Fan Tray Location", "Field Notice Symptoms", "PID/VID",
                                        "Replacement Recommended"]
            for error in self.fan_tray_errors:
                ft_obs_table.add_row([
                    error["Fan Tray Location"],
                    error["Field Notice Symptoms"],
                    f"{error['PID']}/{error['VID']}",
                    error["Replacement Recommended"]
                ])
            print(ft_obs_table)

        # --- FIX: ADD NEW SECTION FOR LC ASIC ERRORS ---
        if hasattr(self, 'lc_asic_errors') and self.lc_asic_errors:
            observations_found = True
            print(f"\ng) LC ASIC Errors:")
            lc_asic_table = PrettyTable()
            lc_asic_table.field_names = ["LC Location", "Error Output"]
            for error in self.lc_asic_errors:
                lc_asic_table.add_row([error["LC Location"], error["Error Output"]])
            print(lc_asic_table)
        # --- END OF FIX ---

        if not observations_found:
            print("NA")

        # Fabric Links Status
        print(f"\n**Fabric Links:**")
        # Links down status - Check MULTIPLE indicators
        fabric_reachability_failed = hasattr(self, 'fabric_reachability_errors') and self.fabric_reachability_errors
        fabric_links_down_detected = hasattr(self, 'fabric_links_down') and self.fabric_links_down
        npu_links_down_detected = hasattr(self, 'npu_link_errors') and self.npu_link_errors

        # Any of these conditions means fabric links are down
        any_fabric_links_down = fabric_reachability_failed or fabric_links_down_detected or npu_links_down_detected

        print(f"Links down - {'Yes' if any_fabric_links_down else 'No links are down.'}")

        # Links degraded status (from Python pre-checks)
        global PYTHON_PHASE2_ERRORS_DETECTED
        links_degraded_detected = PYTHON_PHASE2_ERRORS_DETECTED
        print(f"Links degraded - {'Yes' if links_degraded_detected else 'No links are degraded'}")

        # Next Steps (Static)
        print(f"\n**Next Steps:**")
        print(f"a) Locate device and verify tile and SNs.")
        print(f"b) Physically cordon off the device")
        print(f"c) Verify LED status , front and back")
        print(f"**d) Power off the device --- PLEASE GET CONFIRMATION FROM ME BEFORE DOING THIS**")
        print(f"e) Unscrew all the LC screws, unlatch LCs")
        print(f"f) Take out all the fan trays")
        print(f"g) Take out all the FCs")
        print(f"h) Inspect all of the LCs from the back of the chassis")
        print(f"i) Figure out the number of LCs that need to be installed")
        print(f"j) Perform installation for LCs and FCs")

        print(f"\n{'-' * 80}")

    # === EXECUTION METHODS ===

    def execute_file_upload_only(self):
        """Execute ONLY file upload operation"""
        print(f"\n{'#' * 70}")
        print(f"### MONITOR FILE UPLOAD ###")
        print(f"{'#' * 70}")

        if not self.confirm_action("Proceed with monitor file upload check/upload?"):
            return

        try:
            success = self._perform_file_upload_operation()
            if success:
                print(f"Monitor file operation completed successfully")
            else:
                print(f"Monitor file operation failed")
        except Exception as e:
            print(f"Monitor file operation failed: {e}")

    def _perform_file_upload_operation(self) -> bool:
        """Perform file upload operation exactly like Option 1"""

        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        shell = None
        try:
            logging.info(f"Connecting to {self.router_ip} for file upload...")
            connect_with_retry(client, self.router_ip, self.username, self.password)
            logging.info(f"Successfully connected to {self.router_ip} for file upload.")

            shell = client.invoke_shell()
            time.sleep(1)
            read_and_print_realtime(shell, timeout_sec=2, print_real_time=False)

            execute_command_in_shell(shell, "terminal length 0", "set terminal length to 0", timeout=5,
                                     print_real_time_output=False)
            execute_command_in_shell(shell, "terminal width 511", "set terminal width to 511", timeout=5,
                                     print_real_time_output=False)

            # Check and upload files
            success = check_and_upload_monitor_files(shell, self.router_ip, self.username, self.password, None, client)
            return success

        except Exception as e:
            logging.error(f"File upload operation failed: {e}")
            raise
        finally:
            if shell:
                try:
                    shell.send("exit\n")
                    time.sleep(1)
                    while shell.recv_ready():
                        shell.recv(65535).decode('utf-8', errors='ignore')
                    shell.close()
                except Exception:
                    pass
            if client:
                client.close()
            logging.info("File upload connection closed.")

    def execute_cli_precheck_only(self, standalone=True):
        """Execute CLI pre-checks WITHOUT monitor file upload"""

        # 1. DECLARE GLOBAL AT THE TOP OF THE FUNCTION
        global CLI_PRECHECK_RESULTS


        # Define file paths using the already-created output directory
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        session_log_path = os.path.join(self.output_directory, f"{self.hostname}_combined_session_log_{timestamp}.txt")
        cli_output_path = os.path.join(self.output_directory, f"{self.hostname}_combined_cli_output_{timestamp}.txt")

        session_log_file_handle = open(session_log_path, 'a', encoding='utf-8')
        cli_output_file = open(cli_output_path, 'a')

        # Add a file handler to the root logger for this specific operation's log
        file_handler = logging.FileHandler(session_log_path, encoding='utf-8')
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        logging.getLogger().addHandler(file_handler)

        # Redirect stdout to also write to the session log
        original_stdout = sys.stdout
        sys.stdout = Tee(self.true_original_stdout, session_log_file_handle)

        # Announce the file paths (THIS FUNCTIONALITY IS RETAINED)
        logging.info(f"Session log for this run will be saved to: {session_log_path}")
        logging.info(f"CLI output for this run will be saved to: {cli_output_path}")

        # Execute CLI health checks
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        shell = None
        overall_script_failed = [False]
        all_cpu_locations_from_platform = []
        ft_locations_from_platform = []
        all_card_inventory_info = {}
        current_inventory_raw = ""
        current_intf_summary_raw = ""
        current_intf_brief_raw = ""
        current_fpd_raw = ""
        current_run_parsed_interface_statuses = {}

        all_section_names = [
            "IOS-XR Version Check",
            "Platform Status & Serial Numbers",
            "Fabric Reachability Check",
            "Fabric Link Down Status Check",
            "NPU Link Information Check",
            "NPU Stats Link Check (UCE/CRC)",
            "NPU Driver Status Check",
            "Fabric Plane Statistics Check",
            "ASIC Errors Check (RP0)",
            "Inventory Collection",
            "Interface Status Check",
            "HW Module FPD Status Check",
            "Active Alarms Check",
            "Install Log Collection",
            "LC ASIC Errors Check",
            "Fan Tray Status Check",
            "Overall Environment Status Check",
        ]
        section_statuses = {name: "Not Run" for name in all_section_names}

        try:
            logging.info(f"Attempting to connect to {self.router_ip}...")
            connect_with_retry(client, self.router_ip, self.username, self.password)
            logging.info(f"Successfully connected to {self.router_ip}.")

            shell = client.invoke_shell()
            time.sleep(1)
            read_and_print_realtime(shell, timeout_sec=2, print_real_time=False)

            execute_command_in_shell(shell, "terminal length 0", "set terminal length to 0", timeout=5,
                                     print_real_time_output=False)
            execute_command_in_shell(shell, "terminal width 511", "set terminal width to 511", timeout=5,
                                     print_real_time_output=False)

            self.hostname = get_hostname(shell)
            logging.info(f"Sanitized hostname for file paths: {self.hostname}")

            self.chassis_model = get_chassis_model(shell, cli_output_file)
            logging.info(f"Detected chassis model: {self.chassis_model}")

            print(f"\n--- Device Information Report (Pre-checks) ---")

            _run_section_check("IOS-XR Version Check", check_ios_xr_version, section_statuses, overall_script_failed,
                               shell, cli_output_file)
            _run_section_check("Platform Status & Serial Numbers", check_platform_and_serial_numbers, section_statuses,
                               overall_script_failed, shell, all_card_inventory_info, all_cpu_locations_from_platform,
                               ft_locations_from_platform, cli_output_file, self)
            _run_section_check("Fabric Reachability Check", check_fabric_reachability, section_statuses,
                               overall_script_failed, shell, cli_output_file, chassis_model=self.chassis_model,
                               framework_instance=self)
            _run_section_check("Fabric Link Down Status Check", check_fabric_link_down_status, section_statuses,
                               overall_script_failed, shell, cli_output_file, self)
            _run_section_check("NPU Link Information Check", check_npu_link_info, section_statuses,
                               overall_script_failed, shell, cli_output_file, self)
            _run_section_check("NPU Stats Link Check (UCE/CRC)", check_npu_stats_link, section_statuses,
                               overall_script_failed, shell, cli_output_file, self)
            _run_section_check("NPU Driver Status Check", check_npu_driver_status, section_statuses,
                               overall_script_failed, shell, cli_output_file)
            _run_section_check("Fabric Plane Statistics Check", check_fabric_plane_stats, section_statuses,
                               overall_script_failed, shell, cli_output_file, self)
            _run_section_check("ASIC Errors Check (RP0)", check_asic_errors, section_statuses, overall_script_failed,
                               shell, cli_output_file, self)

            current_inventory_raw = _run_section_check("Inventory Collection", run_show_inventory, section_statuses,
                                                       overall_script_failed, shell, cli_output_file)
            if section_statuses["Inventory Collection"] == "Good":
                section_statuses["Inventory Collection"] = "Collection Only"

            intf_outputs = _run_section_check("Interface Status Check", check_interface_status, section_statuses,
                                              overall_script_failed, shell, cli_output_file, self)
            if intf_outputs:
                current_intf_summary_raw, current_intf_brief_raw = intf_outputs
                current_run_parsed_interface_statuses = parse_interface_status_from_strings(current_intf_summary_raw,
                                                                                            current_intf_brief_raw)
            if section_statuses["Interface Status Check"] == "Good":
                section_statuses["Interface Status Check"] = "Collection Only"

            current_fpd_raw = _run_section_check("HW Module FPD Status Check", check_hw_module_fpd_status,
                                                 section_statuses, overall_script_failed, shell, cli_output_file)
            if section_statuses["HW Module FPD Status Check"] == "Good":
                section_statuses["HW Module FPD Status Check"] = "Collection Only"

            section_name_alarms = "Active Alarms Check"
            section_name_install_log = "Install Log Collection"
            _run_section_check(section_name_alarms, check_and_capture_alarms_and_logs, section_statuses,
                               overall_script_failed, shell, cli_output_file)
            if section_statuses[section_name_alarms] != "Bad":
                section_statuses[section_name_install_log] = "Collection Only"
            else:
                section_statuses[section_name_install_log] = "Collection Only"

            section_name = "LC ASIC Errors Check"
            lc_locations_for_asic_check = [loc for loc in all_cpu_locations_from_platform if "RP" not in loc]
            if lc_locations_for_asic_check:
                _run_section_check(section_name, check_lc_asic_errors, section_statuses, overall_script_failed, shell,
                                   lc_locations_for_asic_check, cli_output_file, self)
            else:
                logging.warning(
                    f"Skipping {section_name} as no non-RP LC locations were identified from 'show platform'.")
                section_statuses[section_name] = "Collection Only (Skipped - No LCs)"

            section_name = "Fan Tray Status Check"
            if ft_locations_from_platform:
                _run_section_check(section_name, check_fan_tray_status, section_statuses, overall_script_failed, shell,
                                   ft_locations_from_platform, all_card_inventory_info, cli_output_file, self)
            else:
                logging.warning(f"Skipping {section_name} as no Fan Tray locations were identified.")
                section_statuses[section_name] = "Collection Only (Skipped - No FTs)"

            _run_section_check("Overall Environment Status Check", check_environment_status, section_statuses,
                               overall_script_failed, shell, cli_output_file)

            initially_down_report, _ = get_initially_down_physical_interfaces(current_run_parsed_interface_statuses)
            print(initially_down_report)

            print("\n" + "=" * 80)
            print(f"{'INITIATING COMPARISON WITH PERMANENT BASELINE':^80}")
            print("=" * 80 + "\n")

            permanent_baseline_file_path = find_earliest_file_as_permanent_baseline(self.hostname, self.output_directory)
            all_comparison_diffs_found = False

            if permanent_baseline_file_path:
                logging.info(f"Using permanent baseline file for comparison: {permanent_baseline_file_path}")

                try:
                    baseline_inventory_raw = extract_command_output_from_file(permanent_baseline_file_path,
                                                                              "show inventory")
                    baseline_intf_summary_raw = extract_command_output_from_file(permanent_baseline_file_path,
                                                                                 "show interface summary")
                    baseline_intf_brief_raw = extract_command_output_from_file(permanent_baseline_file_path,
                                                                               "show interface brief")
                    baseline_fpd_raw = extract_command_output_from_file(permanent_baseline_file_path,
                                                                        "show hw-module fpd")

                    baseline_optics_data = parse_inventory_optics_from_string(baseline_inventory_raw)
                    baseline_lcfc_data = parse_inventory_lcfc_from_string(baseline_inventory_raw)
                    baseline_interface_statuses = parse_interface_status_from_strings(baseline_intf_summary_raw,
                                                                                      baseline_intf_brief_raw)
                    baseline_fpd_statuses = parse_fpd_status_from_string(baseline_fpd_raw)

                    current_optics_data = parse_inventory_optics_from_string(current_inventory_raw)
                    current_lcfc_data = parse_inventory_lcfc_from_string(current_inventory_raw)
                    current_interface_statuses = parse_interface_status_from_strings(current_intf_summary_raw,
                                                                                     current_intf_brief_raw)
                    current_fpd_statuses = parse_fpd_status_from_string(current_fpd_raw)

                    optics_report, optics_diffs = compare_optics_inventory(current_optics_data, baseline_optics_data)
                    print(optics_report)
                    if optics_diffs: all_comparison_diffs_found = True

                    lcfc_report, lcfc_diffs = compare_lcfc_inventory(current_lcfc_data, baseline_lcfc_data,
                                                                     self.hostname, self.chassis_model)
                    print(lcfc_report)
                    if lcfc_diffs: all_comparison_diffs_found = True

                    intf_report, intf_diffs = compare_interface_statuses(current_interface_statuses,
                                                                         baseline_interface_statuses)
                    print(intf_report)
                    if intf_diffs: all_comparison_diffs_found = True

                    fpd_report, fpd_diffs = compare_fpd_statuses(current_fpd_statuses, baseline_fpd_statuses)
                    print(fpd_report)
                    if fpd_diffs: all_comparison_diffs_found = True

                except FileProcessingError as e:
                    logging.error(f"Error processing permanent baseline file for comparison: {e}")
                    print(f"\n--- Comparison Skipped (Error processing permanent baseline file) ---")
                except Exception as e:
                    logging.error(f"An unexpected error occurred during comparison: {e}", exc_info=True)
                    print(f"\n--- Comparison Skipped (Unexpected error) ---")

                if all_comparison_diffs_found:
                    print(f"\n--- COMPARISON COMPLETED WITH DIFFERENCES ---")
                    overall_script_failed[0] = True
                else:
                    print(f"\n--- COMPARISON COMPLETED - NO DIFFERENCES FOUND ---")

            else:
                print(
                    f"No permanent baseline CLI output file found for '{self.hostname}'. Comparison skipped for this run.")
                print(
                    f"The CLI output generated by this run ({cli_output_path}) will serve as the permanent baseline for next comparisons.")

        except (SSHConnectionError, paramiko.SSHException, RouterCommandError) as e:
            logging.critical(f"Critical connection or initial command error: {e}")
            overall_script_failed[0] = True
        except Exception as e:
            logging.critical(f"An unexpected error occurred during script execution: {e}", exc_info=True)
            overall_script_failed[0] = True
        finally:
            # --- Universal Cleanup (runs in both modes) ---
            if shell:
                logging.info("Exiting CLI session.")
                try:
                    shell.send("exit\n")
                    time.sleep(1)
                    while shell.recv_ready():
                        shell.recv(65535).decode('utf-8', errors='ignore')
                except Exception:
                    pass
                shell.close()
            if client:
                client.close()
            logging.info("SSH connection closed.")

            # Store results for the parent function to use
            CLI_PRECHECK_RESULTS = section_statuses.copy()

            # Always close the dedicated CLI output file as it's not used by other steps
            if cli_output_file:
                cli_output_file.close()
                logging.info(f"CLI output saved to {cli_output_path}")

            # --- ALWAYS PRINT SUMMARY (Moved to run in both modes) ---
            # The session_start_time is for the entire script run, which is the correct context here.
            total_execution_time = time.time() - self.session_start_time
            print_final_summary_table(section_statuses, total_execution_time)

            if overall_script_failed[0]:
                logging.critical(f"--- CLI Pre-Check Phase Finished with ERRORS / DIFFERENCES DETECTED ---")
            else:
                logging.info(f"--- CLI Pre-Check Phase Finished Successfully ---")
            # --- END OF SUMMARY PRINTING ---

            # --- Standalone-Only Resource Cleanup ---
            if standalone:
                logging.info("Running in standalone mode, performing full resource cleanup.")

                # Close the session log and restore stdout ONLY in standalone mode.
                if session_log_file_handle:
                    session_log_file_handle.flush()
                    session_log_file_handle.close()
                    logging.info(f"Session log file closed: {session_log_path}")

                sys.stdout = self.true_original_stdout
                logging.info("Standard output restored.")
            else:
                # This block runs when part of a sequence (standalone=False)
                logging.info("Running in sequential mode, leaving session log open for the next step.")

    def execute_python_precheck_only(self, standalone=True):
        """Execute Python pre-checks exactly like Part II"""
        global PYTHON_PHASE2_ERRORS_DETECTED
        PYTHON_PHASE2_ERRORS_DETECTED = False

        # Define file paths using the already-created output directory
        timestamp_for_logs = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        session_log_path = os.path.join(self.output_directory,
                                        f"{self.hostname}_python_pre_check_session_log_{timestamp_for_logs}.txt")
        raw_output_log_path = os.path.join(self.output_directory,
                                           f"{self.hostname}_python_pre_check_output_{timestamp_for_logs}.txt")

        # Create file handlers for this specific operation's log
        session_log_file_handler = logging.FileHandler(session_log_path)
        session_log_file_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
        logging.getLogger().addHandler(session_log_file_handler)

        raw_output_file = open(raw_output_log_path, 'w', encoding='utf-8')

        # Redirect stdout to also write to the raw output file
        original_stdout = sys.stdout
        sys.stdout = Tee(self.true_original_stdout, raw_output_file)

        # Announce the file paths (THIS FUNCTIONALITY IS RETAINED)
        logging.info(f"Internal script logs will be saved to: {session_log_path}")
        logging.info(f"All console output (including router raw output) will be logged to: {raw_output_log_path}")

        scripts_to_run = [
            "monitor_8800_system_v2_3_msft_bash_group0.py",
            "monitor_8800_system_v2_3_msft_bash_group1.py",
            "monitor_8800_system_v2_3_msft_bash_group2.py",
            "monitor_8800_system_v2_3_msft_bash_group3.py",
        ]

        script_aborted = False
        phase_results = {}

        # Phase 1 execution exactly like Part II
        client_phase1 = None
        shell_phase1 = None
        try:
            logging.info(f"\n{'#' * 70}\n### Starting Phase 1: Running scripts with '--dummy' yes ###\n{'#' * 70}\n")
            client_phase1 = paramiko.SSHClient()
            client_phase1.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            logging.info(f"Attempting to connect to {self.router_ip} for Phase 1...")
            connect_with_retry(client_phase1, self.router_ip, self.username, self.password)
            time.sleep(2)
            logging.info(f"Successfully connected to {self.router_ip} for Phase 1.")

            shell_phase1 = client_phase1.invoke_shell()
            time.sleep(1)

            self._execute_script_phase(shell_phase1, scripts_to_run, "'--dummy' yes")

            phase_results["Phase 1 Execution"] = "Complete"
            logging.info(f"✓ Phase 1 Complete. Waiting 20 minute before Phase 2...")

        except Exception as e:
            phase_results["Phase 1 Execution"] = "Failed"
            raise e
        finally:
            if shell_phase1:
                logging.info(f"Exiting bash prompt for Phase 1...")
                try:
                    shell_phase1.send("exit\n")
                    time.sleep(1)
                    shell_phase1.recv(65535).decode('utf-8', errors='ignore')
                except Exception as e:
                    logging.warning(f"Error during shell exit for Phase 1: {e}")
            if client_phase1:
                client_phase1.close()
                logging.info(f"SSH connection for Phase 1 closed.")

        # Countdown between phases exactly like Part II
        countdown_timer(20 * 60, self.true_original_stdout)

        # Phase 2 execution exactly like Part II
        client_phase2 = None
        shell_phase2 = None
        try:
            logging.info(f"\n{'#' * 70}\n### Starting Phase 2: Running scripts with '--dummy' no ###\n{'#' * 70}\n")
            client_phase2 = paramiko.SSHClient()
            client_phase2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            logging.info(f"Attempting to connect to {self.router_ip} for Phase 2...")
            connect_with_retry(client_phase2, self.router_ip, self.username, self.password)
            time.sleep(2)
            logging.info(f"Successfully connected to {self.router_ip} for Phase 2.")

            shell_phase2 = client_phase2.invoke_shell()
            time.sleep(1)

            self._execute_script_phase(shell_phase2, scripts_to_run, "'--dummy' no")

            phase_results["Phase 2 Execution"] = "Complete"
            logging.info(f"✓ Phase 2 Complete.")

        except Exception as e:
            phase_results["Phase 2 Execution"] = "Failed"
            script_aborted = True
        finally:
            if shell_phase2:
                logging.info(f"Exiting bash prompt for Phase 2...")
                try:
                    shell_phase2.send("exit\n")
                    time.sleep(1)
                    shell_phase2.recv(65535).decode('utf-8', errors='ignore')
                except Exception as e:
                    logging.warning(f"Error during shell exit for Phase 2: {e}")
            if client_phase2:
                client_phase2.close()
                logging.info(f"SSH connection for Phase 2 closed.")

                # Only print timing summary if running standalone
                if standalone:
                    total_execution_time = time.time() - self.session_start_time

                    if script_aborted:
                        logging.info(f"--- Script Execution Aborted ---")
                    else:
                        logging.info(f"--- Script Execution Finished Successfully ---")

                    print_python_final_summary_table(phase_results, total_execution_time)

                # Store results
                global PYTHON_PRECHECK_RESULTS
                PYTHON_PRECHECK_RESULTS = phase_results.copy()

                # Cleanup (only if standalone)
                if standalone:
                    sys.stdout = self.true_original_stdout

                    if session_log_file_handler:
                        logging.root.removeHandler(session_log_file_handler)
                        session_log_file_handler.close()
                        print(f"\nInternal session log closed: {session_log_path}")

                    if raw_output_file:
                        raw_output_file.close()
                        print(f"Raw output log closed: {raw_output_log_path}")

                    for handler in logging.root.handlers[:]:
                        if isinstance(handler, logging.StreamHandler) and handler.stream == self.true_original_stdout:
                            logging.root.removeHandler(handler)
                            break

                    total_execution_time = time.time() - self.session_start_time
                    print(f"\nTotal script execution time: {format_execution_time(total_execution_time)}")

    def _execute_script_phase(self, shell, scripts_to_run, script_arg_option):
        """Execute script phase exactly like Part II"""

        logging.info(f"--- Initial Shell Output ---")
        initial_output, _ = read_and_print_realtime(shell, timeout_sec=2, print_real_time=False)
        print(f"{initial_output}", end='')
        print()
        logging.info(f"--- End Initial Shell Output ---\n")

        if not self._execute_command_in_shell_bool(shell, "terminal length 0", "set terminal length to 0", timeout=5,
                                                   print_real_time_output=False):
            raise RouterCommandError("Failed to set terminal length 0.")

        if not self._execute_command_in_shell_bool(shell, "terminal width 511", "set terminal width to 511", timeout=5,
                                                   print_real_time_output=False):
            raise RouterCommandError("Failed to set terminal width 511.")

        if not self._execute_command_in_shell_bool(shell, "attach location 0/RP0/CPU0", "attach location 0/RP0/CPU0",
                                                   timeout=30, print_real_time_output=False):
            raise RouterCommandError(f"Failed to establish bash prompt on router.")

        if not self._execute_command_in_shell_bool(shell, "cd /misc/disk1/", "change directory to /misc/disk1/",
                                                   timeout=10, print_real_time_output=False):
            raise RouterCommandError(f"Failed to change directory on router.")

        scripts_outputs = run_script_list_phase(shell, scripts_to_run, script_arg_option)

        if script_arg_option == "'--dummy' no":
            logging.info(f"\n{'=' * 70}\n### Analyzing 'dummy no' script outputs for errors ###\n{'=' * 70}\n")
            for s_name, s_output in scripts_outputs:
                parse_and_print_errors(s_name, s_output)

        return True

    def _execute_command_in_shell_bool(self, shell, command, command_description, timeout=30,
                                       print_real_time_output=False):
        """Helper function that returns boolean like Part II"""
        logging.info(f"Sending '{command_description}' ('{command}')...")

        time.sleep(0.1)
        while shell.recv_ready():
            shell.recv(65535)

        shell.send(command + "\n")
        time.sleep(0.5)

        output, prompt_found = read_and_print_realtime(shell, timeout_sec=timeout,
                                                       print_real_time=print_real_time_output)

        if not prompt_found:
            logging.warning(
                f"Prompt not detected after '{command_description}'. Attempting to send newline and re-check.")
            shell.send("\n")
            output_retry, prompt_found_retry = read_and_print_realtime(shell, timeout_sec=5,
                                                                       print_real_time=print_real_time_output)
            prompt_found = prompt_found_retry
            if not prompt_found:
                raise RouterCommandError(
                    f"Failed to reach bash prompt after '{command_description}' re-check. Output: {output + output_retry}")
        return True

    def execute_all_prechecks_sequential(self):
        """Execute ALL pre-checks sequentially: File Upload + CLI + Python"""

        print(f"\n{'#' * 70}")
        print(f"### COMPLETE PRE-CHECK WORKFLOW ###")
        print(f"{'#' * 70}")

        total_estimated = 2 + 15 + 60  # File upload + CLI + Python
        print(f"Total Estimated Duration: {total_estimated} minutes")
        print(f"Complete Workflow: File Upload -> CLI Pre-Checks -> Python Pre-Checks")

        print(f"\nWORKFLOW SEQUENCE:")
        print(f"   Step 1: Upload monitor files if needed")
        print(f"   Step 2: Comprehensive health assessment")
        print(f"   Step 3: Two-phase dummy script validation")

        if not self.confirm_action("Proceed with complete 3-step workflow?"):
            return

        workflow_start_time = time.time()
        all_results = {}

        # === STEP 1: FILE UPLOAD ===
        print(f"\n{'Step 1/3: Monitor File Upload':=^80}")
        try:
            file_upload_start = time.time()
            success = self._perform_file_upload_operation()
            file_upload_duration = time.time() - file_upload_start

            if success:
                all_results["File Upload"] = f"Success ({format_execution_time(file_upload_duration)})"
                print(f"File upload completed successfully")
            else:
                all_results["File Upload"] = f"Failed ({format_execution_time(file_upload_duration)})"
                print(f"File upload failed")
                print(f"Continuing with remaining steps...")

        except Exception as e:
            file_upload_duration = time.time() - file_upload_start if 'file_upload_start' in locals() else 0
            logging.error(f"File upload failed: {e}")
            all_results["File Upload"] = f"Failed - {e}"
            print(f"File upload failed: {e}")
            print(f"Continuing with remaining steps...")

        # === STEP 2: CLI PRE-CHECKS ===
        print(f"\n{'Step 2/3: CLI Pre-Checks':=^80}")
        try:
            cli_start = time.time()
            self.execute_cli_precheck_only(standalone=False)
            cli_duration = time.time() - cli_start

            global CLI_PRECHECK_RESULTS
            if CLI_PRECHECK_RESULTS:
                cli_success = not any("Bad" in status for status in CLI_PRECHECK_RESULTS.values())
                if cli_success:
                    all_results["CLI Pre-Checks"] = f"Success ({format_execution_time(cli_duration)})"
                else:
                    all_results["CLI Pre-Checks"] = f"Issues Found ({format_execution_time(cli_duration)})"
            else:
                all_results["CLI Pre-Checks"] = f"Failed ({format_execution_time(cli_duration)})"

        except Exception as e:
            cli_duration = time.time() - cli_start if 'cli_start' in locals() else 0
            logging.error(f"CLI pre-checks failed: {e}")
            all_results["CLI Pre-Checks"] = f"Failed - {e}"

        # === STEP 3: PYTHON PRE-CHECKS ===
        print(f"\n{'Step 3/3: Python Pre-Checks':=^80}")
        try:
            python_start = time.time()
            self.execute_python_precheck_only(standalone=False)
            python_duration = time.time() - python_start

            global PYTHON_PRECHECK_RESULTS, PYTHON_PHASE2_ERRORS_DETECTED
            if PYTHON_PRECHECK_RESULTS:
                python_success = not PYTHON_PHASE2_ERRORS_DETECTED
                if python_success:
                    all_results["Python Pre-Checks"] = f"Success ({format_execution_time(python_duration)})"
                else:
                    all_results[
                        "Python Pre-Checks"] = f"Degraded Links Found ({format_execution_time(python_duration)})"
            else:
                all_results["Python Pre-Checks"] = f"Failed ({format_execution_time(python_duration)})"

        except Exception as e:
            python_duration = time.time() - python_start if 'python_start' in locals() else 0
            logging.error(f"Python pre-checks failed: {e}")
            all_results["Python Pre-Checks"] = f"Failed - {e}"

        # === FINAL COMBINED RESULTS ===
        workflow_duration = time.time() - workflow_start_time
        _display_complete_precheck_workflow_results(all_results, workflow_duration)

        # Generate final summary report
        self.generate_device_summary_report()

    # === INDIVIDUAL OPERATIONS ===

    def check_monitor_file_status(self):
        """Check monitor file status"""
        print(f"\nMONITOR FILE STATUS CHECK")
        print(f"{'─' * 40}")

        try:
            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_with_retry(client, self.router_ip, self.username, self.password)
            shell = client.invoke_shell()
            time.sleep(1)

            execute_command_in_shell(shell, "terminal length 0", "set terminal length", timeout=5,
                                     print_real_time_output=False)

            output = execute_command_in_shell(shell, "dir harddisk: | i .py", "check monitor files", timeout=30,
                                              print_real_time_output=True)

            required_files = ["group0.py", "group1.py", "group2.py", "group3.py"]
            files_found = [f for f in required_files if f in output]

            print(f"\nMONITOR FILE STATUS:")
            print(f"   Required Files: {len(required_files)}")
            print(f"   Found Files: {len(files_found)}")
            print(f"   Files: {', '.join(files_found) if files_found else 'None found'}")

            if len(files_found) == len(required_files):
                print(f"   Status: ALL FILES PRESENT")
            else:
                print(f"   Status: UPLOAD REQUIRED")

        except Exception as e:
            print(f"Monitor file status check failed: {e}")
        finally:
            try:
                if shell:
                    shell.close()
                if client:
                    client.close()
            except:
                pass

    def run_quick_health_check(self):
        """Quick health check"""
        print(f"\nQUICK HEALTH CHECK")
        print(f"{'─' * 40}")

        if not self.confirm_action("Proceed with quick health check?"):
            return

        try:
            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_with_retry(client, self.router_ip, self.username, self.password)
            shell = client.invoke_shell()
            time.sleep(1)

            execute_command_in_shell(shell, "terminal length 0", "set terminal length", timeout=5,
                                     print_real_time_output=False)

            quick_checks = [
                ("Router Clock", "show clock"),
                ("Platform Summary", "show platform | count"),
                ("System Version", "show version | i Version")
            ]

            print(f"\nQUICK HEALTH RESULTS:")
            for name, command in quick_checks:
                try:
                    print(f"\n--- {name} ---")
                    output = execute_command_in_shell(shell, command, name, timeout=30, print_real_time_output=True)
                    print(f"{name}: Completed")
                except Exception as e:
                    print(f"{name}: Failed - {e}")

        except Exception as e:
            print(f"Quick health check failed: {e}")
        finally:
            try:
                if shell:
                    shell.close()
                if client:
                    client.close()
            except:
                pass

    def run_baseline_comparison_only(self):
        """Baseline comparison only"""
        print(f"\nBASELINE COMPARISON ANALYSIS")
        print(f"{'─' * 40}")

        try:
            if not self.hostname or self.hostname == "unknown_host":
                self.hostname = get_hostname_from_router(self.router_ip, self.username, self.password)

            output_directory = os.path.join(os.getcwd(), self.hostname)
            if not os.path.exists(output_directory):
                print(f"No baseline directory found for {self.hostname}")
                return

            baseline_files = [f for f in os.listdir(output_directory) if 'cli_output' in f and f.endswith('.txt')]

            print(f"BASELINE FILE ANALYSIS:")
            print(f"   Directory: {output_directory}")
            print(f"   Baseline Files Found: {len(baseline_files)}")

            if baseline_files:
                print(f"   Available Baselines:")
                for i, filename in enumerate(sorted(baseline_files)[:5], 1):
                    file_date = filename.split('_')[-1].replace('.txt', '') if '_' in filename else 'Unknown'
                    print(f"      {i}. {file_date}")
                print(f"   Use CLI Pre-Check option for full comparison analysis")
            else:
                print(f"   No baseline files found")
                print(f"   Run CLI Pre-Check to establish baseline")

        except Exception as e:
            print(f"Baseline comparison analysis failed: {e}")

    def show_execution_status(self):
        """Show execution status"""
        print(f"\nPRE-CHECK EXECUTION STATUS")
        print(f"{'=' * 80}")

        session_duration = time.time() - self.session_start_time
        print(f"Router: {self.hostname} ({self.router_ip})")
        print(f"Session Duration: {format_execution_time(session_duration)}")
        print(f"User: {self.username}")

        global CLI_PRECHECK_RESULTS, PYTHON_PRECHECK_RESULTS, PYTHON_PHASE2_ERRORS_DETECTED

        print(f"\nOPERATION STATUS:")

        if CLI_PRECHECK_RESULTS:
            cli_success = not any("Bad" in status for status in CLI_PRECHECK_RESULTS.values())
            print(f"   CLI Pre-Checks: {'Completed' if cli_success else 'Issues Found'}")
            print(f"      Components: {len(CLI_PRECHECK_RESULTS)}")
            if not cli_success:
                issues = [comp for comp, status in CLI_PRECHECK_RESULTS.items() if "Bad" in status]
                print(f"      Issues: {', '.join(issues[:3])}{'...' if len(issues) > 3 else ''}")
        else:
            print(f"   CLI Pre-Checks: Not Run")

        if PYTHON_PRECHECK_RESULTS:
            python_success = not PYTHON_PHASE2_ERRORS_DETECTED
            print(f"   Python Pre-Checks: {'Clean' if python_success else 'Degraded Links'}")
            if not python_success:
                print(f"      Issue: Degraded links detected in validation")
        else:
            print(f"   Python Pre-Checks: Not Run")

        input(f"\nPress Enter to continue...")

    def show_help(self):
        """Show help"""
        print(f"\nPRE-CHECK FRAMEWORK HELP")
        print(f"{'=' * 80}")

        print(f"\nOPERATION DESCRIPTIONS:")
        print(f"   File Upload: Upload monitor scripts to router (automatic check)")
        print(f"   CLI Pre-Checks: Comprehensive health assessment (Part I functionality)")
        print(f"   Python Pre-Checks: Two-phase validation (Part II functionality)")

        print(f"\nRECOMMENDED WORKFLOW:")
        print(f"   1. CLI Pre-Checks: Establish system health baseline")
        print(f"   2. Python Pre-Checks: Validate fabric card functionality")
        print(f"   3. Review combined results for remediation readiness")

        print(f"\nIMPORTANT NOTES:")
        print(f"   • CLI issues must be resolved before remediation")
        print(f"   • Python validation detects pre-existing fabric problems")
        print(f"   • Degraded links indicate fabric card issues")

        print(f"\nSUPPORT:")
        print(f"   Author: {__author__}")
        print(f"   Email: {__email__}")

        input(f"\nPress Enter to return to menu...")

    def cleanup(self):
        """Cleanup framework resources"""
        print(f"\nPre-Check Framework Cleanup...")
        sys.stdout = self.true_original_stdout
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        total_session_time = time.time() - self.session_start_time
        print(f"Total Session Time: {format_execution_time(total_session_time)}")
        print(f"Framework cleanup completed")


def main():
    """Main function"""
    # --- ADD BANNER HERE ---
    print(f"{'=' * 80}")
    print(f"{'IOS-XR Universal Pre-Check Interactive Framework v3.0':^80}")
    print(f"{'=' * 80}")
    # --- END OF BANNER ---
    framework = InteractivePreCheckManager()

    try:
        framework.initialize()
        framework.run_interactive_framework()
    except KeyboardInterrupt:
        print(f"\n\nFramework interrupted by user")
    except Exception as e:
        logging.critical(f"Framework execution failed: {e}", exc_info=True)
        print(f"Critical framework error: {e}")
    finally:
        framework.cleanup()
        print(f"\nFramework session ended")


if __name__ == "__main__":
    main()