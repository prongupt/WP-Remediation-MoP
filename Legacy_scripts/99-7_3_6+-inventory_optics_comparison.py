import paramiko
import time
import getpass
import re
import logging
from prettytable import PrettyTable
import datetime
import os
import sys
from typing import List, Tuple, Dict, Any, Optional
import tempfile # Import for temporary file handling

# --- Logger Setup ---
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

if not logger.handlers:
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

SSH_TIMEOUT_SECONDS = 15

PROMPT_PATTERNS = [
    r'#\s*$',
    r'>\s*$',
    r'\]\s*$',
    r'\)\s*$'
]


# --- Exceptions ---
class SSHConnectionError(Exception): pass


class RouterCommandError(Exception): pass


class FileProcessingError(Exception): pass


# --- Utility ---
class Tee:
    def __init__(self, stdout, file_object):
        self.stdout = stdout
        self.file_object = file_object

    def write(self, data):
        self.stdout.write(data)
        self.file_object.write(data)

    def flush(self):
        self.stdout.flush()
        self.file_object.flush()


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
                logger.error(f"Error receiving data: {e}")
                break
        else:
            time.sleep(0.1)

    if print_real_time and full_output_buffer and not full_output_buffer.endswith('\n'):
        print()

    if not prompt_found:
        logger.warning(f"Timeout reached or prompt not found within {timeout_sec} seconds.")
    return full_output_buffer, prompt_found


def execute_command_in_shell(shell: paramiko.Channel, command: str, command_description: str,
                             timeout: int = 30, print_real_time_output: bool = False, cli_output_file=None) -> str:
    logger.info(f"Sending '{command_description}' ('{command}')...")
    if cli_output_file:
        cli_output_file.write(f"\n--- Command: {command} ---\n")
        cli_output_file.flush()

    shell.send(command + "\n")
    output, prompt_found = read_and_print_realtime(shell, timeout_sec=timeout, print_real_time=print_real_time_output)

    if cli_output_file:
        cli_output_file.write(output)
        cli_output_file.flush()

    if not prompt_found:
        logger.warning(f"Prompt not detected after '{command_description}'. Retrying...")
        shell.send("\n")
        output_retry, prompt_found_retry = read_and_print_realtime(shell, timeout_sec=5,
                                                                   print_real_time=print_real_time_output)
        if cli_output_file:
            cli_output_file.write(output_retry)
            cli_output_file.flush()

        output += output_retry
        prompt_found = prompt_found_retry

        if not prompt_found:
            raise RouterCommandError(
                f"Failed to reach prompt after '{command_description}' re-check. Output: {output}")

    return output


def get_hostname(shell: paramiko.Channel) -> str:
    logger.info("Retrieving hostname...")
    output = execute_command_in_shell(shell, "show running-config | i hostname", "get hostname", timeout=10)
    for line in output.splitlines():
        match = re.search(r"^\s*hostname\s+(\S+)", line)
        if match:
            hostname = match.group(1)
            sanitized = hostname.replace('.', '-')
            sanitized = re.sub(r'[^a-zA-Z0-9_-]', '', sanitized)
            return sanitized
    logger.warning("Hostname not found, using 'unknown_host'.")
    return "unknown_host"


def find_latest_cli_output_file(hostname_prefix: str, output_directory: str, current_file_path: Optional[str] = None) -> \
Optional[str]:
    # Define patterns for both new (comparison) and old (pre-check) naming conventions
    new_pattern = re.compile(rf"^{re.escape(hostname_prefix)}_comparison_cli_output_(\d{{8}}_\d{{6}})\.txt$")
    old_pattern = re.compile(rf"^{re.escape(hostname_prefix)}_pre_check_cli_output_(\d{{8}}_\d{{6}})\.txt$")

    latest_file, latest_timestamp = None, None
    if not os.path.isdir(output_directory):
        return None

    files_to_check = []
    for filename in os.listdir(output_directory):
        full_path = os.path.join(output_directory, filename)
        if current_file_path and full_path == current_file_path:
            continue # Skip the file currently being written

        new_match = new_pattern.match(filename)
        old_match = old_pattern.match(filename)

        if new_match:
            files_to_check.append((new_match.group(1), full_path))
        elif old_match:
            files_to_check.append((old_match.group(1), full_path))

    # Sort files by timestamp in descending order to easily find the latest
    files_to_check.sort(key=lambda x: datetime.datetime.strptime(x[0], '%Y%m%d_%H%M%S'), reverse=True)

    if files_to_check:
        latest_file = files_to_check[0][1] # The first element after sorting is the latest
        logger.debug(f"Found latest previous file: {latest_file}")
    else:
        logger.debug("No previous CLI output files found matching known patterns.")

    return latest_file


def extract_command_output(file_path: str, command_string: str) -> str:
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except FileNotFoundError:
        raise FileProcessingError(f"File not found: {file_path}")
    except Exception as e:
        raise FileProcessingError(f"Error reading file {file_path}: {e}")

    escaped_command = re.escape(command_string.strip())
    # This pattern assumes the command itself is on a line after "--- Command: " and before the output.
    # The output is then captured until the next "--- Command:" or end of file.
    pattern = re.compile(rf"--- Command: {escaped_command} ---\n(?:{escaped_command}\s*\n)?(.*?)(?=\n--- Command:|\Z)", re.DOTALL)
    match = pattern.search(content)
    if match:
        output_lines = match.group(1).strip().splitlines()
        cleaned = [line for line in output_lines if line.strip()]
        return "\n".join(cleaned).strip()
    return ""


# --- Parsers ---
def parse_inventory_optics(output: str) -> Dict[str, Dict[str, str]]:
    optics_info = {}
    lines = output.splitlines()
    current_location = None
    intf_pattern = re.compile(r'NAME: "([A-Za-z]+\d+(?:/\d+){2,})",')
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
    return optics_info


def parse_inventory_lcfc(output: str) -> Dict[str, Dict[str, str]]:
    lcfc_info = {}
    lines = output.splitlines()
    current_location = None
    card_pattern = re.compile(r'NAME: "(0/(?:LC|FC|RP)\d*(?:/CPU0)?|0/\d+/CPU0)",')
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
    return lcfc_info


def parse_interface_status_from_cli_output(file_path: str) -> Dict[str, Dict[str, str]]:
    """
    Parses 'show interface summary' and 'show interface brief' outputs from a CLI log file.
    Returns a dictionary mapping interface names to their status from both commands.
    """
    interface_statuses: Dict[str, Dict[str, str]] = {}
    content = ""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        logger.debug(f"Successfully read content from {file_path}, length: {len(content)}")
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        return {}
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return {}

    # Updated pattern to correctly match the command headers as written by execute_command_in_shell
    command_section_pattern = re.compile(
        r"--- Command: (show interface (?:summary|brief)) ---\n(?:show interface (?:summary|brief)\s*\n)?(.*?)(?=\n--- Command:|\Z)", re.DOTALL)


    summary_output_section = ""
    brief_output_section = ""

    for match in command_section_pattern.finditer(content): # Corrected from find_iter to finditer
        command = match.group(1).strip()
        output_section = match.group(2).strip()
        if command == "show interface summary":
            summary_output_section = output_section
            logger.debug(f"Found 'show interface summary' section. Length: {len(summary_output_section)}")
        elif command == "show interface brief":
            brief_output_section = output_section
            logger.debug(f"Found 'show interface brief' section. Length: {len(brief_output_section)}")

    if brief_output_section:
        brief_line_pattern = re.compile(
            r"^\s*(\S+)\s+(up|down|admin-down|not connect|unknown|--)\s+(up|down|admin-down|not connect|unknown|--)\s+.*$",
            re.IGNORECASE
        )

        brief_lines = [
            line for line in brief_output_section.splitlines()
            if not re.match(
                r"^\s*(Intf|Name|State|LineP|Encap|MTU|BW|---|\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+|RP/\d+/\S+#|show interface brief)\s*$",
                line.strip())
               and line.strip()
        ]

        logger.debug(
            f"Processing {len(brief_lines)} lines from 'show interface brief' after header filtering.")

        for line in brief_lines:
            match = brief_line_pattern.match(line)
            if match:
                intf_name = match.group(1).strip()
                brief_admin_status = match.group(2).strip()
                brief_protocol_status = match.group(3).strip()

                brief_admin_status = brief_admin_status.lower()
                brief_protocol_status = brief_protocol_status.lower()

                interface_statuses.setdefault(intf_name, {})["summary_status"] = brief_admin_status
                interface_statuses.setdefault(intf_name, {})["brief_status"] = brief_admin_status
                interface_statuses.setdefault(intf_name, {})["brief_protocol"] = brief_protocol_status
            else:
                logger.debug(f"Skipping brief line (no regex match): '{line}'")
    else:
        logger.debug("No 'show interface brief' output section found for parsing.")

    logger.debug(f"Final parsed interface statuses from {file_path}: {interface_statuses}")
    return interface_statuses


def parse_fpd_status_from_cli_output(file_path: str) -> Dict[Tuple[str, str], Dict[str, str]]:
    """
    Parses 'show hw-module fpd' output from a CLI log file.
    Returns a dictionary mapping (Location, FPD_Device) to their status details.
    """
    fpd_statuses: Dict[Tuple[str, str], Dict[str, str]] = {}
    content = ""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        logger.debug(f"Successfully read content from {file_path}, length: {len(content)}")
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        return {}
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return {}

    # Updated pattern to correctly match the command headers as written by execute_command_in_shell
    command_section_pattern = re.compile(
        r"--- Command: show hw-module fpd ---\n(?:show hw-module fpd\s*\n)?(.*?)(?=\n--- Command:|\Z)", re.DOTALL)

    fpd_output_section = ""
    match = command_section_pattern.search(content)
    if match:
        fpd_output_section = match.group(1).strip()
        logger.debug(f"Found 'show hw-module fpd' section. Length: {len(fpd_output_section)}")
    else:
        logger.debug("No 'show hw-module fpd' output section found in file.")
        return {}

    fpd_line_pattern = re.compile(
        r"^\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S*?)\s*(\S+)\s+(\S+)\s+(\S*)\s+(\S*)\s+(\S+)\s*$"
    )

    lines = fpd_output_section.splitlines()
    data_table_started = False
    for line in lines:
        stripped_line = line.strip()
        if not stripped_line:
            continue

        if re.match(r'^\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+$', stripped_line) or \
                re.match(r'^RP/\d+/\S+:\S+#', stripped_line) or \
                re.escape("show hw-module fpd") in re.escape(stripped_line):
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
            logger.debug(f"Skipping FPD line (no regex match): '{stripped_line}'")

    logger.debug(f"Final parsed FPD statuses from {file_path}: {fpd_statuses}")
    return fpd_statuses


# --- Comparison Functions ---
def compare_optics_inventory(current_optics: Dict[str, Dict[str, str]],
                             previous_optics: Dict[str, Dict[str, str]]) -> Tuple[str, bool]:
    logger.info("Comparing optics inventory...")
    differences_found = False
    comparison_table = PrettyTable()
    comparison_table.field_names = ["Interface", "Change Type", "Previous SN", "Current SN", "Details"]
    comparison_table.align = "l"

    prev_sn_to_intf = {data['SN']: intf for intf, data in previous_optics.items() if
                       data.get('SN') and data['SN'] != 'N/A'}
    accounted_previous_sns = set()

    for current_intf, current_data in current_optics.items():
        current_sn = current_data.get('SN')
        if current_sn and current_sn != 'N/A' and current_sn in prev_sn_to_intf:
            previous_intf_for_sn = prev_sn_to_intf[current_sn]
            if previous_intf_for_sn != current_intf:
                previous_sn_for_current_intf = previous_optics.get(current_intf, {}).get('SN', 'N/A')
                comparison_table.add_row([
                    current_intf,
                    "Incorrect Interface",
                    previous_sn_for_current_intf,
                    current_sn,
                    f"Previously on {previous_intf_for_sn}"
                ])
                differences_found = True
            accounted_previous_sns.add(current_sn)

    for previous_intf, previous_data in previous_optics.items():
        previous_sn = previous_data.get('SN')
        if previous_sn and previous_sn != 'N/A' and previous_sn not in accounted_previous_sns:
            current_sn_at_prev_intf = current_optics.get(previous_intf, {}).get('SN', 'N/A')
            comparison_table.add_row([
                previous_intf,
                "Optics Not Detected",
                previous_sn,
                current_sn_at_prev_intf,
                "Detected Previously"
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
                "New Optic"
            ])
            differences_found = True

    report_output = f"\n{'-' * 80}\n"
    report_output += f"{'OPTICS INVENTORY COMPARISON REPORT':^80}\n"
    report_output += f"{'-' * 80}\n"
    if differences_found:
        report_output += str(comparison_table) + "\nPlease review the optics inventory changes above.\n"
    else:
        report_output += "No optics inventory differences detected.\n"
    return report_output, differences_found


def compare_lcfc_inventory(current_lcfc: Dict[str, Dict[str, str]],
                           previous_lcfc: Dict[str, Dict[str, str]]) -> Tuple[str, bool]:
    logger.info("Comparing LC/FC/RP inventory...")
    differences_found = False
    comparison_table = PrettyTable()
    comparison_table.field_names = ["Location", "Change Type", "Previous SN", "Current SN", "Details"]
    comparison_table.align = "l"

    all_locations = sorted(set(current_lcfc.keys()) | set(previous_lcfc.keys()))

    for location in all_locations:
        current_sn = current_lcfc.get(location, {}).get('SN', 'N/A')
        previous_sn = previous_lcfc.get(location, {}).get('SN', 'N/A')

        if location in previous_lcfc and location in current_lcfc:
            if current_sn != previous_sn:
                comparison_table.add_row([
                    location,
                    "SN Changed",
                    previous_sn,
                    current_sn,
                    "Serial number changed"
                ])
                differences_found = True
        elif location in current_lcfc and location not in previous_lcfc:
            comparison_table.add_row([
                location,
                "Card Added",
                "N/A",
                current_sn,
                "New card detected"
            ])
            differences_found = True
        elif location in previous_lcfc and location not in current_lcfc:
            comparison_table.add_row([
                location,
                "Card Removed",
                previous_sn,
                "N/A",
                "Card removed from chassis"
            ])
            differences_found = True

    report_output = f"\n{'-' * 80}\n"
    report_output += f"{'LINE CARD / FABRIC CARD / ROUTE PROCESSOR INVENTORY COMPARISON REPORT':^80}\n"
    report_output += f"{'-' * 80}\n"
    if differences_found:
        report_output += str(comparison_table) + "\nPlease review the LC/FC/RP inventory changes above.\n"
    else:
        report_output += "No LC/FC/RP inventory differences detected.\n"
    return report_output, differences_found


def compare_interface_statuses(current_statuses: Dict[str, Dict[str, str]],
                               previous_statuses: Dict[str, Dict[str, str]]) -> Tuple[str, bool]:
    """
    Compares current and previous interface statuses and prints differences.
    """
    differences_found = False
    comparison_table = PrettyTable()
    comparison_table.field_names = ["Interface", "Change Type", "Previous Status", "Current Status"]
    comparison_table.align = "l"

    all_interfaces = sorted(list(set(current_statuses.keys()) | set(previous_statuses.keys())))

    for intf in all_interfaces:
        current_data = current_statuses.get(intf, {})
        previous_data = previous_statuses.get(intf, {})

        if intf not in previous_statuses and intf in current_statuses:
            summary_stat = current_data.get("summary_status", "N/A")
            brief_adm_stat = current_data.get("brief_status", "N/A")
            brief_prot_stat = current_data.get("brief_protocol", "N/A")
            comparison_table.add_row([intf, "Newly Appeared", "N/A",
                                      f"Summary: {summary_stat}, Brief: {brief_adm_stat}/{brief_prot_stat}"])
            differences_found = True
            continue

        if intf in previous_statuses and intf not in current_statuses:
            summary_stat = previous_data.get("summary_status", "N/A")
            brief_adm_stat = previous_data.get("brief_status", "N/A")
            brief_prot_stat = previous_data.get("brief_protocol", "N/A")
            comparison_table.add_row([intf, "Disappeared",
                                      f"Summary: {summary_stat}, Brief: {brief_adm_stat}/{brief_prot_stat}",
                                      "N/A"])
            differences_found = True
            continue

        if intf in current_statuses and intf in previous_statuses:
            current_sum = current_data.get("summary_status", "N/A")
            prev_sum = previous_data.get("summary_status", "N/A")
            if current_sum != prev_sum:
                comparison_table.add_row([intf, "Summary Status Change", prev_sum, current_sum])
                differences_found = True

            current_brief_adm = current_data.get("brief_status", "N/A")
            prev_brief_adm = previous_data.get("brief_status", "N/A")
            if current_brief_adm != prev_brief_adm:
                comparison_table.add_row([intf, "Brief Admin Status Change", prev_brief_adm, current_brief_adm])
                differences_found = True

            current_brief_prot = current_data.get("brief_protocol", "N/A")
            prev_brief_prot = previous_data.get("brief_protocol", "N/A")
            if current_brief_prot != prev_brief_prot:
                comparison_table.add_row([intf, "Brief Protocol Status Change", prev_brief_prot, current_brief_prot])
                differences_found = True

    report_output = f"\n{'-' * 80}\n"
    report_output += f"{'INTERFACE STATUS COMPARISON REPORT':^80}\n"
    report_output += f"{'-' * 80}\n"
    if differences_found:
        report_output += str(comparison_table) + "\nPlease review the interface status changes above.\n"
    else:
        report_output += "No interface status differences detected between current and previous run.\n"
    return report_output, differences_found


def compare_fpd_statuses(current_statuses: Dict[Tuple[str, str], Dict[str, str]],
                         previous_statuses: Dict[Tuple[str, str], Dict[str, str]]) -> Tuple[str, bool]:
    """
    Compares current and previous FPD statuses and prints differences for 'Status' and 'FPD Device'.
    """
    differences_found = False
    comparison_table = PrettyTable()
    comparison_table.field_names = ["Location", "FPD Device", "Change Type", "Previous Status", "Current Status"]
    comparison_table.align = "l"

    all_fpd_keys = sorted(list(set(current_statuses.keys()) | set(previous_statuses.keys())))

    for key in all_fpd_keys:
        current_data = current_statuses.get(key, {})
        previous_data = previous_statuses.get(key, {})

        location, fpd_device = key

        if key not in previous_statuses and key in current_statuses:
            current_status = current_data.get("Status", "N/A")
            comparison_table.add_row([location, fpd_device, "Newly Appeared", "N/A", current_status])
            differences_found = True
            continue

        if key in previous_statuses and key not in current_statuses:
            previous_status = previous_data.get("Status", "N/A")
            comparison_table.add_row([location, fpd_device, "Disappeared", previous_status, "N/A"])
            differences_found = True
            continue

        if key in current_statuses and key in previous_statuses:
            current_status_val = current_data.get("Status", "N/A")
            previous_status_val = previous_data.get("Status", "N/A")

            if current_status_val != previous_status_val:
                comparison_table.add_row(
                    [location, fpd_device, "Status Change", previous_status_val, current_status_val])
                differences_found = True

    report_output = f"\n{'-' * 80}\n"
    report_output += f"{'FPD STATUS COMPARISON REPORT':^80}\n"
    report_output += f"{'-' * 80}\n"
    if differences_found:
        report_output += str(comparison_table) + "\nPlease review the FPD status changes above.\n"
    else:
        report_output += "No FPD status differences detected between current and previous run.\n"
    return report_output, differences_found


# --- Main ---
def main():
    original_stdout = sys.stdout
    router_ip = input("Enter Router IP address or Hostname: ")
    username = input("Enter SSH Username: ")
    password = getpass.getpass("Enter SSH Password: ")

    client = None
    shell = None
    current_cli_output_file_handle = None # Renamed for clarity
    session_log_file_handle = None

    try:
        logger.info(f"Connecting to {router_ip}...")
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(router_ip, port=22, username=username, password=password, timeout=SSH_TIMEOUT_SECONDS,
                       look_for_keys=False)
        logger.info("Connected.")

        shell = client.invoke_shell()
        time.sleep(1)
        read_and_print_realtime(shell, timeout_sec=2)

        execute_command_in_shell(shell, "terminal length 0", "set terminal length to 0")
        execute_command_in_shell(shell, "terminal width 511", "set terminal width to 511")

        router_sanitized_hostname = get_hostname(shell)
        legacy_hostname_prefix_candidate = router_sanitized_hostname.replace('-', '_')

        cwd = os.getcwd()
        if os.path.basename(cwd) == router_sanitized_hostname:
            chosen_output_directory = cwd
            chosen_hostname_prefix = router_sanitized_hostname
        elif os.path.basename(cwd) == legacy_hostname_prefix_candidate:
            chosen_output_directory = cwd
            chosen_hostname_prefix = legacy_hostname_prefix_candidate
        else:
            potential_underscore_dir = os.path.join(cwd, legacy_hostname_prefix_candidate)
            if os.path.isdir(potential_underscore_dir):
                chosen_output_directory = potential_underscore_dir
                chosen_hostname_prefix = legacy_hostname_prefix_candidate
            else:
                potential_hyphen_dir = os.path.join(cwd, router_sanitized_hostname)
                chosen_output_directory = potential_hyphen_dir
                chosen_hostname_prefix = router_sanitized_hostname
                os.makedirs(chosen_output_directory, exist_ok=True)

        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        # Renamed the output file to be more generic for comparison data
        current_cli_output_path = os.path.join(chosen_output_directory,
                                                     f"{chosen_hostname_prefix}_comparison_cli_output_{timestamp}.txt")
        current_cli_output_file_handle = open(current_cli_output_path, 'a', encoding='utf-8')

        session_log_path = os.path.join(chosen_output_directory,
                                        f"{chosen_hostname_prefix}_comparison_session_log_{timestamp}.txt")
        session_log_file_handle = open(session_log_path, 'a', encoding='utf-8')

        sys.stdout = Tee(original_stdout, session_log_file_handle)
        print(f"\n--- Starting Comparisons for {chosen_hostname_prefix} ---")

        # Collect current data for all comparisons
        logger.info("Collecting current CLI outputs for comparison...")
        execute_command_in_shell(shell, "show inventory", "show inventory", timeout=120,
                               cli_output_file=current_cli_output_file_handle)
        execute_command_in_shell(shell, "show interface summary", "show interface summary", timeout=60,
                               cli_output_file=current_cli_output_file_handle)
        execute_command_in_shell(shell, "show interface brief", "show interface brief", timeout=120,
                               cli_output_file=current_cli_output_file_handle)
        execute_command_in_shell(shell, "show hw-module fpd", "show hw-module fpd", timeout=120,
                               cli_output_file=current_cli_output_file_handle)
        logger.info("Finished collecting current CLI outputs.")


        previous_cli_output_path = find_latest_cli_output_file(chosen_hostname_prefix, chosen_output_directory,
                                                               current_file_path=current_cli_output_path)

        all_diffs_found = False

        if previous_cli_output_path:
            logger.info(f"Found previous CLI output file for comparison: {previous_cli_output_path}")

            # --- Optics Inventory Comparison ---
            optics_diffs_found = False
            try:
                current_show_inventory_raw = extract_command_output(current_cli_output_path, "show inventory")
                previous_show_inventory_raw = extract_command_output(previous_cli_output_path, "show inventory")
                if current_show_inventory_raw and previous_show_inventory_raw:
                    current_optics_data = parse_inventory_optics(current_show_inventory_raw)
                    previous_optics_data = parse_inventory_optics(previous_show_inventory_raw)
                    optics_report_str, optics_diffs_found = compare_optics_inventory(current_optics_data,
                                                                                     previous_optics_data)
                    print(optics_report_str)
                    if optics_diffs_found:
                        all_diffs_found = True
                else:
                    print("\n--- Optics Inventory Comparison Skipped (Missing 'show inventory' data) ---")
            except FileProcessingError as e:
                print(f"\n--- Optics Inventory Comparison Skipped (Error processing files: {e}) ---")
            except Exception as e:
                print(f"\n--- Optics Inventory Comparison Failed (Unexpected error: {e}) ---")


            # --- LC/FC/RP Inventory Comparison ---
            lcfc_diffs_found = False
            try:
                # Reuse current_show_inventory_raw and previous_show_inventory_raw if already extracted
                if 'current_show_inventory_raw' not in locals(): # Check if variable exists from previous block
                    current_show_inventory_raw = extract_command_output(current_cli_output_path, "show inventory")
                if 'previous_show_inventory_raw' not in locals(): # Check if variable exists from previous block
                    previous_show_inventory_raw = extract_command_output(previous_cli_output_path, "show inventory")

                if current_show_inventory_raw and previous_show_inventory_raw:
                    current_lcfc_data = parse_inventory_lcfc(current_show_inventory_raw)
                    previous_lcfc_data = parse_inventory_lcfc(previous_show_inventory_raw)
                    lcfc_report_str, lcfc_diffs_found = compare_lcfc_inventory(current_lcfc_data, previous_lcfc_data)
                    print(lcfc_report_str)
                    if lcfc_diffs_found:
                        all_diffs_found = True
                else:
                    print("\n--- LC/FC/RP Inventory Comparison Skipped (Missing 'show inventory' data) ---")
            except FileProcessingError as e:
                print(f"\n--- LC/FC/RP Inventory Comparison Skipped (Error processing files: {e}) ---")
            except Exception as e:
                print(f"\n--- LC/FC/RP Inventory Comparison Failed (Unexpected error: {e}) ---")


            # --- Interface Status Comparison ---
            intf_diffs_found = False
            current_temp_intf_file = None
            previous_temp_intf_file = None
            try:
                current_intf_summary_content = extract_command_output(current_cli_output_path, "show interface summary")
                current_intf_brief_content = extract_command_output(current_cli_output_path, "show interface brief")
                previous_intf_summary_content = extract_command_output(previous_cli_output_path, "show interface summary")
                previous_intf_brief_content = extract_command_output(previous_cli_output_path, "show interface brief")

                # Create temporary files for parsing functions, adding the command headers back
                # This is necessary because parse_interface_status_from_cli_output expects a file containing multiple commands with headers.
                current_temp_intf_file = tempfile.NamedTemporaryFile(mode='w+', delete=False, encoding='utf-8', dir=chosen_output_directory)
                current_temp_intf_file.write(f"--- Command: show interface summary ---\n{current_intf_summary_content}\n")
                current_temp_intf_file.write(f"--- Command: show interface brief ---\n{current_intf_brief_content}\n")
                current_temp_intf_file.close() # Close to ensure content is written and can be read by parse function

                previous_temp_intf_file = tempfile.NamedTemporaryFile(mode='w+', delete=False, encoding='utf-8', dir=chosen_output_directory)
                previous_temp_intf_file.write(f"--- Command: show interface summary ---\n{previous_intf_summary_content}\n")
                previous_temp_intf_file.write(f"--- Command: show interface brief ---\n{previous_intf_brief_content}\n")
                previous_temp_intf_file.close() # Close to ensure content is written and can be read by parse function


                current_interface_statuses = parse_interface_status_from_cli_output(current_temp_intf_file.name)
                previous_interface_statuses = parse_interface_status_from_cli_output(previous_temp_intf_file.name)

                if current_interface_statuses or previous_interface_statuses:
                    intf_report_str, intf_diffs_found = compare_interface_statuses(current_interface_statuses, previous_interface_statuses)
                    print(intf_report_str)
                    if intf_diffs_found:
                        all_diffs_found = True
                else:
                    print("\n--- Interface Status Comparison Skipped (No interface data found) ---")
            except FileProcessingError as e:
                print(f"\n--- Interface Status Comparison Skipped (Error processing files: {e}) ---")
            except Exception as e:
                print(f"\n--- Interface Status Comparison Failed (Unexpected error: {e}) ---")
            finally:
                if current_temp_intf_file and os.path.exists(current_temp_intf_file.name):
                    os.remove(current_temp_intf_file.name)
                if previous_temp_intf_file and os.path.exists(previous_temp_intf_file.name):
                    os.remove(previous_temp_intf_file.name)


            # --- FPD Status Comparison ---
            fpd_diffs_found = False
            current_temp_fpd_file = None
            previous_temp_fpd_file = None
            try:
                current_fpd_content = extract_command_output(current_cli_output_path, "show hw-module fpd")
                previous_fpd_content = extract_command_output(previous_cli_output_path, "show hw-module fpd")

                # Create temporary files for parsing functions
                current_temp_fpd_file = tempfile.NamedTemporaryFile(mode='w+', delete=False, encoding='utf-8', dir=chosen_output_directory)
                current_temp_fpd_file.write(f"--- Command: show hw-module fpd ---\n{current_fpd_content}\n")
                current_temp_fpd_file.close()

                previous_temp_fpd_file = tempfile.NamedTemporaryFile(mode='w+', delete=False, encoding='utf-8', dir=chosen_output_directory)
                previous_temp_fpd_file.write(f"--- Command: show hw-module fpd ---\n{previous_fpd_content}\n")
                previous_temp_fpd_file.close()

                current_fpd_statuses = parse_fpd_status_from_cli_output(current_temp_fpd_file.name)
                previous_fpd_statuses = parse_fpd_status_from_cli_output(previous_temp_fpd_file.name)

                if current_fpd_statuses or previous_fpd_statuses:
                    fpd_report_str, fpd_diffs_found = compare_fpd_statuses(current_fpd_statuses, previous_fpd_statuses)
                    print(fpd_report_str)
                    if fpd_diffs_found:
                        all_diffs_found = True
                else:
                    print("\n--- FPD Status Comparison Skipped (No FPD data found) ---")
            except FileProcessingError as e:
                print(f"\n--- FPD Status Comparison Skipped (Error processing files: {e}) ---")
            except Exception as e:
                print(f"\n--- FPD Status Comparison Failed (Unexpected error: {e}) ---")
            finally:
                if current_temp_fpd_file and os.path.exists(current_temp_fpd_file.name):
                    os.remove(current_temp_fpd_file.name)
                if previous_temp_fpd_file and os.path.exists(previous_temp_fpd_file.name):
                    os.remove(previous_temp_fpd_file.name)


            # Final summary based on all comparisons
            if all_diffs_found:
                print(f"\n--- All Comparisons Completed for {chosen_hostname_prefix} with DIFFERENCES ---")
            else:
                print(f"\n--- All Comparisons Completed for {chosen_hostname_prefix} (No Differences Found) ---")

        else:
            print("\n--- All Comparisons Skipped (No previous CLI output file found) ---")

    finally:
        if shell:
            try:
                shell.send("exit\n")
                time.sleep(1)
                while shell.recv_ready():
                    shell.recv(65535).decode('utf-8', errors='ignore')
            except Exception as e:
                logger.warning(f"Error during shell exit: {e}")
            shell.close()
        if client:
            client.close()
        if current_cli_output_file_handle:
            current_cli_output_file_handle.close()
        sys.stdout = original_stdout
        if session_log_file_handle:
            session_log_file_handle.close()


if __name__ == "__main__":
    main()