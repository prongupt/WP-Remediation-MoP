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
    pattern = re.compile(rf"^{re.escape(hostname_prefix)}_pre_check_cli_output_(\d{{8}}_\d{{6}})\.txt$")
    latest_file, latest_timestamp = None, None
    if not os.path.isdir(output_directory):
        return None

    for filename in os.listdir(output_directory):
        full_path = os.path.join(output_directory, filename)
        if current_file_path and full_path == current_file_path:
            continue
        match = pattern.match(filename)
        if match:
            timestamp_str = match.group(1)
            try:
                ts = datetime.datetime.strptime(timestamp_str, '%Y%m%d_%H%M%S')
                if latest_timestamp is None or ts > latest_timestamp:
                    latest_timestamp = ts
                    latest_file = full_path
            except ValueError:
                continue
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
    pattern = re.compile(rf"--- Command: {escaped_command} ---\n(.*?)(?=\n--- Command:|\Z)", re.DOTALL)
    match = pattern.search(content)
    if match:
        output_lines = match.group(1).strip().splitlines()
        if output_lines and output_lines[0].strip() == command_string.strip():
            output_lines = output_lines[1:]
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


# --- New Comparison Functions ---
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


# --- Main ---
def main():
    original_stdout = sys.stdout
    router_ip = input("Enter Router IP address or Hostname: ")
    username = input("Enter SSH Username: ")
    password = getpass.getpass("Enter SSH Password: ")

    client = None
    shell = None
    current_inventory_file_handle = None
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
        current_inventory_output_path = os.path.join(chosen_output_directory,
                                                     f"{chosen_hostname_prefix}_inventory_optics_compare.txt")
        current_inventory_file_handle = open(current_inventory_output_path, 'a', encoding='utf-8')

        session_log_path = os.path.join(chosen_output_directory,
                                        f"{chosen_hostname_prefix}_inventory_compare_session_log_{timestamp}.txt")
        session_log_file_handle = open(session_log_path, 'a', encoding='utf-8')

        sys.stdout = Tee(original_stdout, session_log_file_handle)
        print(f"\n--- Starting Inventory Comparison for {chosen_hostname_prefix} ---")

        current_show_inventory_raw = execute_command_in_shell(shell, "show inventory", "show inventory", timeout=120,
                                                              cli_output_file=current_inventory_file_handle)
        previous_cli_output_path = find_latest_cli_output_file(chosen_hostname_prefix, chosen_output_directory,
                                                               current_file_path=None)

        if previous_cli_output_path:
            previous_show_inventory_raw = extract_command_output(previous_cli_output_path, "show inventory")
            if previous_show_inventory_raw:
                current_optics_data = parse_inventory_optics(current_show_inventory_raw)
                previous_optics_data = parse_inventory_optics(previous_show_inventory_raw)

                current_lcfc_data = parse_inventory_lcfc(current_show_inventory_raw)
                previous_lcfc_data = parse_inventory_lcfc(previous_show_inventory_raw)

                optics_report_str, optics_diffs_found = compare_optics_inventory(current_optics_data,
                                                                                 previous_optics_data)
                lcfc_report_str, lcfc_diffs_found = compare_lcfc_inventory(current_lcfc_data, previous_lcfc_data)

                print(optics_report_str)
                print(lcfc_report_str)

                if optics_diffs_found or lcfc_diffs_found:
                    print(f"\n--- Inventory Comparison Completed for {chosen_hostname_prefix} with DIFFERENCES ---")
                else:
                    print(
                        f"\n--- Inventory Comparison Completed for {chosen_hostname_prefix} (No Differences Found) ---")
            else:
                print("\n--- Comparison Skipped (Previous 'show inventory' not found) ---")
        else:
            print("\n--- Comparison Skipped (No previous CLI output file found) ---")

    finally:
        if shell:
            try:
                shell.send("exit\n")
                time.sleep(1)
                while shell.recv_ready():
                    shell.recv(65535).decode('utf-8', errors='ignore')
            except:
                pass
            shell.close()
        if client:
            client.close()
        if current_inventory_file_handle:
            current_inventory_file_handle.close()
        sys.stdout = original_stdout
        if session_log_file_handle:
            session_log_file_handle.close()


if __name__ == "__main__":
    main()
