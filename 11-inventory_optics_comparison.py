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
logger.setLevel(logging.INFO)  # Keeping INFO for normal operation

# Ensure no duplicate handlers if script is run multiple times in same session
if not logger.handlers:
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

SSH_TIMEOUT_SECONDS = 15

# Common IOS-XR prompts
PROMPT_PATTERNS = [
    r'#\s*$',  # Privileged exec mode
    r'>\s*$',  # User exec mode
    r'\]\s*$',  # Config mode (e.g., "router(config)#")
    r'\)\s*$'  # Sub-config modes
]


# --- Custom Exceptions ---
class SSHConnectionError(Exception):
    """Custom exception for SSH connection failures."""
    pass


class RouterCommandError(Exception):
    """Custom exception for command execution failures on the router."""
    pass


class FileProcessingError(Exception):
    """Custom exception for errors during file reading/parsing."""
    pass


# --- Utility Classes/Functions for SSH Interaction ---

# Custom stream to redirect stdout to both console and a file
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
    """
    Reads data from the SSH shell in real-time until a prompt is found or timeout occurs.
    Returns the full output buffer and a boolean indicating if a prompt was found.
    """
    full_output_buffer = ""
    start_time = time.time()
    prompt_found = False
    prompt_check_buffer = ""  # Buffer to check for prompt, keeps last few lines

    while time.time() - start_time < timeout_sec:
        if shell_obj.recv_ready():
            try:
                data = shell_obj.recv(65535).decode('utf-8', errors='ignore')
                if data:
                    if print_real_time:
                        print(f"{data}", end='')
                    full_output_buffer += data
                    prompt_check_buffer += data
                    # Keep only the last 500 characters to check for prompt efficiently
                    if len(prompt_check_buffer) > 500:
                        prompt_check_buffer = prompt_check_buffer[-500:]
                    lines = prompt_check_buffer.strip().splitlines()
                    if lines:
                        last_line = lines[-1]
                        for pattern in PROMPT_PATTERNS:
                            if re.search(pattern, last_line):
                                prompt_found = True
                                if print_real_time and not data.endswith('\n'):
                                    print()  # Ensure output ends with a newline
                                return full_output_buffer, prompt_found
            except Exception as e:
                logger.error(f"Error receiving data: {e}")
                break
        else:
            time.sleep(0.1)  # Wait a bit if no data is ready

    if print_real_time and full_output_buffer and not full_output_buffer.endswith('\n'):
        print()  # Ensure output ends with a newline if not already

    if not prompt_found:
        logger.warning(f"Timeout reached or prompt not found within {timeout_sec} seconds.")
    return full_output_buffer, prompt_found


def execute_command_in_shell(shell: paramiko.Channel, command: str, command_description: str,
                             timeout: int = 30, print_real_time_output: bool = False, cli_output_file=None) -> str:
    """
    Sends a command to the SSH shell and returns its output.
    Optionally prints output in real-time and writes to a file.
    Raises RouterCommandError if prompt is not found after command execution.
    """
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
        logger.warning(f"Prompt not detected after '{command_description}'. Attempting to send newline and re-check.")
        shell.send("\n")
        output_retry, prompt_found_retry = read_and_print_realtime(shell, timeout_sec=5,
                                                                   print_real_time=print_real_time_output)

        if cli_output_file:
            cli_output_file.write(output_retry)
            cli_output_file.flush()

        output += output_retry
        prompt_found = prompt_found_retry  # Update prompt_found status

        if not prompt_found:
            raise RouterCommandError(
                f"Failed to reach prompt after '{command_description}' re-check. Output: {output}")

    return output


def get_hostname(shell: paramiko.Channel) -> str:
    """
    Retrieves the hostname of the router and sanitizes it for filename use.
    The sanitization converts dots to hyphens, but preserves underscores,
    matching the behavior of all_XR_pre_check_CLI.py.
    """
    logger.info("Attempting to retrieve hostname using 'show running-config | i hostname'...")
    output = execute_command_in_shell(shell, "show running-config | i hostname", "get hostname", timeout=10)
    for line in output.splitlines():
        match = re.search(r"^\s*hostname\s+(\S+)", line)
        if match:
            hostname = match.group(1)
            # ONLY replace dots with hyphens
            sanitized_hostname = hostname.replace('.', '-')
            # Remove any other characters not suitable for filenames, but PRESERVE underscores
            sanitized_hostname = re.sub(r'[^a-zA-Z0-9_-]', '', sanitized_hostname)
            logger.info(f"Hostname detected and sanitized: {sanitized_hostname}")
            return sanitized_hostname
    logger.warning("Could not parse hostname from 'show running-config | i hostname' output. Using 'unknown_host'.")
    return "unknown_host"


def find_latest_cli_output_file(hostname_prefix: str, output_directory: str, current_file_path: Optional[str] = None) -> \
Optional[str]:
    """
    Finds the path to the most recent pre-check CLI output file for a given hostname prefix,
    excluding the current file being generated (if current_file_path is provided).
    """
    # Pattern to match files like "hostname_pre_check_cli_output_YYYYMMDD_HHMMSS.txt"
    pattern = re.compile(rf"^{re.escape(hostname_prefix)}_pre_check_cli_output_(\d{{8}}_\d{{6}})\.txt$")
    latest_file = None
    latest_timestamp = None

    if not os.path.isdir(output_directory):
        logger.debug(f"Output directory not found: {output_directory}")
        return None

    for filename in os.listdir(output_directory):
        full_path = os.path.join(output_directory, filename)
        if current_file_path and full_path == current_file_path:  # Skip the current file being written
            continue

        match = pattern.match(filename)
        if match:
            timestamp_str = match.group(1)
            try:
                current_timestamp = datetime.datetime.strptime(timestamp_str, '%Y%m%d_%H%M%S')
                if latest_timestamp is None or current_timestamp > latest_timestamp:
                    latest_timestamp = current_timestamp
                    latest_file = full_path
            except ValueError:
                logger.warning(f"Could not parse timestamp from filename: {filename}")
                continue
    return latest_file


def extract_command_output(file_path: str, command_string: str) -> str:
    """
    Extracts the output of a specific command from a CLI log file.
    Assumes commands are delimited by '--- Command: <command> ---'.
    """
    content = ""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        logger.debug(f"Successfully read content from {file_path}, length: {len(content)}")
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        raise FileProcessingError(f"File not found: {file_path}")
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        raise FileProcessingError(f"Error reading file {file_path}: {e}")

    # Escape special characters in the command string for regex
    escaped_command = re.escape(command_string.strip())
    # Regex to find the command section and capture its content
    # It looks for "--- Command: <command> ---" and captures everything until the next "--- Command:" or end of file
    pattern = re.compile(
        rf"--- Command: {escaped_command} ---\n(.*?)(?=\n--- Command:|\Z)", re.DOTALL
    )
    match = pattern.search(content)
    if match:
        output = match.group(1).strip()
        logger.debug(f"Extracted '{command_string}' output (length: {len(output)}). First 200 chars: {output[:200]}")
        # Remove the command line itself if it appears at the start of the output
        output_lines = output.splitlines()
        if output_lines and output_lines[0].strip() == command_string.strip():
            output_lines = output_lines[1:]

        # Remove common timestamps and prompts that might be at the beginning or end of the output
        cleaned_output_lines = []
        for line in output_lines:
            stripped_line = line.strip()
            if not stripped_line: continue
            if re.match(r'^\w{3}\s+\w{3}\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+$', stripped_line): continue  # Timestamp
            if re.match(r'^RP/\d+/\S+:\S+#', stripped_line): continue  # Prompt
            if re.match(r'^\s*$', stripped_line): continue  # Empty lines
            cleaned_output_lines.append(line)  # Keep original line for formatting

        return "\n".join(cleaned_output_lines).strip()
    else:
        logger.warning(f"Command '{command_string}' output section not found in {file_path}.")
        logger.debug(f"Content of {file_path} (first 500 chars): {content[:500]}")  # Added for debugging
        return ""


# --- Inventory Parsing Functions ---

def parse_inventory_optics(inventory_output_string: str) -> Dict[str, Dict[str, str]]:
    """
    Parses 'show inventory' output specifically for optics modules.
    Returns a dictionary mapping interface names (locations) to their PID, VID, and SN.
    """
    optics_info = {}
    lines = inventory_output_string.splitlines()
    current_location = None

    # Regex to match interface names like "FourHundredGigE0/9/0/0"
    # This pattern is robust to capture various interface types (GigabitEthernet, TenGigE, etc.)
    # and their full path (e.g., FourHundredGigE0/9/0/0, GigabitEthernet0/RP0/CPU0/0)
    # It specifically looks for names that appear to be interfaces, not chassis, RPs, LCs, etc.
    # Interfaces typically have multiple slashes in their location.
    interface_name_pattern = re.compile(r'NAME: "([A-Za-z]+\d+(?:/\d+){2,})",')
    pid_vid_sn_pattern = re.compile(r'PID: (\S+)\s*,\s*VID: (\S+),\s*SN: (\S+)')

    for line in lines:
        name_match = interface_name_pattern.search(line)
        if name_match:
            current_location = name_match.group(1)
            logger.debug(f"Optics parser: Matched interface name: {current_location}")
            continue  # Move to the next line to find PID/VID/SN

        pid_vid_sn_match = pid_vid_sn_pattern.search(line)
        if pid_vid_sn_match and current_location:
            optics_info[current_location] = {
                "PID": pid_vid_sn_match.group(1),
                "VID": pid_vid_sn_match.group(2),
                "SN": pid_vid_sn_match.group(3)
            }
            logger.debug(f"Optics parser: Parsed data for {current_location}: {optics_info[current_location]}")
            current_location = None  # Reset for the next optic
    return optics_info


def parse_inventory_lcfc(inventory_output_string: str) -> Dict[str, Dict[str, str]]:
    """
    Parses 'show inventory' output for Line Cards (LC), Fabric Cards (FC), and Route Processors (RP).
    Returns a dictionary mapping their locations to PID, VID, and SN.
    """
    lcfc_info = {}
    lines = inventory_output_string.splitlines()
    current_location = None

    # UPDATED REGEX to include 0/SLOT_NUMBER/CPU0 for Line Cards
    card_name_pattern = re.compile(r'NAME: "(0/(?:LC|FC|RP)\d*(?:/CPU0)?|0/\d+/CPU0)",')
    pid_vid_sn_pattern = re.compile(r'PID: (\S+)\s*,\s*VID: (\S+),\s*SN: (\S+)')

    for line in lines:
        name_match = card_name_pattern.search(line)
        if name_match:
            current_location = name_match.group(1)
            logger.debug(f"LC/FC parser: Matched location: {current_location}")  # Added for debugging
            continue

        pid_vid_sn_match = pid_vid_sn_pattern.search(line)
        if pid_vid_sn_match and current_location:
            lcfc_info[current_location] = {
                "PID": pid_vid_sn_match.group(1),
                "VID": pid_vid_sn_match.group(2),
                "SN": pid_vid_sn_match.group(3)
            }
            logger.debug(
                f"LC/FC parser: Parsed data for {current_location}: {lcfc_info[current_location]}")  # Added for debugging
            current_location = None
    return lcfc_info


# --- Inventory Comparison Functions ---

def compare_optics_inventory(current_optics: Dict[str, Dict[str, str]],
                             previous_optics: Dict[str, Dict[str, str]]) -> Tuple[str, bool]:
    """
    Compares current and previous optics inventory for missing or swapped serial numbers.
    Returns a formatted string of the comparison report and a boolean indicating if differences were found.
    """
    logger.info("Comparing optics inventory...")
    differences_found = False
    comparison_table = PrettyTable()
    comparison_table.field_names = ["Interface", "Change Type", "Previous SN", "Current SN", "Details"]
    comparison_table.align = "l"

    # Create reverse mappings for SN to Interface for easy lookup
    # Filter out 'N/A' SNs as they are not useful for tracking specific optics
    prev_sn_to_intf = {data['SN']: intf for intf, data in previous_optics.items() if data['SN'] != 'N/A'}
    curr_sn_to_intf = {data['SN']: intf for intf, data in current_optics.items() if data['SN'] != 'N/A'}

    # Track which previous optics (by SN) have been accounted for in the current inventory
    accounted_previous_sns = set()

    # 1. Check for Optic Moved to Incorrect Interface
    for current_intf, current_data in current_optics.items():
        current_sn = current_data.get('SN')
        if current_sn and current_sn != 'N/A':
            if current_sn in prev_sn_to_intf:
                previous_intf_for_sn = prev_sn_to_intf[current_sn]
                if previous_intf_for_sn != current_intf:
                    comparison_table.add_row([
                        current_intf,
                        "Incorrect Interface",
                        current_sn,  # Previous SN is the same as current SN for a move
                        current_sn,
                        f"Previously on {previous_intf_for_sn}"  # Concise detail
                    ])
                    differences_found = True
                accounted_previous_sns.add(current_sn)  # Mark this SN as accounted for

    # 2. Check for Optics Not Detected (Missing or SN became N/A)
    for previous_intf, previous_data in previous_optics.items():
        previous_sn = previous_data.get('SN')
        if previous_sn and previous_sn != 'N/A' and previous_sn not in accounted_previous_sns:
            # If the SN was not found in any current interface, it's missing or its SN is now N/A
            # This covers all cases where the optic is no longer in its expected place or detected.
            current_sn_at_prev_intf = current_optics.get(previous_intf, {}).get('SN', 'N/A')

            comparison_table.add_row([
                previous_intf,
                "Optics Not Detected",
                previous_sn,
                current_sn_at_prev_intf,  # Show what's there now, if anything
                "Detected Previously"
            ])
            differences_found = True

    # 3. Check for Newly Added Optics
    for current_intf, current_data in current_optics.items():
        current_sn = current_data.get('SN')
        if current_sn and current_sn != 'N/A' and current_sn not in prev_sn_to_intf:
            comparison_table.add_row([
                current_intf,
                "Optic Added",
                "N/A",
                current_sn,
                "New Optic"  # Concise detail
            ])
            differences_found = True

    report_output = f"\n{'-' * 80}\n"
    report_output += f"{'OPTICS INVENTORY COMPARISON REPORT':^80}\n"
    report_output += f"{'-' * 80}\n"

    if differences_found:
        report_output += str(comparison_table) + "\n"
        report_output += "Please review the optics inventory changes above.\n"
        logger.warning("!!! OPTICS INVENTORY DIFFERENCES DETECTED !!!")
    else:
        report_output += "No optics inventory differences detected.\n"
        logger.info("No optics inventory differences detected.")

    return report_output, differences_found


def compare_lcfc_inventory(current_lcfc: Dict[str, Dict[str, str]],
                           previous_lcfc: Dict[str, Dict[str, str]]) -> Tuple[str, bool]:
    """
    Compares current and previous LC/FC/RP inventory for changes in Location and Serial Number.
    Returns a formatted string of the comparison report and a boolean indicating if differences were found.
    """
    logger.info("Comparing Line Card, Fabric Card, and Route Processor inventory...")
    differences_found = False
    comparison_table = PrettyTable()
    comparison_table.field_names = ["Location", "Change Type", "Previous SN", "Current SN", "Details"]
    comparison_table.align = "l"

    all_locations = sorted(list(set(current_lcfc.keys()) | set(previous_lcfc.keys())))

    for location in all_locations:
        current_data = current_lcfc.get(location, {})
        previous_data = previous_lcfc.get(location, {})

        current_sn = current_data.get('SN', 'N/A')
        previous_sn = previous_data.get('SN', 'N/A')

        if location in previous_lcfc and location in current_lcfc:
            # Location exists in both, check for SN change
            if current_sn != previous_sn:
                comparison_table.add_row([
                    location,
                    "SN Changed",
                    previous_sn,
                    current_sn,
                    "SN changed"  # Concise detail
                ])
                differences_found = True
        elif location in current_lcfc and location not in previous_lcfc:
            # New card/location added
            comparison_table.add_row([
                location,
                "Card Added",
                "N/A",
                current_sn,
                "New card"  # Concise detail
            ])
            differences_found = True
        elif location in previous_lcfc and location not in current_lcfc:
            # Card/location removed
            comparison_table.add_row([
                location,
                "Card Removed",
                previous_sn,
                "N/A",
                "Card removed"  # Concise detail
            ])
            differences_found = True

    report_output = f"\n{'-' * 80}\n"
    report_output += f"{'LINE CARD / FABRIC CARD / ROUTE PROCESSOR INVENTORY COMPARISON REPORT':^80}\n"
    report_output += f"{'-' * 80}\n"

    if differences_found:
        report_output += str(comparison_table) + "\n"
        report_output += "Please review the LC/FC/RP inventory changes above.\n"
        logger.warning("!!! LINE CARD / FABRIC CARD / ROUTE PROCESSOR INVENTORY DIFFERENCES DETECTED !!!")
    else:
        report_output += "No Line Card, Fabric Card, or Route Processor inventory differences detected.\n"
        logger.info("No Line Card, Fabric Card, or Route Processor inventory differences detected.")

    return report_output, differences_found


# --- Main Execution Logic ---

def main():
    # Preserve original stdout for logging to console while redirecting print()
    original_stdout = sys.stdout

    # Get router connection details
    router_ip = input(f"Enter Router IP address or Hostname: ")
    username = input(f"Enter SSH Username: ")
    password = getpass.getpass(f"Enter SSH Password: ")

    client = None
    shell = None
    current_inventory_file_handle = None
    session_log_file_handle = None

    # These will be determined dynamically
    chosen_output_directory = None
    chosen_hostname_prefix = "unknown_host"
    current_inventory_output_path = None  # Path for the new _inventory_optics_compare.txt

    try:
        logger.info(f"Attempting to connect to {router_ip}...")
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        # AutoAddPolicy is okay for one-off scripts, but not production for security reasons
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(router_ip, port=22, username=username, password=password, timeout=SSH_TIMEOUT_SECONDS,
                       look_for_keys=False)
        logger.info(f"Successfully connected to {router_ip}.")

        shell = client.invoke_shell()
        time.sleep(1)  # Give shell a moment to initialize
        read_and_print_realtime(shell, timeout_sec=2)  # Clear initial buffer

        # Set terminal properties for full output
        execute_command_in_shell(shell, "terminal length 0", "set terminal length to 0")
        execute_command_in_shell(shell, "terminal width 511", "set terminal width to 511")  # Max width for IOS-XR

        # Get the hostname from the device (sanitized to match all_XR_pre_check_CLI.py's behavior)
        router_sanitized_hostname = get_hostname(shell)
        # Derive the potential "legacy" (underscore) hostname prefix.
        # If router_sanitized_hostname already has underscores, this will just be itself.
        legacy_hostname_prefix_candidate = router_sanitized_hostname.replace('-', '_')

        current_working_dir = os.getcwd()
        chosen_output_directory = None
        chosen_hostname_prefix = None

        # Scenario 1: Script is run from *inside* a hostname-specific directory
        # Check if the current directory's name matches either the sanitized or legacy hostname format
        if os.path.basename(current_working_dir) == router_sanitized_hostname:
            chosen_output_directory = current_working_dir
            chosen_hostname_prefix = router_sanitized_hostname
            logger.info(f"Running from within hostname directory: {chosen_output_directory}")
        elif os.path.basename(current_working_dir) == legacy_hostname_prefix_candidate:
            chosen_output_directory = current_working_dir
            chosen_hostname_prefix = legacy_hostname_prefix_candidate
            logger.info(f"Running from within legacy hostname directory: {chosen_output_directory}")
        else:
            # Scenario 2: Script is run from a parent directory *containing* hostname directories
            # First, check for the existing underscore-formatted directory
            potential_underscore_dir = os.path.join(current_working_dir, legacy_hostname_prefix_candidate)
            if os.path.isdir(potential_underscore_dir):
                chosen_output_directory = potential_underscore_dir
                chosen_hostname_prefix = legacy_hostname_prefix_candidate
                logger.info(f"Found existing underscore-formatted output directory: {chosen_output_directory}")
            else:
                # If no underscore-formatted directory, default to the hyphen-formatted one and create if needed
                potential_hyphen_dir = os.path.join(current_working_dir, router_sanitized_hostname)
                chosen_output_directory = potential_hyphen_dir
                chosen_hostname_prefix = router_sanitized_hostname
                os.makedirs(chosen_output_directory, exist_ok=True)
                logger.info(f"Created/Ensured hyphen-formatted output directory: {chosen_output_directory}")

        # --- Setup Output Files for this script ---
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

        # New: File to store current show inventory output
        current_inventory_output_path = os.path.join(chosen_output_directory,
                                                     f"{chosen_hostname_prefix}_inventory_optics_compare.txt")
        current_inventory_file_handle = open(current_inventory_output_path, 'a', encoding='utf-8')
        logger.info(f"Current 'show inventory' output will be saved to: {current_inventory_output_path}")

        # Session log file for this script (for all script logs, including print statements)
        session_log_path = os.path.join(chosen_output_directory,
                                        f"{chosen_hostname_prefix}_inventory_compare_session_log_{timestamp}.txt")
        session_log_file_handle = open(session_log_path, 'a', encoding='utf-8')
        logger.info(f"Session log for inventory comparison will be saved to: {session_log_path}")

        # Redirect sys.stdout to our Tee object
        sys.stdout = Tee(original_stdout, session_log_file_handle)

        print(f"\n--- Starting Inventory Comparison for {chosen_hostname_prefix} ---")

        # --- Collect Current Show Inventory Output ---
        logger.info("Collecting current 'show inventory' output...")
        current_show_inventory_raw = execute_command_in_shell(
            shell, "show inventory", "show inventory", timeout=120, cli_output_file=current_inventory_file_handle
        )
        logger.info("Finished collecting current 'show inventory'.")

        # --- Locate Previous CLI Output File from all_XR_pre_check_CLI.py ---
        logger.info(
            "Attempting to locate the latest previous CLI output file for comparison (from all_XR_pre_check_CLI.py)...")
        # Note: We pass current_inventory_output_path as None because we are looking for a *different* type of file
        previous_cli_output_path = find_latest_cli_output_file(
            chosen_hostname_prefix, chosen_output_directory, current_file_path=None
            # Do not exclude current file if it's a different type
        )

        if previous_cli_output_path:  # Only proceed with comparison if a previous file is found
            logger.info(f"Found previous CLI output file: {previous_cli_output_path}")
            logger.info("Extracting 'show inventory' section from previous file...")
            previous_show_inventory_raw = extract_command_output(
                previous_cli_output_path, "show inventory"
            )

            if previous_show_inventory_raw:  # Only proceed if previous 'show inventory' output is extracted
                logger.debug(f"Raw current_show_inventory_raw length: {len(current_show_inventory_raw)}")
                logger.debug(f"Raw current_show_inventory_raw (first 500 chars): {current_show_inventory_raw[:500]}")

                logger.debug(f"Raw previous_show_inventory_raw length: {len(previous_show_inventory_raw)}")
                logger.debug(f"Raw previous_show_inventory_raw (first 500 chars): {previous_show_inventory_raw[:500]}")

                # --- Parse Inventory Data ---
                logger.info("Parsing current and previous optics inventory...")
                current_optics_data = parse_inventory_optics(current_show_inventory_raw)
                previous_optics_data = parse_inventory_optics(previous_show_inventory_raw)
                logger.debug(f"Parsed current optics data: {current_optics_data}")
                logger.debug(f"Parsed previous optics data: {previous_optics_data}")

                logger.info("Parsing current and previous LC/FC/RP inventory...")
                current_lcfc_data = parse_inventory_lcfc(current_show_inventory_raw)
                previous_lcfc_data = parse_inventory_lcfc(previous_show_inventory_raw)
                logger.debug(f"Parsed current LC/FC data: {current_lcfc_data}")
                logger.debug(f"Parsed previous LC/FC data: {previous_lcfc_data}")

                # --- Perform Comparisons and Get Reports ---
                optics_report_str, optics_diffs_found = compare_optics_inventory(current_optics_data,
                                                                                 previous_optics_data)
                lcfc_report_str, lcfc_diffs_found = compare_lcfc_inventory(current_lcfc_data, previous_lcfc_data)

                # --- Print Reports to Console and Save to File ---
                print(optics_report_str)
                print(lcfc_report_str)

                if optics_diffs_found or lcfc_diffs_found:
                    print(f"\n--- Inventory Comparison Completed for {chosen_hostname_prefix} with DIFFERENCES ---")
                    print(f"Detailed comparison report saved to: {current_inventory_output_path}")
                else:
                    print(
                        f"\n--- Inventory Comparison Completed for {chosen_hostname_prefix} (No Differences Found) ---")
                    print(f"Full inventory data saved to: {current_inventory_output_path}")

            else:
                logger.warning("Could not extract 'show inventory' from the previous file. Skipping comparison steps.")
                print("\n--- Comparison Skipped (Previous 'show inventory' not found in CLI output file) ---")
        else:  # Handle case where no previous file is found
            logger.warning("No previous CLI output file found for comparison. Skipping comparison steps.")
            print("\n--- Comparison Skipped (No previous data from all_XR_pre_check_CLI.py) ---")

    except (SSHConnectionError, paramiko.SSHException, RouterCommandError) as e:
        logger.critical(f"Critical connection or command execution error: {e}")
        print(f"\n--- Script Failed: Critical Error ---")
        print(f"Error Details: {e}")
    except FileProcessingError as e:
        logger.critical(f"File processing error: {e}")
        print(f"\n--- Script Failed: File Error ---")
        print(f"Error Details: {e}")
    except Exception as e:
        logger.critical(f"An unexpected error occurred during script execution: {e}", exc_info=True)
        print(f"\n--- Script Failed: Unexpected Error ---")
        print(f"Error Details: {e}")

    finally:
        # --- Cleanup SSH Connection ---
        if shell:
            logger.info("Attempting to close SSH shell.")
            try:
                shell.send("exit\n")
                time.sleep(1)
                # Consume any remaining output
                while shell.recv_ready():
                    shell.recv(65535).decode('utf-8', errors='ignore')
            except Exception as e:
                logger.warning(f"Error during shell exit: {e}")
            finally:
                shell.close()
        if client:
            logger.info("Closing SSH client connection.")
            client.close()
        logger.info("SSH connection closed.")

        # --- Close File Handles ---
        if current_inventory_file_handle:
            current_inventory_file_handle.close()
            logger.info(f"Current 'show inventory' file closed: {current_inventory_output_path}")

        # Restore original stdout before closing session log file
        sys.stdout = original_stdout
        if session_log_file_handle:
            session_log_file_handle.flush()
            session_log_file_handle.close()

        logger.info("Script execution finished.")


if __name__ == "__main__":
    main()