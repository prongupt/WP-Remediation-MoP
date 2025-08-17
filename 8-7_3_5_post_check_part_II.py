import paramiko
import time
import getpass
import re
import datetime
import logging
import os
from typing import Optional, List, Tuple, Dict, Any

# --- Constants and Configuration ---
SSH_TIMEOUT_SECONDS = 15
DATAPLANE_MONITOR_TIMEOUT_SECONDS = 1200  # 20 minutes
WAIT_TIME_MINUTES = 20

# Define common prompt patterns for IOS-XR bash and CLI
PROMPT_PATTERNS = [
    r'#\s*$',  # Matches '#' followed by optional whitespace at end of line
    r'\$\s*$'  # Matches '$' for non-root users
]

# Global variables for session log files
session_log_file_console_mirror = None
session_log_file_raw_output = None
router_log_dir = None


# --- Custom Exceptions ---
class SSHConnectionError(Exception):
    """Custom exception for SSH connection failures."""
    pass


class RouterCommandError(Exception):
    """Custom exception for command execution failures on the router."""
    pass


class ScriptExecutionError(Exception):
    """Custom exception for failures during script execution phases."""
    pass


class DataplaneError(Exception):
    """Custom exception for issues detected during dataplane monitoring."""
    pass


# --- Initial Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)


# --- Helper Functions ---
def colorful_countdown_timer(seconds: int):
    """Displays a countdown timer on the console."""
    while seconds:
        mins, secs = divmod(seconds, 60)
        timer = f'{mins:02d}:{secs:02d}'
        print(f'\rWaiting... {timer} remaining', end='', flush=True)
        time.sleep(1)
        seconds -= 1
    print(f'\rWaiting... 00:00 - Time is up!   ')


def read_and_print_realtime(shell_obj: paramiko.Channel, timeout_sec: int = 600, print_realtime: bool = True) -> Tuple[
    str, bool]:
    """
    Reads shell output and prints in real-time until a prompt is found or timeout occurs.
    Returns the full accumulated output and a boolean indicating if a prompt was found.
    """
    full_output_buffer = ""
    start_time = time.time()
    prompt_found = False
    prompt_check_buffer = ""

    while time.time() - start_time < timeout_sec:
        if shell_obj.recv_ready():
            try:
                data = shell_obj.recv(65535).decode('utf-8', errors='ignore')
                if data:
                    # Write raw data to the dedicated raw output file
                    global session_log_file_raw_output
                    if session_log_file_raw_output:
                        session_log_file_raw_output.write(data)
                        session_log_file_raw_output.flush()

                    # Write data to the console mirror file if printing real-time
                    global session_log_file_console_mirror
                    if print_realtime and session_log_file_console_mirror:
                        session_log_file_console_mirror.write(data)
                        session_log_file_console_mirror.flush()

                    if print_realtime:
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
                                if print_realtime and not data.endswith('\n'):
                                    print()
                                return full_output_buffer, prompt_found
            except Exception as e:
                logging.error(f"Error receiving data: {e}")
                break
        else:
            time.sleep(0.1)

    if print_realtime and full_output_buffer and not full_output_buffer.endswith('\n'):
        print()
    return full_output_buffer, prompt_found


def execute_command_in_shell(shell: paramiko.Channel, command: str, command_description: str,
                             timeout: int = 30, print_realtime_output: bool = True) -> bool:
    """
    Sends a command to the shell, prints output in real-time (or not), and waits for prompt.
    Returns True on success (prompt found), False otherwise.
    """
    logging.info(f"Sending '{command_description}'...")

    # Small delay and buffer drain before sending the command
    time.sleep(0.1)
    while shell.recv_ready():
        shell.recv(65535)

    shell.send(command + "\n")
    time.sleep(0.5)

    output, prompt_found = read_and_print_realtime(shell, timeout_sec=timeout, print_realtime=print_realtime_output)
    if not prompt_found:
        logging.warning(f"Prompt not detected after '{command_description}'. Attempting to send newline and re-check.")
        shell.send("\n")
        output_retry, prompt_found_retry = read_and_print_realtime(shell, timeout_sec=5,
                                                                   print_realtime=print_realtime_output)
        prompt_found = prompt_found_retry
        if not prompt_found:
            raise RouterCommandError(
                f"Failed to reach prompt after '{command_description}' re-check. Output: {output + output_retry}")
    return True


def run_script_list_phase(shell: paramiko.Channel, scripts_to_run: List[str], script_arg_option: str) -> List[
    Tuple[str, str]]:
    """
    Executes a list of Python scripts sequentially within an already established shell session.
    Returns a list of tuples: (script_name, full_script_output_string).
    """
    all_scripts_raw_output = []

    for script_name in scripts_to_run:
        group_match = re.search(r'group(\d+)\.py', script_name)
        group_number = group_match.group(1) if group_match else "Unknown"

        script_arg_option_for_log = script_arg_option.strip("'")
        padding_len = 15
        logging.info(
            f"{'=' * padding_len}--- Running Group {group_number} with option {script_arg_option_for_log} ---{'=' * padding_len}")

        command_to_execute = f"python3 {script_name} {script_arg_option}"
        logging.info(f"Sending '{command_to_execute}'...")
        shell.send(command_to_execute + "\n")

        logging.info(f"Waiting for '{script_name}' to finish (up to 10 minutes) and printing output in real-time...")
        script_output, prompt_found = read_and_print_realtime(shell, timeout_sec=600, print_realtime=True)

        all_scripts_raw_output.append((script_name, script_output))

        if not prompt_found:
            logging.warning(f"Prompt not detected within 600 seconds after running '{script_name}'.")
        else:
            logging.info(f"Prompt detected, '{script_name}' execution assumed complete.")
        logging.info(f"{'=' * padding_len}--- Finished execution for: {script_name} ---{'=' * padding_len}")

    return all_scripts_raw_output


def get_hostname(shell: paramiko.Channel) -> str:
    """
    Retrieves the hostname from the router using 'show running-config | i hostname'.
    Returns 'unknown_host' if hostname cannot be determined.
    """
    logging.info("Attempting to retrieve hostname using 'show running-config | i hostname'...")
    shell.send("show running-config | i hostname\n")
    output, prompt_found = read_and_print_realtime(shell, timeout_sec=10, print_realtime=False)
    print()

    for line in output.splitlines():
        match = re.search(r"^\s*hostname\s+(\S+)", line)
        if match:
            hostname = match.group(1)
            hostname = hostname.replace('.', '-')
            logging.info(f"Hostname detected from 'show running-config': {hostname}")
            return hostname

    if prompt_found:
        prompt_match = re.search(r'[:>](\S+)[#$]', output)
        if prompt_match:
            hostname = prompt_match.group(1)
            hostname = hostname.replace('.', '-')
            logging.info(f"Hostname detected from prompt: {hostname}")
            return hostname

    logging.warning("Could not parse hostname. Using 'unknown_host'.")
    return "unknown_host"


def parse_dataplane_output_for_errors(output_text: str) -> bool:
    """
    Parses the output of 'monitor dataplane' and reports non-zero values in LOSS, CORRUPT, or ERROR columns.
    Returns True if no errors, False if errors found.
    """
    errors_found = []
    header_pattern = re.compile(r"LC\s+NP\s+Slice\s+GOOD\s+LOSS\s+CORRUPT\s+ERROR")
    data_pattern = re.compile(r"^\s*(\d+)?\s+(\d+)?\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")

    lines = output_text.splitlines()
    parsing_data = False
    current_lc = None
    current_np = None

    for line in lines:
        if header_pattern.search(line):
            parsing_data = True
            continue

        if parsing_data:
            if re.match(r"^-+$", line.strip()) or "Summary of results:" in line or "DATAPLANE CHECK IS CLEAN." in line:
                parsing_data = False
                continue

            match = data_pattern.match(line)
            if match:
                lc_str, np_str, slice_str, good_str, loss_str, corrupt_str, error_str = match.groups()

                if lc_str is not None and lc_str.strip():
                    current_lc = int(lc_str)
                if np_str is not None and np_str.strip():
                    current_np = int(np_str)

                lc = current_lc if current_lc is not None else "N/A"
                npu = current_np if current_np is not None else "N/A"

                slice_val = int(slice_str)
                loss = int(loss_str)
                corrupt = int(corrupt_str)
                error = int(error_str)

                if loss > 0 or corrupt > 0 or error > 0:
                    errors_found.append({
                        "LC": lc, "NPU": npu, "Slice": slice_val,
                        "LOSS": loss, "CORRUPT": corrupt, "ERROR": error
                    })

    if errors_found:
        logging.error("!!! DATAPLANE ERRORS DETECTED !!!")
        for err in errors_found:
            logging.error(f"LC: {err['LC']}, NPU: {err['NPU']}, Slice: {err['Slice']}, "
                          f"LOSS: {err['LOSS']}, CORRUPT: {err['CORRUPT']}, ERROR: {err['ERROR']}")
        logging.error("!!! Please investigate the reported non-zero values. !!!")
        return False
    else:
        logging.info("Dataplane output check: No LOSS, CORRUPT, or ERROR detected.")
        return True


def poll_dataplane_monitoring_735(shell: paramiko.Channel, max_poll_duration_sec: int) -> bool:
    """
    For IOS-XR 7.3.5. Monitors 'monitor dataplane-health' command.
    """
    logging.info(f"Running 'monitor dataplane-health' command...")
    shell.send("monitor dataplane-health\n")
    time.sleep(2)

    output, prompt_found = read_and_print_realtime(shell, timeout_sec=max_poll_duration_sec, print_realtime=True)

    if not prompt_found:
        raise DataplaneError(
            f"Dataplane monitoring did not complete within {max_poll_duration_sec // 60} minutes or prompt was not detected")

    if "DATAPATH CHECK IS CLEAN." in output or "Summary of results:" in output:
        logging.info("Dataplane monitoring completed successfully")
        return parse_dataplane_output_for_errors(output)
    else:
        raise DataplaneError("Dataplane monitoring completed but no valid results found in output")


def parse_script_output_for_errors(script_name: str, script_output: str) -> List[Dict[str, str]]:
    """
    Parses the output of a monitor_8800_system script for faulty link details.
    Returns a list of dictionaries, each representing a faulty link.
    """
    errors_found_details = []

    faulty_link_pattern = re.compile(
        r"Link\s+(.*?)\s+---\s+(.*?)\s+between\s+(.*?)\s+and\s+(.*?)\s+is faulty\s+-\s+codewords\s+(.*?),\s+BER\s+([\d\.e-]+)\s+FLR\s+([\d\.e-]+)\s+RX Link Down Count\s+(\d+)"
    )

    lines = script_output.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        match = faulty_link_pattern.search(line)
        if match:
            link_conn_part1 = match.group(1).strip()
            link_conn_part2 = match.group(2).strip()
            loc1 = match.group(3).strip()
            loc2 = match.group(4).strip()

            link_connection_full = f"{link_conn_part1} --- {link_conn_part2} between {loc1} and {loc2}"

            current_link_status = {
                "Link Connection": link_connection_full,
                "Codewords": match.group(5).strip(),
                "FLR": match.group(7).strip(),
                "BER": match.group(6).strip(),
                "Link_flap": match.group(8).strip()
            }

            errors_found_details.append(current_link_status)
        i += 1

    return errors_found_details


def get_group_number_from_script_name(script_name: str) -> str:
    """Extracts the group number from the script name."""
    match = re.search(r'group(\d+)\.py', script_name)
    return match.group(1) if match else "N/A"


def format_and_print_error_report(script_name: str, group_number: str, error_details: List[Dict[str, str]]):
    """
    Formats and prints the error report for a given script.
    """
    logging.info(f"--- Error Report for {script_name} ---")
    logging.info("Reference Thresholds: BER < 1e-08, FLR < 1e-21")

    if not error_details:
        logging.info("No errors detected for this group.")
    else:
        for detail in error_details:
            logging.error(f"Faulty Link: {detail['Link Connection']}")
            logging.error(f"Group: {group_number}, Codewords: {detail['Codewords']}, "
                          f"FLR: {detail['FLR']}, BER: {detail['BER']}, Link_flap: {detail['Link_flap']}")
        logging.error(f"Errors detected for this group. Total {len(error_details)} degraded links found.")


def run_dataplane_monitor_phase(router_ip: str, username: str, password: str, monitor_description: str,
                                ssh_timeout: int, dataplane_timeout: int) -> bool:
    """
    Connects to the router, runs a dataplane monitor, and returns success/failure.
    """
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    shell = None
    try:
        logging.info(f"Connecting to {router_ip} for {monitor_description} dataplane monitor...")
        client.connect(router_ip, port=22, username=username, password=password, timeout=ssh_timeout,
                       look_for_keys=False)
        logging.info(f"Successfully connected for {monitor_description} dataplane monitor.")
        shell = client.invoke_shell()
        time.sleep(1)
        logging.info(f"--- Initial Shell Output ({monitor_description} Dataplane Monitor) ---")
        read_and_print_realtime(shell, timeout_sec=2)
        logging.info(f"--- End Initial Shell Output ---")

        # Set terminal length and width to prevent pagination
        if not execute_command_in_shell(shell, "terminal length 0", "set terminal length to 0", timeout=5,
                                        print_realtime_output=False):
            raise RouterCommandError("Failed to set terminal length 0.")
        if not execute_command_in_shell(shell, "terminal width 511", "set terminal width to 511", timeout=5,
                                        print_realtime_output=False):
            raise RouterCommandError("Failed to set terminal width 511.")

        logging.info(f"Running 'monitor dataplane-health' for IOS-XR 7.3.5.")
        dataplane_check_clean = poll_dataplane_monitoring_735(shell, dataplane_timeout)

        if dataplane_check_clean:
            logging.info(f"{monitor_description} Dataplane monitoring completed and reported no errors.")
            return True
        else:
            logging.error(f"{monitor_description} Dataplane monitoring completed, but errors were reported.")
            # Do not raise DataplaneError here, let the caller decide based on return value
            return False

    except paramiko.AuthenticationException as e:
        raise SSHConnectionError(f"Authentication failed for {monitor_description} monitor: {e}")
    except paramiko.SSHException as e:
        raise SSHConnectionError(f"SSH error during {monitor_description} monitor: {e}")
    except DataplaneError:
        # Re-raise DataplaneError if it originated from poll_dataplane_monitoring_735
        raise
    except Exception as e:
        raise SSHConnectionError(f"An unexpected error occurred during {monitor_description} dataplane monitor: {e}")
    finally:
        if shell:
            logging.info(f"Exiting CLI session after {monitor_description} dataplane monitor.")
            shell.send("exit\n")
            time.sleep(1)
            try:
                while shell.recv_ready():
                    shell.recv(65535).decode('utf-8', errors='ignore')
            except Exception as e:
                logging.warning(f"Error clearing shell buffer on exit: {e}")
            shell.close()
        if client:
            client.close()
        logging.info(f"SSH connection for {monitor_description} monitor closed.")


def execute_script_phase(router_ip: str, username: str, password: str, scripts_to_run: List[str],
                         script_arg_option: str, ssh_timeout: int) -> bool:
    """
    Handles the SSH connection, initial commands, and execution of scripts for a single phase.
    Returns True if scripts ran without detected errors, False otherwise.
    """
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    shell = None
    try:
        logging.info(f"Attempting to connect to {router_ip} for phase with option '{script_arg_option}'...")
        client.connect(router_ip, port=22, username=username, password=password, timeout=ssh_timeout,
                       look_for_keys=False)
        logging.info(f"Successfully connected to {router_ip}.")

        shell = client.invoke_shell()
        time.sleep(1)
        logging.info("--- Initial Shell Output ---")
        read_and_print_realtime(shell, timeout_sec=2)
        logging.info("--- End Initial Shell Output ---")

        # Set terminal length and width to prevent pagination
        if not execute_command_in_shell(shell, "terminal length 0", "set terminal length to 0", timeout=5,
                                        print_realtime_output=False):
            raise RouterCommandError("Failed to set terminal length 0.")
        if not execute_command_in_shell(shell, "terminal width 511", "set terminal width to 511", timeout=5,
                                        print_realtime_output=False):
            raise RouterCommandError("Failed to set terminal width 511.")

        if not execute_command_in_shell(shell, "attach location 0/RP0/CPU0", "attach location 0/RP0/CPU0", timeout=30,
                                        print_realtime_output=False):
            raise RouterCommandError("Failed to establish bash prompt on router.")

        if not execute_command_in_shell(shell, "cd /misc/disk1/", "cd to /misc/disk1/", timeout=10,
                                        print_realtime_output=False):
            raise RouterCommandError("Failed to change directory on router.")

        scripts_outputs = run_script_list_phase(shell, scripts_to_run, script_arg_option)

        if script_arg_option == "'--dummy' no":
            logging.info(f"{'=' * 70}{'=' * 70}")
            logging.info("### Analyzing 'dummy no' script outputs for errors ###")
            errors_found_in_dummy_no = False
            for s_name, s_output in scripts_outputs:
                group_num = get_group_number_from_script_name(s_name)
                detailed_errors = parse_script_output_for_errors(s_name, s_output)
                format_and_print_error_report(s_name, group_num, detailed_errors)
                if detailed_errors:
                    errors_found_in_dummy_no = True

            if errors_found_in_dummy_no:
                raise ScriptExecutionError("Errors detected in 'dummy no' script outputs.")
        return True

    except paramiko.AuthenticationException as e:
        raise SSHConnectionError(f"Authentication failed for script phase '{script_arg_option}': {e}")
    except paramiko.SSHException as e:
        raise SSHConnectionError(f"SSH error during script phase '{script_arg_option}': {e}")
    except RouterCommandError as e:
        raise RouterCommandError(f"Router command error during script phase '{script_arg_option}': {e}")
    except ScriptExecutionError:
        # Re-raise if it originated from within this function (e.g., errors_found_in_dummy_no)
        raise
    except Exception as e:
        raise ScriptExecutionError(f"An unexpected error occurred during script phase '{script_arg_option}': {e}")
    finally:
        if shell:
            logging.info("Exiting bash prompt...")
            shell.send("exit\n")
            time.sleep(1)
            try:
                while shell.recv_ready():
                    shell.recv(65535).decode('utf-8', errors='ignore')
            except Exception as e:
                logging.warning(f"Error clearing shell buffer on exit: {e}")
            shell.close()
        if client:
            client.close()
            logging.info("SSH connection closed.")


def print_final_summary(results: Dict[str, str]):
    """Prints a summary of all executed steps in a table format."""
    logging.info(f"\n--- Final Script Summary ---")

    step_name_map = {
        "Step a": "Dummy Yes",
        "Step b": "Monitor Dataplane",
        "Step c": f"Wait time {WAIT_TIME_MINUTES} minutes",
        "Step d": "Dummy no",
        "Step e": "Monitor Dataplane",
        "Step f": f"Wait time {WAIT_TIME_MINUTES} minutes",
        "Step g": "Dummy no",
    }

    headers = ["Section Name", "Status"]
    data_rows = []

    # Ensure steps are processed in order a, b, c, etc.
    sorted_step_keys = sorted(results.keys())

    max_section_len = len(headers[0])
    max_status_len = len(headers[1])

    for step_key in sorted_step_keys:
        section_name = step_name_map.get(step_key, step_key)
        status_message = results[step_key]

        # Extract just "Success" or "Failed" or the full error message
        if "Success" in status_message:
            status = "Success"
        elif "Failed" in status_message:
            # For failures, show the reason if available, otherwise just "Failed"
            status_parts = status_message.split("Failed - ", 1)
            status = status_parts[1] if len(status_parts) > 1 else "Failed"
        else:
            status = status_message  # Fallback for unexpected statuses

        data_rows.append([section_name, status])

        max_section_len = max(max_section_len, len(section_name))
        max_status_len = max(max_status_len, len(status))

    # Add padding for aesthetic
    max_section_len += 2
    max_status_len += 2

    # Print header
    header_line = f"+{'-' * max_section_len}+{'-' * max_status_len}+"
    logging.info(header_line)
    logging.info(f"| {headers[0]:<{max_section_len}} | {headers[1]:<{max_status_len}} |")
    logging.info(header_line)

    # Print data rows
    for row in data_rows:
        logging.info(f"| {row[0]:<{max_section_len}} | {row[1]:<{max_status_len}} |")
    logging.info(header_line)


# --- Main execution block ---
if __name__ == "__main__":
    logging.info(f"--- IOS-XR Router Automation Script ---")

    # Router details (prompted)
    ROUTER_IP = input(f"Enter Router IP_add / Host: ")
    SSH_USERNAME = input(f"Enter SSH Username: ")
    SSH_PASSWORD = getpass.getpass(f"Enter SSH Password: ")

    # Get Hostname for Router Directory and Log Files
    hostname_for_log = "unknown_host"
    initial_client = None
    initial_shell = None
    try:
        logging.info(f"Attempting initial connection to {ROUTER_IP} to retrieve hostname for log directory...")
        initial_client = paramiko.SSHClient()
        initial_client.load_system_host_keys()
        initial_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        initial_client.connect(ROUTER_IP, port=22, username=SSH_USERNAME, password=SSH_PASSWORD,
                               timeout=SSH_TIMEOUT_SECONDS, look_for_keys=False)
        initial_shell = initial_client.invoke_shell()
        time.sleep(1)
        execute_command_in_shell(initial_shell, "terminal length 0", "set terminal length to 0", timeout=5,
                                 print_realtime_output=False)
        execute_command_in_shell(initial_shell, "terminal width 511", "set terminal width to 511", timeout=5,
                                 print_realtime_output=False)
        hostname_for_log = get_hostname(initial_shell)
        logging.info(f"Retrieved hostname: {hostname_for_log}")
    except Exception as e:
        logging.error(f"Failed to retrieve hostname during initial connection: {e}. Using 'unknown_host'.")
    finally:
        if initial_shell:
            try:
                while initial_shell.recv_ready():
                    initial_shell.recv(65535).decode('utf-8', errors='ignore')
                initial_shell.send("exit\n")
                time.sleep(1)
            except Exception as e:
                logging.warning(f"Error during initial shell exit: {e}")
            initial_shell.close()
        if initial_client:
            initial_client.close()
        logging.info("Initial SSH connection for hostname retrieval closed.")

    # Determine and Create Router Directory
    router_log_dir = hostname_for_log
    try:
        os.makedirs(router_log_dir, exist_ok=True)
        logging.info(f"Ensured router log directory exists: {os.path.abspath(router_log_dir)}")
    except OSError as e:
        logging.critical(f"Failed to create or access router log directory {router_log_dir}: {e}. Exiting.")
        exit(1)

    # Reconfigure Application Logging to the new directory
    timestamp_for_app_log = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    # MODIFIED: Application Log File Name
    app_log_filename = os.path.join(router_log_dir, f"{hostname_for_log}_automation_7_3_5_log_{timestamp_for_app_log}.log")

    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(app_log_filename),
            logging.StreamHandler()
        ]
    )
    logging.info(f"Application logs will be written to: {app_log_filename}")

    # Open Session Log Files in the new directory
    timestamp_for_session_logs = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    # MODIFIED: Console Mirror Session Log File Name
    console_mirror_filename = os.path.join(router_log_dir,
                                           f"{hostname_for_log}_session_7_3_5_log_{timestamp_for_session_logs}.txt")
    # MODIFIED: Raw SSH Output Log File Name
    raw_output_filename = os.path.join(router_log_dir,
                                       f"{hostname_for_log}_outputs7_3_5phase_II_{timestamp_for_session_logs}.txt")

    try:
        session_log_file_console_mirror = open(console_mirror_filename, 'w', encoding='utf-8')
        logging.info(f"Console mirror session output will be logged to: {console_mirror_filename}")
    except IOError as e:
        logging.error(f"Could not open console mirror session log file: {e}")
        session_log_file_console_mirror = None

    try:
        session_log_file_raw_output = open(raw_output_filename, 'w', encoding='utf-8')
        logging.info(f"Raw SSH output will be logged to: {raw_output_filename}")
    except IOError as e:
        logging.error(f"Could not open raw SSH output log file: {e}")
        session_log_file_raw_output = None

    # List of scripts to run (hardcoded)
    scripts_to_run = [
        "monitor_8800_system_v2_3_msft_bash_group0.py",
        "monitor_8800_system_v2_3_msft_bash_group1.py",
        "monitor_8800_system_v2_3_msft_bash_group2.py",
        "monitor_8800_system_v2_3_msft_bash_group3.py",
    ]

    results_summary: Dict[str, str] = {}
    script_aborted = False

    try:
        # a) Dummy yes
        logging.info(f"\n{'#' * 70}")
        logging.info("### Step a: Running scripts with '--dummy' yes ###")
        try:
            execute_script_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, scripts_to_run, "'--dummy' yes",
                                 SSH_TIMEOUT_SECONDS)
            results_summary["Step a"] = "Dummy Yes: Success"
        except (SSHConnectionError, RouterCommandError, ScriptExecutionError) as e:
            results_summary["Step a"] = f"Dummy Yes: Failed - {e}"
            logging.critical(f"Dummy yes phase failed: {e}")
            script_aborted = True
            raise ScriptExecutionError(f"Script aborted during Dummy Yes phase: {e}")

        # b) Monitor dataplane (First)
        logging.info(f"\n{'#' * 70}")
        logging.info("### Step b: First Dataplane Monitor ###")
        try:
            dataplane_success = run_dataplane_monitor_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, "FIRST",
                                                            SSH_TIMEOUT_SECONDS,
                                                            DATAPLANE_MONITOR_TIMEOUT_SECONDS)
            results_summary[
                "Step b"] = "Monitor Dataplane: Success" if dataplane_success else "Monitor Dataplane: Failed - Errors Detected"
        except DataplaneError as e:
            results_summary["Step b"] = f"Monitor Dataplane: Failed - {e}"
            logging.critical(f"First Dataplane Monitor failed: {e}")
            script_aborted = True
            raise ScriptExecutionError(f"Script aborted during First Dataplane Monitor: {e}")
        except (SSHConnectionError, RouterCommandError) as e:
            results_summary["Step b"] = f"Monitor Dataplane: Failed - Connection/Command Error: {e}"
            logging.critical(f"First Dataplane Monitor failed: {e}")
            script_aborted = True
            raise ScriptExecutionError(f"Script aborted during First Dataplane Monitor: {e}")

        # c) Wait time of 20 minutes
        logging.info(f"\n{'#' * 70}")
        logging.info(f"### Step c: {WAIT_TIME_MINUTES}-minute Wait Time ###")
        try:
            colorful_countdown_timer(WAIT_TIME_MINUTES * 60)
            results_summary["Step c"] = f"Wait time {WAIT_TIME_MINUTES} minutes: Success"
        except Exception as e:
            results_summary["Step c"] = f"Wait time {WAIT_TIME_MINUTES} minutes: Failed - {e}"
            logging.critical(f"{WAIT_TIME_MINUTES}-minute wait failed: {e}")
            script_aborted = True
            raise ScriptExecutionError(f"Script aborted during Wait Time: {e}")

        # d) Dummy no (First set of actual checks)
        logging.info(f"\n{'#' * 70}")
        logging.info("### Step d: Running scripts with '--dummy' no ###")
        try:
            execute_script_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, scripts_to_run, "'--dummy' no",
                                 SSH_TIMEOUT_SECONDS)
            results_summary["Step d"] = "Dummy no: Success"
        except ScriptExecutionError as e:
            results_summary["Step d"] = f"Dummy no: Failed - {e}"
            logging.critical(f"Dummy no phase failed: {e}")
            script_aborted = True
            raise ScriptExecutionError(f"Script aborted during Dummy No phase (link errors): {e}")
        except (SSHConnectionError, RouterCommandError) as e:
            results_summary["Step d"] = f"Dummy no: Failed - Connection/Command Error: {e}"
            logging.critical(f"Dummy no phase failed: {e}")
            script_aborted = True
            raise ScriptExecutionError(f"Script aborted during Dummy No phase (connection error): {e}")

        # e) Monitor dataplane (Second)
        logging.info(f"\n{'#' * 70}")
        logging.info("### Step e: Second Dataplane Monitor ###")
        try:
            dataplane_success = run_dataplane_monitor_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, "SECOND",
                                                            SSH_TIMEOUT_SECONDS,
                                                            DATAPLANE_MONITOR_TIMEOUT_SECONDS)
            results_summary[
                "Step e"] = "Monitor Dataplane: Success" if dataplane_success else "Monitor Dataplane: Failed - Errors Detected"
        except DataplaneError as e:
            results_summary["Step e"] = f"Monitor Dataplane: Failed - {e}"
            logging.critical(f"Second Dataplane Monitor failed: {e}")
            script_aborted = True
            raise ScriptExecutionError(f"Script aborted during Second Dataplane Monitor: {e}")
        except (SSHConnectionError, RouterCommandError) as e:
            results_summary["Step e"] = f"Monitor Dataplane: Failed - Connection/Command Error: {e}"
            logging.critical(f"Second Dataplane Monitor failed: {e}")
            script_aborted = True
            raise ScriptExecutionError(f"Script aborted during Second Dataplane Monitor: {e}")

        # f) Wait time of 20 minutes
        logging.info(f"\n{'#' * 70}")
        logging.info(f"### Step f: Second {WAIT_TIME_MINUTES}-minute Wait Time ###")
        try:
            colorful_countdown_timer(WAIT_TIME_MINUTES * 60)
            results_summary["Step f"] = f"Wait time {WAIT_TIME_MINUTES} minutes: Success"
        except Exception as e:
            results_summary["Step f"] = f"Wait time {WAIT_TIME_MINUTES} minutes: Failed - {e}"
            logging.critical(f"Second {WAIT_TIME_MINUTES}-minute wait failed: {e}")
            script_aborted = True
            raise ScriptExecutionError(f"Script aborted during Second Wait Time: {e}")

        # g) Final Dummy no (Final set of actual checks)
        logging.info(f"\n{'#' * 70}")
        logging.info("### Step g: Final Dummy No ###")
        try:
            execute_script_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, scripts_to_run, "'--dummy' no",
                                 SSH_TIMEOUT_SECONDS)
            results_summary["Step g"] = "Dummy no: Success"
        except ScriptExecutionError as e:
            results_summary["Step g"] = f"Dummy no: Failed - {e}"
            logging.critical(f"Final dummy no phase failed: {e}")
            script_aborted = True
            raise ScriptExecutionError(f"Script aborted during Final Dummy No phase (link errors): {e}")
        except (SSHConnectionError, RouterCommandError) as e:
            results_summary["Step g"] = f"Dummy no: Failed - Connection/Command Error: {e}"
            logging.critical(f"Final dummy no phase failed: {e}")
            script_aborted = True
            raise ScriptExecutionError(f"Script aborted during Final Dummy No phase (connection error): {e}")

    except ScriptExecutionError as e:  # Catch the custom exception for controlled abortion
        logging.critical(f"Script execution aborted: {e}")
        script_aborted = True
    except Exception as e:
        logging.critical(f"An unhandled critical error occurred during script execution: {e}", exc_info=True)
        script_aborted = True
    finally:
        pass

    # Print Final Summary
    logging.info(f"\n{'#' * 70}")
    logging.info("### Final Summary ###")
    if script_aborted:
        logging.critical("Script execution was aborted due to a critical error. See summary below.")
    else:
        logging.info("All planned steps completed successfully.")

    print_final_summary(results_summary)  # Pass the results_summary dictionary
    logging.info(f"--- Script Execution Finished ---")

    # Close the session log files at the very end
    if session_log_file_console_mirror:
        session_log_file_console_mirror.close()
        logging.info(f"Console mirror session log file closed.")
    if session_log_file_raw_output:
        session_log_file_raw_output.close()
        logging.info(f"Raw SSH output log file closed.")