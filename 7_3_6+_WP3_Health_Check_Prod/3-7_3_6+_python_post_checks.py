import paramiko
import time
import getpass
import re
import threading
from prettytable import PrettyTable
from prettytable.prettytable import HEADER, ALL
import datetime
import logging
import platform
import os
from typing import Optional, List, Tuple, Dict, Any

# --- Constants and Configuration ---
SSH_TIMEOUT_SECONDS = 15
DATAPLANE_MONITOR_TIMEOUT_SECONDS = 1200 # 20 minutes
SHOW_TECH_MONITOR_TIMEOUT_SECONDS = 3600 # 60 minutes
COUNTDOWN_DURATION_MINUTES = 15

# Define common prompt patterns for IOS-XR bash and CLI
PROMPT_PATTERNS = [
r'#\s*$', # Matches '#' followed by optional whitespace at end of line
r'\$\s*$' # Matches '$' for non-root users
]

# Global variables to store show tech timing information
SHOW_TECH_START_TIMESTAMP_FROM_LOG: Optional[str] = None
SHOW_TECH_END_TIMESTAMP_FROM_LOG: Optional[str] = None

# Global variables for session log files
session_log_file_console_mirror = None
session_log_file_raw_output = None

# Global variable for the determined router log directory
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

class ShowTechError(Exception):
    """Custom exception for failures during show tech collection."""
    pass

class AsicErrorShowError(Exception):
    """Custom exception for failures during asic_errors_show command."""
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
    print(f'\rWaiting... 00:00 - Time is up! ')

def read_and_print_realtime(shell_obj: paramiko.Channel, timeout_sec: int = 600, print_realtime: bool = True) -> Tuple[str, bool]:
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

def run_script_list_phase(shell: paramiko.Channel, scripts_to_run: List[str], script_arg_option: str) -> List[Tuple[str, str]]:
    """
    Executes a list of Python scripts sequentially within an already established shell session.
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
            logging.warning(f"The remote script might still be running, or the prompt format is unexpected.")
        else:
            logging.info(f"Prompt detected, '{script_name}' execution assumed complete.")
            logging.info(f"{'=' * padding_len}--- Finished execution for: {script_name} ---{'=' * padding_len}")

    return all_scripts_raw_output

def parse_version_string(version_str: str) -> Tuple[int, ...]:
    """Parses a version string (e.g., "7.3.5") into a tuple of integers (e.g., (7, 3, 5))."""
    return tuple(map(int, version_str.split('.')))

def get_ios_xr_version(shell: paramiko.Channel) -> str:
    """
    Retrieves the IOS-XR version from the router.
    """
    logging.info("Attempting to retrieve IOS-XR version...")
    shell.send("show version\n")
    output, prompt_found = read_and_print_realtime(shell, timeout_sec=30, print_realtime=False)
    print(f"{output}", end='')
    print()
    if not prompt_found:
        raise RouterCommandError("Prompt not found after 'show version'. Cannot determine IOS-XR version.")

    match = re.search(r"Cisco IOS XR Software, Version (\d+\.\d+\.\d+)", output)
    if match:
        version = match.group(1)
        logging.info(f"IOS-XR Version detected: {version}")
        return version
    else:
        raise RouterCommandError("Could not parse IOS-XR version from 'show version' output.")

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

    logging.warning("Could not parse hostname from 'show running-config | i hostname' output or from prompt. Using 'unknown_host'.")
    return "unknown_host"

def parse_dataplane_output_for_errors(output_text: str) -> bool:
    """
    Parses the output of 'monitor dataplane' or 'show dataplane status'
    and reports non-zero values in LOSS, CORRUPT, or ERROR columns.
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
        table = PrettyTable()
        table.field_names = ["LC", "NPU", "Slice", "LOSS", "CORRUPT", "ERROR"]
        for err in errors_found:
            table.add_row([err["LC"], err["NPU"], err["Slice"], err["LOSS"], err["CORRUPT"], err["ERROR"]])
        logging.error(f"\n{table}")
        logging.error("!!! Please investigate the reported non-zero values. !!!")
        return False
    else:
        logging.info("Dataplane output check: No LOSS, CORRUPT, or ERROR detected.")
        return True

def get_router_timestamp(shell: paramiko.Channel) -> datetime.datetime:
    """
    Gets the current timestamp from the router using 'show clock'.
    Returns a datetime object.
    """
    logging.info("Getting router's current timestamp using 'show clock'...")
    shell.send("show clock\n")
    output, prompt_found = read_and_print_realtime(shell, timeout_sec=10, print_realtime=False)
    print()
    if not prompt_found:
        raise RouterCommandError("Prompt not found after 'show clock'. Cannot get router timestamp.")

    match = re.search(r"(\d{2}:\d{2}:\d{2}\.\d{3})\s+(\w+)\s+\w+\s+(\w{3})\s+(\d+)\s+(\d{4})", output)
    if match:
        time_str, tz_str, month_str, day_str, year_str = match.groups()
        timestamp_full_str = f"{month_str} {day_str} {year_str} {time_str}"
        try:
            dt_obj = datetime.datetime.strptime(timestamp_full_str, "%b %d %Y %H:%M:%S.%f")
            logging.info(f"Router timestamp detected: {dt_obj}")
            return dt_obj
        except ValueError as e:
            raise RouterCommandError(f"Failed to parse router timestamp '{timestamp_full_str}': {e}")
    else:
        raise RouterCommandError(f"Could not parse 'show clock' output for timestamp: {output}")

def poll_dataplane_monitoring_736(shell: paramiko.Channel, max_poll_duration_sec: int) -> bool:
    """
    For IOS-XR 7.3.6 and higher. Polls 'show logging | i "%PLATFORM-DPH_MONITOR-6"' every 3 minutes
    to detect dataplane monitoring completion.
    """
    logging.info(f"Running 'monitor dataplane' command (IOS-XR 7.3.6+)...")
    shell.send("monitor dataplane\n")
    time.sleep(2)

    logging.info("Waiting for initial 'monitor dataplane' output to complete and prompt to return...")
    initial_dataplane_output, prompt_found_after_dataplane = read_and_print_realtime(shell, timeout_sec=30, print_realtime=True)
    if not prompt_found_after_dataplane:
        logging.warning("Prompt not detected after initial 'monitor dataplane' output. Attempting to send newline and re-check.")
        shell.send("\n")
        retry_output, prompt_found_after_dataplane = read_and_print_realtime(shell, timeout_sec=5, print_realtime=True)
        initial_dataplane_output += retry_output
        if not prompt_found_after_dataplane:
            raise RouterCommandError(f"Failed to reach prompt after 'monitor dataplane' command. Output: {initial_dataplane_output}")
    logging.info("Prompt returned after 'monitor dataplane' initiation.")

    router_monitor_start_time = get_router_timestamp(shell)
    logging.info(f"Router's recorded start time for monitor dataplane: {router_monitor_start_time}")

    completed_pattern = re.compile(
        r"RP/\d/\w+/\w+:(\w{3})\s+(\d+)\s+(\d{2}:\d{2}:\d{2}\.\d{3})\s+(\w{3}):.*%PLATFORM-DPH_MONITOR-6-COMPLETED : Dataplane health monitoring completed\.")

    poll_interval_sec = 180  # 3 minutes
    poll_start_time = time.time()
    current_year = datetime.datetime.now().year

    logging.info(
        f"Polling 'show logging | i %PLATFORM-DPH_MONITOR-6' every {poll_interval_sec // 60} minutes for up to {max_poll_duration_sec // 60} minutes to detect dataplane monitoring completion...")

    monitoring_completed_successfully = False

    while time.time() - poll_start_time < max_poll_duration_sec:
        shell.send('show logging | i "%PLATFORM-DPH_MONITOR-6"\n')
        output, prompt_found = read_and_print_realtime(shell, timeout_sec=60, print_realtime=False)
        if not prompt_found:
            logging.warning(
                "Prompt not detected after 'show logging | i...' command. This might indicate an issue or a very long output.")

        latest_relevant_completed_time = None

        for line in output.splitlines():
            match = completed_pattern.search(line)
            if match:
                month_str, day_str, time_str, tz_str_log = match.groups()
                try:
                    log_timestamp_full_str = f"{month_str} {day_str} {current_year} {time_str}"
                    parsed_log_dt = datetime.datetime.strptime(log_timestamp_full_str, "%b %d %Y %H:%M:%S.%f")

                    if parsed_log_dt > router_monitor_start_time:
                        if latest_relevant_completed_time is None or parsed_log_dt > latest_relevant_completed_time:
                            latest_relevant_completed_time = parsed_log_dt
                            logging.info(f"Found relevant completion log: {line}")

                except ValueError as e:
                    logging.warning(f"Could not parse timestamp from log line: '{line}'. Error: {e}")
                    continue

        if latest_relevant_completed_time:
            monitoring_completed_successfully = True
            logging.info(
                f"Detected latest relevant 'COMPLETED' log entry at {latest_relevant_completed_time}. Proceeding to 'show dataplane status'.")
            break

        logging.info(
            f"Dataplane monitoring not completed yet. Waiting {poll_interval_sec // 60} minutes before next poll...")
        colorful_countdown_timer(poll_interval_sec)

    if monitoring_completed_successfully:
        logging.info("Running 'show dataplane status' command after completion detected...")
        shell.send("show dataplane status\n")
        status_output, prompt_found = read_and_print_realtime(shell, timeout_sec=60, print_realtime=False)

        print(f"{status_output}", end='')
        print()

        if prompt_found:
            return parse_dataplane_output_for_errors(status_output)
        else:
            logging.warning("Prompt not detected after 'show dataplane status' command.")
            return parse_dataplane_output_for_errors(status_output)
    else:
        raise DataplaneError(
            f"Dataplane monitoring did not complete within {max_poll_duration_sec // 60} minutes polling period, or no relevant completion log was found.")

def get_group_number_from_script_name(script_name: str) -> str:
    """Extracts the group number from the script name."""
    match = re.search(r'group(\d+)\.py', script_name)
    return match.group(1) if match else "N/A"

def parse_script_output_for_errors(script_name: str, script_output: str) -> List[Dict[str, str]]:
    """
    Parses the output of a monitor_8800_system script for faulty link details.
    Returns a list of dictionaries, each representing a faulty link.
    """
    errors_found_details = []

    faulty_link_pattern = re.compile(
        r"Link\s+(.*?)\s+---\s+(.*?)\s+between\s+(.*?)\s+and\s+(.*?)\s+is faulty\s+-\s+codewords\s+(.*?),\s+BER\s+([\d\.e-]+)\s+FLR\s+([\d\.e-]+)\s+RX Link Down Count\s+(\d+)"
    )

    status_line_pattern = re.compile(r"^(Codewords|BER|FLR|RX Link Down Count):\s+(OK|BAD)$")

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

            codewords_val = match.group(5).strip()
            ber_val = match.group(6).strip()
            flr_val = match.group(7).strip()
            rx_link_down_count_val = match.group(8).strip()

            current_link_status = {
                "Link Connection": link_connection_full,
                "Codewords": codewords_val,
                "FLR": flr_val,
                "BER": ber_val,
                "Link_flap": rx_link_down_count_val,
                "Codewords_Status": "N/A",
                "BER_Status": "N/A",
                "FLR_Status": "N/A",
                "Link_flap_Status": "N/A"
            }

            j = i + 1
            while j < len(lines) and not faulty_link_pattern.search(lines[j]) and not lines[j].strip().startswith("Total "):
                status_match = status_line_pattern.search(lines[j])
                if status_match:
                    metric = status_match.group(1)
                    status = status_match.group(2)
                    if metric == "Codewords":
                        current_link_status["Codewords_Status"] = status
                    elif metric == "BER":
                        current_link_status["BER_Status"] = status
                    elif metric == "FLR":
                        current_link_status["FLR_Status"] = status
                    elif metric == "RX Link Down Count":
                        current_link_status["Link_flap_Status"] = status
                j += 1

            errors_found_details.append(current_link_status)
            i = j - 1
        i += 1

    return errors_found_details

def format_and_print_error_report(script_name: str, group_number: str, error_details: List[Dict[str, str]]):
    """
    Formats and prints the error report for a given script.
    """
    logging.info(f"--- Error Report for {script_name} ---")
    logging.info("Reference Thresholds: BER < 1e-08, FLR < 1e-21")

    table = PrettyTable()
    table.field_names = ["Link Connection", "Group_number", "Codewords", "FLR", "BER", "Link_flap"]

    table.align["Link Connection"] = "l"
    table.align["Group_number"] = "c"
    table.align["Codewords"] = "l"
    table.align["FLR"] = "l"
    table.align["BER"] = "l"
    table.align["Link_flap"] = "l"

    if not error_details:
        table.add_row(["", group_number, "", "", "", ""])
        table_string = table.get_string(hrules=HEADER, vrules=ALL, header=True, border=True)
        print(table_string)
        logging.info("No errors detected for this group.")
        first_line_of_table = table_string.splitlines()[0]
        border_length = len(first_line_of_table)
        print(f"+{'-'*(border_length-2)}+")
    else:
        for detail in error_details:
            flr_display = f"{detail['FLR']} ({detail['FLR_Status']})" if detail['FLR_Status'] != "N/A" else detail['FLR']
            ber_display = f"{detail['BER']} ({detail['BER_Status']})" if detail['BER_Status'] != "N/A" else detail['BER']
            link_flap_display = f"{detail['Link_flap']} ({detail['Link_flap_Status']})" if detail['Link_flap_Status'] != "N/A" else detail['Link_flap']

            table.add_row([
                detail["Link Connection"],
                group_number,
                detail["Codewords"],
                flr_display,
                ber_display,
                link_flap_display
            ])

        table_string = table.get_string(hrules=ALL, vrules=ALL, header=True, border=True)
        print(table_string)
        logging.error(f"Errors detected for this group. Total {len(error_details)} degraded links found.")
        first_line_of_table = table_string.splitlines()[0]
        border_length = len(first_line_of_table)
        print(f"+{'-'*(border_length-2)}+")

def wait_for_prompt_after_ctrlc(shell: paramiko.Channel, timeout_sec: int = 60) -> bool:
    """
    Waits for the shell prompt to return after sending Ctrl+C.
    """
    logging.info(f"Waiting for bash prompt after Ctrl+C (timeout: {timeout_sec}s)...")
    start_time = time.time()

    while time.time() - start_time < timeout_sec:
        output, prompt_found = read_and_print_realtime(shell, timeout_sec=1, print_realtime=False)
        if prompt_found:
            logging.info("Prompt detected after Ctrl+C.")
            return True

        shell.send("\n")
        time.sleep(0.5)

        output, prompt_found = read_and_print_realtime(shell, timeout_sec=1, print_realtime=False)
        if prompt_found:
            logging.info("Prompt detected after sending newline.")
            return True

    logging.warning("Failed to detect prompt after Ctrl+C within timeout.")
    return False

def run_show_tech_fabric_threaded(shell: paramiko.Channel, hostname: str,
                                  show_tech_finished_event: threading.Event,
                                  result_dict: Dict) -> None:
    """
    Runs the show tech fabric link-include command, monitors its progress in a thread,
    and calculates the time taken. Signals completion via events and results via dict.
    """
    global SHOW_TECH_START_TIMESTAMP_FROM_LOG, SHOW_TECH_END_TIMESTAMP_FROM_LOG
    SHOW_TECH_START_TIMESTAMP_FROM_LOG = None
    SHOW_TECH_END_TIMESTAMP_FROM_LOG = None

    logging.info("--- Starting Show Tech Fabric Collection (Threaded) ---")

    try:
        logging.info("Checking for existing show tech files...")
        shell.send("dir harddisk: | i tech\n")
        dir_output, prompt_found = read_and_print_realtime(shell, timeout_sec=30)
        if not prompt_found:
            raise ShowTechError("Prompt not found after 'dir harddisk:'. Cannot proceed with show tech.")

        timestamp_str = time.strftime("%Y%m%d-%H%M%S")
        clean_hostname = hostname
        show_tech_filename = f"sh-tech-fabric-{clean_hostname}-{timestamp_str}.tgz"
        log_filename = f"{show_tech_filename}.logs"

        logging.info(f"Generated show tech filename: {show_tech_filename}")
        logging.info(f"Log filename will be: {log_filename}")

        show_tech_command = f"show tech-support fabric link-include file harddisk:/{show_tech_filename} background no-timeout compressed"
        logging.info(f"Running command: {show_tech_command}")
        shell.send(show_tech_command + "\n")
        show_tech_init_output, prompt_found = read_and_print_realtime(shell, timeout_sec=60)
        if not prompt_found:
            raise ShowTechError("Prompt not found after initiating show tech. It might not have started.")
        if "Error" in show_tech_init_output or "Invalid" in show_tech_init_output:
            raise ShowTechError(f"Error detected when initiating show tech: {show_tech_init_output}")

        logging.info("Show tech command initiated. Waiting a moment for log file to be created...")
        time.sleep(5)

        if not execute_command_in_shell(shell, "attach location 0/RP0/CPU0", "attach location 0/RP0/CPU0", timeout=30,
                                        print_realtime_output=False):
            raise ShowTechError("Failed to attach to RP for show tech log monitoring.")

        if not execute_command_in_shell(shell, "cd /misc/disk1/", "cd to /misc/disk1/", timeout=10,
                                        print_realtime_output=False):
            raise RouterCommandError("Failed to change directory to /misc/disk1/ for show tech log monitoring.")

        monitor_command = f"tail -f {log_filename}"
        logging.info(f"Monitoring show tech log with command: {monitor_command}")
        shell.send(monitor_command + "\n")

        full_log_output = ""
        start_monitoring_time = time.time()
        show_tech_completed_in_log = False

        start_time_pattern = re.compile(r"\+\+ Show tech start time: (\d{4}-\w{3}-\d{2}\.\d{6}\.\w{3}) \+\+")
        end_time_pattern = re.compile(r"\+\+ Show tech end time: (\d{4}-\w{3}-\d{2}\.\d{6}\.\w{3}) \+\+")

        while time.time() - start_monitoring_time < SHOW_TECH_MONITOR_TIMEOUT_SECONDS:
            if shell.recv_ready():
                try:
                    data = shell.recv(65535).decode('utf-8', errors='ignore')
                    if data:
                        if session_log_file_raw_output:
                            session_log_file_raw_output.write(data)
                            session_log_file_raw_output.flush()

                        if session_log_file_console_mirror:
                            session_log_file_console_mirror.write(data)
                            session_log_file_console_mirror.flush()

                        print(f"{data}", end='')
                        full_log_output += data

                        if SHOW_TECH_START_TIMESTAMP_FROM_LOG is None:
                            match_start = start_time_pattern.search(data)
                            if match_start:
                                SHOW_TECH_START_TIMESTAMP_FROM_LOG = match_start.group(1)
                                logging.info(
                                    f"Show tech actual start time captured from log: {SHOW_TECH_START_TIMESTAMP_FROM_LOG}")

                        match_end = end_time_pattern.search(data)
                        if match_end:
                            SHOW_TECH_END_TIMESTAMP_FROM_LOG = match_end.group(1)
                            logging.info("Detected '++ Show tech end time:' in log. Sending Ctrl+C...")
                            shell.send("\x03")
                            show_tech_completed_in_log = True
                            break
                except Exception as e:
                    logging.error(f"Error receiving data during show tech log monitoring: {e}")
                    break
            else:
                time.sleep(0.5)

        print()

        if not show_tech_completed_in_log:
            logging.warning(
                f"Show tech completion string not found within internal timeout ({SHOW_TECH_MONITOR_TIMEOUT_SECONDS}s).")

        # Attempt to send Ctrl+C if not already sent or if the loop timed out
        try:
            shell.send("\x03")
        except Exception as e:
            logging.warning(f"Error sending Ctrl+C to shell: {e}")

        if SHOW_TECH_END_TIMESTAMP_FROM_LOG is None:
            SHOW_TECH_END_TIMESTAMP_FROM_LOG = datetime.datetime.now().strftime(
                "%Y-%b-%d.%H%M%S.UTC")

        if not wait_for_prompt_after_ctrlc(shell, timeout_sec=60):
            raise ShowTechError("Failed to recover bash prompt after sending Ctrl+C during show tech monitoring.")

        if not execute_command_in_shell(shell, "exit", "exit bash prompt", timeout=10, print_realtime_output=False):
            logging.warning("Failed to exit bash prompt after show tech log monitoring.")

        if SHOW_TECH_START_TIMESTAMP_FROM_LOG and SHOW_TECH_END_TIMESTAMP_FROM_LOG:
            start_timestamp_no_tz = SHOW_TECH_START_TIMESTAMP_FROM_LOG.rsplit('.', 1)[0]
            end_timestamp_no_tz = SHOW_TECH_END_TIMESTAMP_FROM_LOG.rsplit('.', 1)[0]

            start_dt = datetime.datetime.strptime(start_timestamp_no_tz, "%Y-%b-%d.%H%M%S")
            end_dt = datetime.datetime.strptime(end_timestamp_no_tz, "%Y-%b-%d.%H%M%S")

            total_time_seconds = (end_dt - start_dt).total_seconds()
            mins, secs = divmod(total_time_seconds, 60)
            logging.info(f"Show tech file collection completed in: {int(mins)} minutes and {int(secs)} seconds.")
            result_dict["duration"] = total_time_seconds
            result_dict["success"] = True
        else:
            logging.error("Could not determine total time taken for show tech (missing start/end timestamps from log).")
            result_dict["duration"] = False
            result_dict["success"] = False

    except Exception as e:
        logging.error(f"Error during show tech collection (threaded): {e}", exc_info=True)
        result_dict["duration"] = False
        result_dict["success"] = False
    finally:
        show_tech_finished_event.set()
        logging.info("Show tech thread finished and signaled completion.")

def run_dataplane_monitor_phase(router_ip: str, username: str, password: str, monitor_description: str,
                                ssh_timeout: int, dataplane_timeout: int) -> bool:
    """
    Connects to the router, runs a dataplane monitor, and returns success/failure.
    This function is for sequential dataplane monitoring steps.
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

        if not execute_command_in_shell(shell, "terminal length 0", "set terminal length to 0", timeout=5,
                                        print_realtime_output=False):
            raise RouterCommandError("Failed to set terminal length 0.")
        if not execute_command_in_shell(shell, "terminal width 511", "set terminal width to 511", timeout=5,
                                        print_realtime_output=False):
            raise RouterCommandError("Failed to set terminal width 511.")

        logging.info(f"Running 'monitor dataplane' (polling logs) for IOS-XR 7.3.6+.")
        dataplane_check_clean = poll_dataplane_monitoring_736(shell, dataplane_timeout)
        monitoring_performed = True

        if monitoring_performed:
            if dataplane_check_clean:
                logging.info(f"{monitor_description} Dataplane monitoring completed and reported no errors.")
                return True
            else:
                logging.error(
                    f"{monitor_description} Dataplane monitoring completed, but errors were reported. Please check the output above.")
                raise DataplaneError(
                    f"Dataplane errors detected during {monitor_description} monitor.")
        else:
            return True

    except paramiko.AuthenticationException as e:
        raise SSHConnectionError(f"Authentication failed for {monitor_description} monitor: {e}")
    except paramiko.SSHException as e:
        raise SSHConnectionError(f"SSH error during {monitor_description} monitor: {e}")
    except DataplaneError:
        raise
    except Exception as e:
        raise SSHConnectionError(f"An unexpected error occurred during {monitor_description} dataplane monitor: {e}")
    finally:
        if shell:
            logging.info(f"Exiting CLI session after {monitor_description} dataplane monitor.")
            try:
                shell.send("exit\n")
                time.sleep(1)
                while shell.recv_ready():
                    shell.recv(65535).decode('utf-8', errors='ignore')
            except Exception as e:
                logging.warning(f"Error during graceful shell exit in {monitor_description} monitor: {e}. The socket might have already been closed.")
            finally:
                try:
                    shell.close()
                except Exception as e:
                    logging.warning(f"Error closing Paramiko shell channel in {monitor_description} monitor: {e}")
        if client:
            try:
                client.close()
            except Exception as e:
                logging.warning(f"Error closing Paramiko SSH client in {monitor_description} monitor: {e}")
        logging.info(f"SSH connection for {monitor_description} monitor closed.")

def run_concurrent_countdown_and_show_tech(router_ip: str, username: str, password: str,
                                           ssh_timeout: int, countdown_duration_minutes: int,
                                           show_tech_monitor_timeout_seconds: int) -> bool:
    """
    Connects to router CLI, runs parallel show tech and countdown.
    This function waits for BOTH the countdown timer and show tech collection to complete.
    """
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    shell = None
    try:
        logging.info(f"Connecting to {router_ip} for Concurrent Countdown and Show Tech...")
        client.connect(router_ip, port=22, username=username, password=password, timeout=ssh_timeout,
                      look_for_keys=False)
        logging.info(f"Successfully connected for Concurrent Countdown and Show Tech.")

        shell = client.invoke_shell()
        time.sleep(1)
        logging.info(f"--- Initial Shell Output (Concurrent Countdown and Show Tech) ---")
        read_and_print_realtime(shell, timeout_sec=2)
        logging.info(f"--- End Initial Shell Output ---")

        if not execute_command_in_shell(shell, "terminal length 0", "set terminal length to 0", timeout=5,
                                        print_realtime_output=False):
            raise RouterCommandError("Failed to set terminal length 0.")
        if not execute_command_in_shell(shell, "terminal width 511", "set terminal width to 511", timeout=5,
                                        print_realtime_output=False):
            raise RouterCommandError("Failed to set terminal width 511.")

        hostname = get_hostname(shell)

        show_tech_finished_event = threading.Event()
        show_tech_result = {"duration": False, "success": False}

        countdown_duration_sec = countdown_duration_minutes * 60

        timer_thread = threading.Thread(target=colorful_countdown_timer, args=(countdown_duration_sec,))
        timer_thread.start()

        show_tech_thread = threading.Thread(target=run_show_tech_fabric_threaded,
                                            args=(shell, hostname, show_tech_finished_event, show_tech_result))
        show_tech_thread.start()

        logging.info(
            f"Waiting for BOTH the {countdown_duration_minutes}-minute timer AND show tech collection to complete...")

        timer_thread.join()
        logging.info(f"{countdown_duration_minutes}-minute countdown timer has finished.")

        show_tech_thread.join()
        logging.info("Show tech collection has finished.")

        logging.info("Both parallel waiting conditions met. Proceeding with next steps.")

        if not show_tech_result["success"]:
            logging.error("Show tech collection failed or could not determine duration.")
            return False

        return True

    except paramiko.AuthenticationException as e:
        raise SSHConnectionError(f"Authentication failed during concurrent tasks phase: {e}")
    except paramiko.SSHException as e:
        raise SSHConnectionError(f"SSH error during concurrent tasks phase: {e}")
    except RouterCommandError as e:
        raise RouterCommandError(f"Router command error during concurrent tasks phase: {e}")
    except ShowTechError as e:
        raise ShowTechError(f"Show tech collection failed during concurrent tasks phase: {e}")
    except Exception as e:
        # Catch any other unexpected errors that might occur before the finally block
        logging.error(f"An unexpected error occurred during concurrent tasks phase: {e}", exc_info=True)
        raise Exception(f"An unexpected error occurred during concurrent tasks phase: {e}")
    finally:
        if shell:
            logging.info("Attempting to gracefully exit CLI session after concurrent tasks phase.")
            try:
                # Attempt to send exit command. This might fail if the socket is already closed.
                shell.send("exit\n")
                time.sleep(1)
                # Clear any remaining buffer, ignoring errors if socket is closed
                while shell.recv_ready():
                    shell.recv(65535).decode('utf-8', errors='ignore')
            except Exception as e:
                logging.warning(f"Error during graceful shell exit attempt: {e}. The socket might have already been closed.")
            finally:
                # Ensure the shell channel is closed, even if the exit command failed
                try:
                    shell.close()
                except Exception as e:
                    logging.warning(f"Error closing Paramiko shell channel: {e}")
        if client:
            logging.info("Attempting to close SSH client connection.")
            try:
                client.close()
            except Exception as e:
                logging.warning(f"Error closing Paramiko SSH client: {e}")
        logging.info("SSH connection closed for concurrent tasks phase.")

def execute_script_phase(router_ip: str, username: str, password: str, scripts_to_run: List[str],
                         script_arg_option: str, ssh_timeout: int) -> bool:
    """
    Handles the SSH connection, initial commands, and execution of scripts for a single phase.
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
                raise ScriptExecutionError(
                    "Errors detected in 'dummy no' script outputs. Aborting.")

        return True

    except paramiko.AuthenticationException as e:
        raise SSHConnectionError(f"Authentication failed for script phase '{script_arg_option}': {e}")
    except paramiko.SSHException as e:
        raise SSHConnectionError(f"SSH error during script phase '{script_arg_option}': {e}")
    except RouterCommandError as e:
        raise RouterCommandError(f"Router command error during script phase '{script_arg_option}': {e}")
    except ScriptExecutionError:
        raise
    except Exception as e:
        raise ScriptExecutionError(f"An unexpected error occurred during script phase '{script_arg_option}': {e}")
    finally:
        if shell:
            logging.info("Exiting bash prompt...")
            try:
                shell.send("exit\n")
                time.sleep(1)
                while shell.recv_ready():
                    shell.recv(65535).decode('utf-8', errors='ignore')
            except Exception as e:
                logging.warning(f"Error during graceful shell exit in script phase: {e}. The socket might have already been closed.")
            finally:
                try:
                    shell.close()
                except Exception as e:
                    logging.warning(f"Error closing Paramiko shell channel in script phase: {e}")
        if client:
            try:
                client.close()
            except Exception as e:
                logging.warning(f"Error closing Paramiko SSH client in script phase: {e}")
        logging.info("SSH connection closed.")

def run_asic_errors_show_command(router_ip: str, username: str, password: str, ssh_timeout: int) -> bool:
    """
    Connects to the router, runs the asic_errors_show command from bash.
    The command varies based on the IOS-XR version (7.x.x vs 24.x.x).
    """
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    shell = None
    try:
        logging.info(f"Connecting to {router_ip} to run asic_errors_show command...")
        client.connect(router_ip, port=22, username=username, password=password, timeout=ssh_timeout,
                      look_for_keys=False)
        logging.info(f"Successfully connected to {router_ip}.")

        shell = client.invoke_shell()
        time.sleep(1)
        logging.info("--- Initial Shell Output (asic_errors_show) ---")
        read_and_print_realtime(shell, timeout_sec=2)
        logging.info("--- End Initial Shell Output ---")

        if not execute_command_in_shell(shell, "terminal length 0", "set terminal length to 0", timeout=5,
                                        print_realtime_output=False):
            raise RouterCommandError("Failed to set terminal length 0.")
        if not execute_command_in_shell(shell, "terminal width 511", "set terminal width to 511", timeout=5,
                                        print_realtime_output=False):
            raise RouterCommandError("Failed to set terminal width 511.")

        ios_xr_version_str = get_ios_xr_version(shell)
        ios_xr_version_tuple = parse_version_string(ios_xr_version_str)
        major_version = ios_xr_version_tuple[0]

        asic_command = ""
        if major_version == 7:
            asic_command = 'asic_errors_show "-n" "A" "-a" "0x7" "-i" "0x100" "-C" "0x0" "-e" "0x0" "-c"'
            logging.info(f"IOS-XR version {ios_xr_version_str} detected. Using command for 7.x.x.")
        elif major_version == 24:
            asic_command = 'asic_errors_show "-n" "all" "-a" "0x7" "-i" "0x100" "-C" "0x0" "-e" "0x0" "-c"'
            logging.info(f"IOS-XR version {ios_xr_version_str} detected. Using command for 24.x.x.")
        else:
            logging.warning(f"Unsupported IOS-XR major version {major_version} detected. Defaulting to 7.x.x command.")
            asic_command = 'asic_errors_show "-n" "A" "-a" "0x7" "-i" "0x100" "-C" "0x0" "-e" "0x0" "-c"'

        if not execute_command_in_shell(shell, "attach location 0/RP0/CPU0", "attach location 0/RP0/CPU0", timeout=30,
                                        print_realtime_output=False):
            raise RouterCommandError("Failed to establish bash prompt for asic_errors_show.")

        logging.info(f"Running command: {asic_command}")

        shell.send(asic_command + "\n")
        asic_output, prompt_found = read_and_print_realtime(shell, timeout_sec=300, print_realtime=False)

        if not prompt_found:
            logging.warning("Prompt not detected after asic_errors_show. Attempting to send newline and re-check.")
            shell.send("\n")
            asic_output_retry, prompt_found_retry = read_and_print_realtime(shell, timeout_sec=5, print_realtime=False)
            asic_output += asic_output_retry
            prompt_found = prompt_found_retry

        if not prompt_found:
            raise AsicErrorShowError(f"Failed to reach prompt after asic_errors_show. Output: {asic_output}")

        print(f"{asic_output}", end='')
        print()

        if not execute_command_in_shell(shell, "exit", "exit bash prompt", timeout=10, print_realtime_output=False):
            logging.warning("Failed to exit bash prompt after asic_errors_show. Continuing...")

        return True

    except paramiko.AuthenticationException as e:
        raise SSHConnectionError(f"Authentication failed for asic_errors_show: {e}")
    except paramiko.SSHException as e:
        raise SSHConnectionError(f"SSH error during asic_errors_show: {e}")
    except RouterCommandError as e:
        raise RouterCommandError(f"Router command error during asic_errors_show: {e}")
    except Exception as e:
        raise AsicErrorShowError(f"An unexpected error occurred during asic_errors_show: {e}")
    finally:
        if shell:
            logging.info("Ensuring bash prompt is exited after asic_errors_show.")
            try:
                shell.send("exit\n")
                time.sleep(1)
                while shell.recv_ready():
                    shell.recv(65535).decode('utf-8', errors='ignore')
            except Exception as e:
                logging.warning(f"Error during graceful shell exit after asic_errors_show: {e}. The socket might have already been closed.")
            finally:
                try:
                    shell.close()
                except Exception as e:
                    logging.warning(f"Error closing Paramiko shell channel after asic_errors_show: {e}")
        if client:
            try:
                client.close()
            except Exception as e:
                logging.warning(f"Error closing Paramiko SSH client after asic_errors_show: {e}")
        logging.info("SSH connection closed.")

def print_final_summary(results: Dict[str, str]):
    """Prints a summary table of all executed steps."""
    logging.info(f"{'=' * 30} FINAL SCRIPT SUMMARY {'=' * 30}")
    table = PrettyTable()
    table.field_names = ["Step", "Description", "Status"]
    for step_num, result in results.items():
        status_text = result.split(': ')[1]
        table.add_row([step_num, result.split(': ')[0], status_text])

    print(table)
    logging.info(f"{'=' * 75}")

# --- Main execution block ---
if __name__ == "__main__":
    logging.info(f"--- IOS-XR Router Automation Script ---")

    # --- Router details (prompted) ---
    ROUTER_IP = input(f"Enter Router IP_add / Host: ")
    SSH_USERNAME = input(f"Enter SSH Username: ")
    SSH_PASSWORD = getpass.getpass(f"Enter SSH Password: ")

    # --- Get Hostname for Router Directory and Log Files ---
    hostname_for_log = "unknown_host"
    initial_client = None
    initial_shell = None
    try:
        logging.info(f"Attempting initial connection to {ROUTER_IP} to retrieve hostname for log directory...")
        initial_client = paramiko.SSHClient()
        initial_client.load_system_host_keys()
        initial_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        initial_client.connect(ROUTER_IP, port=22, username=SSH_USERNAME, password=SSH_PASSWORD, timeout=SSH_TIMEOUT_SECONDS, look_for_keys=False)
        initial_shell = initial_client.invoke_shell()
        time.sleep(1)
        execute_command_in_shell(initial_shell, "terminal length 0", "set terminal length to 0", timeout=5, print_realtime_output=False)
        execute_command_in_shell(initial_shell, "terminal width 511", "set terminal width to 511", timeout=5, print_realtime_output=False)
        hostname_for_log = get_hostname(initial_shell)
        logging.info(f"Retrieved hostname: {hostname_for_log}")
    except Exception as e:
        logging.error(f"Failed to retrieve hostname during initial connection: {e}. Using 'unknown_host' for log directory and filenames.")
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

    # --- Determine and Create Router Directory ---
    router_log_dir = hostname_for_log
    try:
        os.makedirs(router_log_dir, exist_ok=True)
        logging.info(f"Ensured router log directory exists: {os.path.abspath(router_log_dir)}")
    except OSError as e:
        logging.critical(f"Failed to create or access router log directory {router_log_dir}: {e}. Script cannot proceed without a log directory. Exiting.")
        exit(1)

    # --- Reconfigure Application Logging to the new directory ---
    timestamp_for_app_log = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    app_log_filename = os.path.join(router_log_dir, f"{hostname_for_log}_automation_log_{timestamp_for_app_log}.log")

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

    # --- Open Session Log Files in the new directory ---
    timestamp_for_session_logs = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    console_mirror_filename = os.path.join(router_log_dir, f"{hostname_for_log}_post_check_session_log_{timestamp_for_session_logs}.txt")
    raw_output_filename = os.path.join(router_log_dir, f"{hostname_for_log}_post_check_outputs_{timestamp_for_session_logs}.txt")

    try:
        session_log_file_console_mirror = open(console_mirror_filename, 'w', encoding='utf-8')
        logging.info(f"Console mirror session output will be logged to: {console_mirror_filename}")
    except IOError as e:
        logging.error(f"Could not open console mirror session log file {console_mirror_filename}: {e}. Console mirror output will not be logged to file.")
        session_log_file_console_mirror = None

    try:
        session_log_file_raw_output = open(raw_output_filename, 'w', encoding='utf-8')
        logging.info(f"Raw SSH output will be logged to: {raw_output_filename}")
    except IOError as e:
        logging.error(f"Could not open raw SSH output log file {raw_output_filename}: {e}. Raw SSH output will not be logged to file.")
        session_log_file_raw_output = None

    # --- List of your scripts to run (hardcoded) ---
    scripts_to_run = [
        "monitor_8800_system_v2_3_msft_bash_group0.py",
        "monitor_8800_system_v2_3_msft_bash_group1.py",
        "monitor_8800_system_v2_3_msft_bash_group2.py",
        "monitor_8800_system_v2_3_msft_bash_group3.py",
    ]

    results_summary: Dict[str, str] = {}
    script_aborted = False

    try:
        # Step 1: Phase 1: Dummy Yes
        logging.info(f"\n{'#' * 70}{'#' * 70}")
        logging.info("### Step 1: Starting Phase 1: Running scripts with '--dummy' yes ###")
        try:
            execute_script_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, scripts_to_run, "'--dummy' yes",
                                 SSH_TIMEOUT_SECONDS)
            results_summary["Step 1"] = "Phase 1 (Dummy Yes): Success"
            logging.info("Phase 1 completed successfully.")
        except (SSHConnectionError, RouterCommandError, ScriptExecutionError) as e:
            results_summary["Step 1"] = f"Phase 1 (Dummy Yes): Failed - {e}"
            logging.critical(f"Phase 1 failed: {e}")
            script_aborted = True
            raise

        # Step 2: Monitor Dataplane (First instance)
        logging.info(f"\n{'#' * 70}{'#' * 70}")
        logging.info("### Step 2: Running First Dataplane Monitor ###")
        try:
            run_dataplane_monitor_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, "FIRST", SSH_TIMEOUT_SECONDS,
                                        DATAPLANE_MONITOR_TIMEOUT_SECONDS)
            results_summary["Step 2"] = "First Dataplane Monitor: Success"
            logging.info("First Dataplane Monitor completed successfully.")
        except (SSHConnectionError, RouterCommandError, DataplaneError) as e:
            results_summary["Step 2"] = f"First Dataplane Monitor: Failed - {e}"
            logging.critical(f"First Dataplane Monitor failed: {e}")
            script_aborted = True
            raise

        # Step 3: Wait 15 minutes (Sequential timer)
        logging.info(f"\n{'#' * 70}{'#' * 70}")
        logging.info(f"### Step 3: Starting Sequential {COUNTDOWN_DURATION_MINUTES}-minute Countdown ###")
        try:
            colorful_countdown_timer(COUNTDOWN_DURATION_MINUTES * 60)
            results_summary["Step 3"] = "Sequential 15-minute Countdown: Success"
            logging.info(f"Sequential {COUNTDOWN_DURATION_MINUTES}-minute countdown finished.")
        except Exception as e:
            results_summary["Step 3"] = f"Sequential 15-minute Countdown: Failed - {e}"
            logging.critical(f"Sequential countdown failed: {e}")
            script_aborted = True
            raise

        # Step 4: Phase 2: Dummy no
        logging.info(f"\n{'#' * 70}{'#' * 70}")
        logging.info("### Step 4: Starting Phase 2: Running scripts with '--dummy' no ###")
        try:
            execute_script_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, scripts_to_run, "'--dummy' no",
                                 SSH_TIMEOUT_SECONDS)
            results_summary["Step 4"] = "Phase 2 (Dummy No): Success"
            logging.info("Phase 2 completed successfully.")
        except (SSHConnectionError, RouterCommandError, ScriptExecutionError) as e:
            results_summary["Step 4"] = f"Phase 2 (Dummy No): Failed - {e}"
            logging.critical(f"Phase 2 failed: {e}")
            script_aborted = True
            raise

        # Step 5: Monitor dataplane (Second instance)
        logging.info(f"\n{'#' * 70}{'#' * 70}")
        logging.info("### Step 5: Running Second Dataplane Monitor ###")
        try:
            run_dataplane_monitor_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, "SECOND", SSH_TIMEOUT_SECONDS,
                                        DATAPLANE_MONITOR_TIMEOUT_SECONDS)
            results_summary["Step 5"] = "Second Dataplane Monitor: Success"
            logging.info("Second Dataplane Monitor completed successfully.")
        except (SSHConnectionError, RouterCommandError, DataplaneError) as e:
            results_summary["Step 5"] = f"Second Dataplane Monitor: Failed - {e}"
            logging.critical(f"Second Dataplane Monitor failed: {e}")
            script_aborted = True
            raise

        # Step 6: Concurrent 15 minute timer and show tech collection
        logging.info(f"\n{'#' * 70}{'#' * 70}")
        logging.info(
            f"### Step 6: Starting Concurrent {COUNTDOWN_DURATION_MINUTES}-minute Countdown and Show Tech Collection ###")
        try:
            concurrent_success = run_concurrent_countdown_and_show_tech(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD,
                                                                        SSH_TIMEOUT_SECONDS, COUNTDOWN_DURATION_MINUTES,
                                                                        SHOW_TECH_MONITOR_TIMEOUT_SECONDS)
            if concurrent_success:
                results_summary["Step 6"] = "Concurrent 15-minute Countdown and Show Tech: Success"
                logging.info("Concurrent countdown and show tech phase completed successfully.")
            else:
                results_summary["Step 6"] = "Concurrent 15-minute Countdown and Show Tech: Failed - Show tech issue"
                logging.critical("Concurrent countdown and show tech phase failed due to show tech issue.")
                script_aborted = True
                raise ShowTechError("Show tech collection failed during concurrent tasks phase.")
        except (SSHConnectionError, RouterCommandError, ShowTechError) as e:
            results_summary["Step 6"] = f"Concurrent 15-minute Countdown and Show Tech: Failed - {e}"
            logging.critical(f"Concurrent countdown and show tech phase failed: {e}")
            script_aborted = True
            raise

        # Step 7: Final Dummy No Run
        logging.info(f"\n{'#' * 70}{'#' * 70}")
        logging.info("### Step 7: Starting Final Phase: Running scripts with '--dummy' no again ###")
        try:
            execute_script_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, scripts_to_run,
                                 "'--dummy' no",
                                 SSH_TIMEOUT_SECONDS)
            results_summary["Step 7"] = "Final Dummy No: Success"
            logging.info("Final 'dummy no' phase completed successfully.")
        except (SSHConnectionError, RouterCommandError, ScriptExecutionError) as e:
            results_summary["Step 7"] = f"Final Dummy No: Failed - {e}"
            logging.critical(f"Final 'dummy no' phase failed: {e}")
            script_aborted = True
            raise

        # Step 8: Run asic_errors_show command
        logging.info(f"\n{'#' * 70}{'#' * 70}")
        logging.info("### Step 8: Running asic_errors_show command ###")
        try:
            run_asic_errors_show_command(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, SSH_TIMEOUT_SECONDS)
            results_summary["Step 8"] = "asic_errors_show Command: Success"
            logging.info("asic_errors_show command completed successfully.")
        except (SSHConnectionError, RouterCommandError, AsicErrorShowError) as e:
            results_summary["Step 8"] = f"asic_errors_show Command: Failed - {e}"
            logging.critical(f"asic_errors_show command failed: {e}")

    except Exception as e:
        logging.critical(f"An unhandled critical error occurred during script execution: {e}", exc_info=True)
        script_aborted = True
    finally:
        pass

    # Print Final Summary
    logging.info(f"\n{'#' * 70}{'#' * 70}")
    logging.info("### Printing Final Summary ###")
    if script_aborted:
        logging.critical("Script execution was aborted due to a critical error.")
    else:
        logging.info("All planned steps completed.")
    print_final_summary(results_summary)
    logging.info(f"--- Script Execution Finished ---")

    # Close the session log files at the very end
    if session_log_file_console_mirror:
        session_log_file_console_mirror.close()
        logging.info(f"Console mirror session log file closed.")
    if session_log_file_raw_output:
        session_log_file_raw_output.close()
        logging.info(f"Raw SSH output log file closed.")