import paramiko
import time
import getpass
import re
import threading
from prettytable import PrettyTable, HEADER, ALL
import datetime
import logging
import platform
import os
from typing import Optional, List, Tuple, Dict, Any

# --- Constants and Configuration ---
# LOG_FILE constant is now dynamic and will be set after hostname retrieval
SSH_TIMEOUT_SECONDS = 15
DATAPLANE_MONITOR_TIMEOUT_SECONDS = 1200  # 20 minutes
SHOW_TECH_MONITOR_TIMEOUT_SECONDS = 3600  # 60 minutes
WAIT_TIME_MINUTES = 20  # New wait time constant
COUNTDOWN_DURATION_MINUTES = 65  # Modified countdown duration

# Define common prompt patterns for IOS-XR bash and CLI
PROMPT_PATTERNS = [
    r'#\s*$',  # Matches '#' followed by optional whitespace at end of line (e.g., router# or root@host:~# )
    r'\$\s*$'  # Matches '$' for non-root users (less likely after 'attach location')
]

# Global variables to store show tech timing information
SHOW_TECH_START_TIMESTAMP_FROM_LOG: Optional[str] = None
SHOW_TECH_END_TIMESTAMP_FROM_LOG: Optional[str] = None

# Global variables for session log files (now two separate files)
# These will be assigned in the main execution block of each script that imports this module
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


# --- Helper Functions ---
def colorful_countdown_timer(seconds: int):
    """Displays a countdown timer on the console (colors removed)."""
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
    Ensures a newline is printed at the end if the output didn't already end with one,
    when print_realtime is True.
    Also writes the raw output to the global session log file if available.
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
                        session_log_file_raw_output.flush()  # Ensure data is written immediately

                    # Write data to the console mirror file if printing real-time
                    global session_log_file_console_mirror
                    if print_realtime and session_log_file_console_mirror:
                        session_log_file_console_mirror.write(data)
                        session_log_file_console_mirror.flush()  # Ensure data is written immediately

                    if print_realtime:
                        print(f"{data}", end='')  # Removed color codes
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
                                # If a prompt is found, and we were printing real-time,
                                # ensure the cursor is on a new line for subsequent logs.
                                if print_realtime and not data.endswith('\n'):
                                    print()  # Add a newline if the last data didn't have one
                                return full_output_buffer, prompt_found
            except Exception as e:
                logging.error(f"Error receiving data: {e}")
                break
        else:
            time.sleep(0.1)

    # If timeout occurs and we were printing real-time, ensure a newline
    if print_realtime and full_output_buffer and not full_output_buffer.endswith('\n'):
        print()
    return full_output_buffer, prompt_found


def execute_command_in_shell(shell: paramiko.Channel, command: str, command_description: str,
                             timeout: int = 30, print_realtime_output: bool = True) -> bool:
    """
    Sends a command to the shell, prints output in real-time (or not), and waits for prompt.
    Returns True on success (prompt found), False otherwise.
    Raises RouterCommandError if prompt is not found.
    """
    logging.info(f"Sending '{command_description}'...")

    # --- Add a small delay and buffer drain before sending the command ---
    # This helps clear any lingering output from previous commands and ensures shell is ready
    time.sleep(0.1)  # Small delay to let previous operations settle
    # Read and discard any data currently in the buffer
    while shell.recv_ready():
        shell.recv(65535)
    # --------------------------------------------------------------------

    shell.send(command + "\n")
    time.sleep(0.5)  # Give the router a moment to process the command and start sending output

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
    Prints output in real-time.
    Returns a list of tuples: (script_name, full_script_output_string).
    """
    all_scripts_raw_output = []

    for script_name in scripts_to_run:
        # Extract group number from script name
        group_match = re.search(r'group(\d+)\.py', script_name)
        group_number = group_match.group(1) if group_match else "Unknown"

        # Clean up script_arg_option for logging (remove surrounding quotes if present)
        script_arg_option_for_log = script_arg_option.strip("'")

        # Adjust padding to ensure it fits on one line
        padding_len = 15  # Reduced from 50 to make it fit
        logging.info(
            f"{'=' * padding_len}--- Running Group {group_number} with option {script_arg_option_for_log} ---{'=' * padding_len}")

        command_to_execute = f"python3 {script_name} {script_arg_option}"
        logging.info(f"Sending '{command_to_execute}'...")
        shell.send(command_to_execute + "\n")

        logging.info(f"Waiting for '{script_name}' to finish (up to 10 minutes) and printing output in real-time...")
        # Now printing in real-time again for dummy scripts
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
    Assumes it's operating from the XR CLI prompt.
    Raises RouterCommandError if version cannot be determined.
    """
    logging.info("Attempting to retrieve IOS-XR version...")
    shell.send("show version\n")
    output, prompt_found = read_and_print_realtime(shell, timeout_sec=30, print_realtime=False)  # Silent capture
    print(f"{output}", end='')  # Explicitly print captured output, removed color
    print()  # Add newline after router output
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
    Assumes it's operating from the XR CLI prompt.
    Returns 'unknown_host' if hostname cannot be determined.
    The hostname will have dots '.' replaced with hyphens '-'.
    No other characters will be sanitized.
    """
    logging.info("Attempting to retrieve hostname using 'show running-config | i hostname'...")
    shell.send("show running-config | i hostname\n")
    # Capture output silently to avoid mixing with logs
    output, prompt_found = read_and_print_realtime(shell, timeout_sec=10, print_realtime=False)
    print()  # Add newline after router output (even if silent, ensures cursor is on new line for next log)

    # Try parsing hostname from 'show running-config | i hostname' output first
    for line in output.splitlines():
        match = re.search(r"^\s*hostname\s+(\S+)",
                          line)  # Added ^\s* to match start of line, allowing leading whitespace
        if match:
            hostname = match.group(1)
            # Replace dots with hyphens, retain all other characters
            hostname = hostname.replace('.', '-')
            logging.info(f"Hostname detected from 'show running-config': {hostname}")
            return hostname

    # Fallback: Try parsing hostname from the prompt if 'show running-config' failed or didn't provide it
    if prompt_found:  # Only try parsing from prompt if a prompt was actually found
        # Example prompt: RP/0/RP0/CPU0:8818_SJC24_R34_SYS-03#
        # Look for pattern ending with '#' or '$' and capture the part before it
        # This regex tries to capture the last segment before '#' or '$'
        prompt_match = re.search(r'[:>](\S+)[#$]', output)
        if prompt_match:
            hostname = prompt_match.group(1)
            # Replace dots with hyphens, retain all other characters
            hostname = hostname.replace('.', '-')
            logging.info(f"Hostname detected from prompt: {hostname}")
            return hostname

    logging.warning(
        "Could not parse hostname from 'show running-config | i hostname' output or from prompt. Using 'unknown_host'.")
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
    Raises RouterCommandError if timestamp cannot be retrieved or parsed.
    Example output: "03:56:02.142 PDT Sun Aug 3 2025"
    """
    logging.info("Getting router's current timestamp using 'show clock'...")
    shell.send("show clock\n")
    output, prompt_found = read_and_print_realtime(shell, timeout_sec=10, print_realtime=False)  # Silent capture
    print()  # Add newline after router output (even if silent, ensures cursor is on new line for next log)
    if not prompt_found:
        raise RouterCommandError("Prompt not found after 'show clock'. Cannot get router timestamp.")

    # Regex to capture time, timezone, day, month, day_of_month, year
    # Example: "03:56:02.142 PDT Sun Aug 3 2025"
    # Pattern: HH:MM:SS.ms TZ Day Mon DD YYYY
    match = re.search(r"(\d{2}:\d{2}:\d{2}\.\d{3})\s+(\w+)\s+\w+\s+(\w{3})\s+(\d+)\s+(\d{4})", output)
    if match:
        time_str, tz_str, month_str, day_str, year_str = match.groups()
        # Construct a full datetime string for parsing
        timestamp_full_str = f"{month_str} {day_str} {year_str} {time_str}"
        try:
            # Parse datetime. Note: strptime does not handle timezone abbreviations like 'PDT' directly.
            # For exact comparison, we assume router's clock and log timestamps are consistent.
            dt_obj = datetime.datetime.strptime(timestamp_full_str, "%b %d %Y %H:%M:%S.%f")
            logging.info(f"Router timestamp detected: {dt_obj}")
            return dt_obj
        except ValueError as e:
            raise RouterCommandError(f"Failed to parse router timestamp '{timestamp_full_str}': {e}")
    else:
        raise RouterCommandError(f"Could not parse 'show clock' output for timestamp: {output}")


def poll_dataplane_monitoring_735(shell: paramiko.Channel, max_poll_duration_sec: int) -> bool:
    """
    For IOS-XR 7.3.5. Monitors 'monitor dataplane-health' command
    which runs in foreground and provides direct output.
    """
    logging.info(f"Running 'monitor dataplane-health' command (IOS-XR 7.3.5 foreground mode)...")
    shell.send("monitor dataplane-health\n")
    time.sleep(2)

    # Read output in real-time until command completes
    output, prompt_found = read_and_print_realtime(shell, timeout_sec=max_poll_duration_sec, print_realtime=True)

    if not prompt_found:
        raise DataplaneError(
            f"Dataplane monitoring did not complete within {max_poll_duration_sec // 60} minutes or prompt was not detected")

    # Check if monitoring completed successfully by looking for completion indicators
    if "DATAPATH CHECK IS CLEAN." in output or "Summary of results:" in output:
        logging.info("Dataplane monitoring completed successfully")
        return parse_dataplane_output_for_errors(output)
    else:
        raise DataplaneError("Dataplane monitoring completed but no valid results found in output")


# --- New Helper Functions for Error Reporting ---

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

    # Regex to capture the main faulty link line
    faulty_link_pattern = re.compile(
        r"Link\s+(.*?)\s+---\s+(.*?)\s+between\s+(.*?)\s+and\s+(.*?)\s+is faulty\s+-\s+codewords\s+(.*?),\s+BER\s+([\d\.e-]+)\s+FLR\s+([\d\.e-]+)\s+RX Link Down Count\s+(\d+)"
    )

    # Regex to capture the status lines that follow a faulty link
    status_line_pattern = re.compile(r"^(Codewords|BER|FLR|RX Link Down Count):\s+(OK|BAD)$")

    lines = script_output.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        match = faulty_link_pattern.search(line)
        if match:
            # Extract parts of the link connection
            link_conn_part1 = match.group(1).strip()
            link_conn_part2 = match.group(2).strip()
            loc1 = match.group(3).strip()
            loc2 = match.group(4).strip()

            # Reconstruct the full link connection string
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

            # Look for status lines immediately following the faulty link line
            j = i + 1
            # Continue reading status lines until a new faulty link line, "Total " line, or end of output
            while j < len(lines) and not faulty_link_pattern.search(lines[j]) and not lines[j].strip().startswith(
                    "Total "):
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
            i = j - 1  # Adjust index to continue after processing this faulty link and its statuses
        i += 1

    return errors_found_details


def format_and_print_error_report(script_name: str, group_number: str, error_details: List[Dict[str, str]]):
    """
    Formats and prints the error report for a given script.
    """
    # Print the header lines
    logging.info(f"--- Error Report for {script_name} ---")
    logging.info("Reference Thresholds: BER < 1e-08, FLR < 1e-21")

    table = PrettyTable()
    table.field_names = ["Link Connection", "Group_number", "Codewords", "FLR", "BER", "Link_flap"]

    # Set alignment for columns
    table.align["Link Connection"] = "l"
    table.align["Group_number"] = "c"
    table.align["Codewords"] = "l"
    table.align["FLR"] = "l"
    table.align["BER"] = "l"
    table.align["Link_flap"] = "l"

    if not error_details:
        # Add a dummy row for "No errors detected" format
        table.add_row(["", group_number, "", "", "", ""])

        # Get the string representation of the table with only header and the dummy row
        # Use `hrules=PrettyTable.HEADER` to get a rule only after the header.
        # Use `vrules=PrettyTable.ALL` for all vertical rules.
        # Use `border=True` for top/bottom/side borders.
        table_string = table.get_string(hrules=HEADER, vrules=ALL, header=True, border=True)
        print(table_string)

        logging.info("No errors detected for this group.")

        # Print the final horizontal rule, matching the table's width
        first_line_of_table = table_string.splitlines()[0]
        border_length = len(first_line_of_table)
        print(f"+{'-' * (border_length - 2)}+")

    else:
        for detail in error_details:
            flr_display = f"{detail['FLR']} ({detail['FLR_Status']})" if detail['FLR_Status'] != "N/A" else detail[
                'FLR']
            ber_display = f"{detail['BER']} ({detail['BER_Status']})" if detail['BER_Status'] != "N/A" else detail[
                'BER']
            link_flap_display = f"{detail['Link_flap']} ({detail['Link_flap_Status']})" if detail[
                                                                                               'Link_flap_Status'] != "N/A" else \
            detail['Link_flap']

            table.add_row([
                detail["Link Connection"],
                group_number,
                detail["Codewords"],
                flr_display,
                ber_display,
                link_flap_display
            ])

        # For errors, print with all horizontal rules (between data rows too)
        table_string = table.get_string(hrules=ALL, vrules=ALL, header=True, border=True)
        print(table_string)

        logging.error(f"Errors detected for this group. Total {len(error_details)} degraded links found.")

        # Print the final horizontal rule, matching the table's width
        first_line_of_table = table_string.splitlines()[0]
        border_length = len(first_line_of_table)
        print(f"+{'-' * (border_length - 2)}+")


def wait_for_prompt_after_ctrlc(shell: paramiko.Channel, timeout_sec: int = 60) -> bool:
    """
    Waits for the shell prompt to return after sending Ctrl+C.
    Sends newlines periodically to try and force the prompt.
    Returns True if prompt is found, False otherwise.
    """
    logging.info(f"Waiting for bash prompt after Ctrl+C (timeout: {timeout_sec}s)...")
    start_time = time.time()

    while time.time() - start_time < timeout_sec:
        # Read any pending output
        output, prompt_found = read_and_print_realtime(shell, timeout_sec=1, print_realtime=False)  # Silent capture
        if prompt_found:
            logging.info("Prompt detected after Ctrl+C.")
            return True

        # If no prompt, try sending a newline to force it
        shell.send("\n")
        time.sleep(0.5)  # Give it a moment to process newline

        output, prompt_found = read_and_print_realtime(shell, timeout_sec=1, print_realtime=False)  # Silent capture
        if prompt_found:
            logging.info("Prompt detected after sending newline.")
            return True

    logging.warning("Failed to detect prompt after Ctrl+C within timeout.")
    return False


def run_show_tech_fabric(shell: paramiko.Channel, hostname: str) -> bool:
    """
    Runs the show tech fabric link-include command and monitors its completion.
    Returns True on success, raises ShowTechError on failure.
    """
    global SHOW_TECH_START_TIMESTAMP_FROM_LOG, SHOW_TECH_END_TIMESTAMP_FROM_LOG
    SHOW_TECH_START_TIMESTAMP_FROM_LOG = None
    SHOW_TECH_END_TIMESTAMP_FROM_LOG = None

    logging.info("--- Starting Show Tech Fabric Collection ---")

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
                f"Show tech completion string not found within timeout ({SHOW_TECH_MONITOR_TIMEOUT_SECONDS}s).")
            shell.send("\x03")
            if SHOW_TECH_END_TIMESTAMP_FROM_LOG is None:
                SHOW_TECH_END_TIMESTAMP_FROM_LOG = datetime.datetime.now().strftime("%Y-%b-%d.%H%M%S.UTC")

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
            return True
        else:
            logging.error("Could not determine total time taken for show tech (missing start/end timestamps from log).")
            return False

    except Exception as e:
        logging.error(f"Error during show tech collection: {e}", exc_info=True)
        return False


def run_dataplane_monitor_phase(router_ip: str, username: str, password: str, monitor_description: str,
                                ssh_timeout: int, dataplane_timeout: int) -> bool:
    """
    Connects to the router, runs a dataplane monitor, and returns success/failure.
    This function is for sequential dataplane monitoring steps.
    Raises SSHConnectionError, RouterCommandError, DataplaneError.
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

        # Directly call poll_dataplane_monitoring_736 as per new requirement
        logging.info(f"Running 'monitor dataplane-health' for IOS-XR 7.3.5.")
        dataplane_check_clean = poll_dataplane_monitoring_735(shell, dataplane_timeout)

        if dataplane_check_clean:
            logging.info(f"{monitor_description} Dataplane monitoring completed and reported no errors.")
            return True
        else:
            logging.error(
                f"{monitor_description} Dataplane monitoring completed, but errors were reported. Please check the output above.")
            raise DataplaneError(
                f"Dataplane errors detected during {monitor_description} monitor.")

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
    Closes the connection after completion.
    Raises SSHConnectionError, RouterCommandError, ScriptExecutionError.
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
                raise ScriptExecutionError("Errors detected in 'dummy no' script outputs. Aborting.")

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


def run_show_tech_phase(router_ip: str, username: str, password: str, ssh_timeout: int) -> bool:
    """
    Connects to the router and runs show tech collection.
    Raises SSHConnectionError, RouterCommandError, ShowTechError.
    """
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    shell = None
    try:
        logging.info(f"Connecting to {router_ip} for Show Tech collection...")
        client.connect(router_ip, port=22, username=username, password=password, timeout=ssh_timeout,
                       look_for_keys=False)
        logging.info(f"Successfully connected for Show Tech collection.")

        shell = client.invoke_shell()
        time.sleep(1)
        logging.info("--- Initial Shell Output (Show Tech) ---")
        read_and_print_realtime(shell, timeout_sec=2)
        logging.info("--- End Initial Shell Output ---")

        # Set terminal length and width to prevent pagination
        if not execute_command_in_shell(shell, "terminal length 0", "set terminal length to 0", timeout=5,
                                        print_realtime_output=False):
            raise RouterCommandError("Failed to set terminal length 0.")
        if not execute_command_in_shell(shell, "terminal width 511", "set terminal width to 511", timeout=5,
                                        print_realtime_output=False):
            raise RouterCommandError("Failed to set terminal width 511.")

        hostname = get_hostname(shell)
        success = run_show_tech_fabric(shell, hostname)

        if not success:
            raise ShowTechError("Show tech collection failed.")

        return True

    except paramiko.AuthenticationException as e:
        raise SSHConnectionError(f"Authentication failed for show tech: {e}")
    except paramiko.SSHException as e:
        raise SSHConnectionError(f"SSH error during show tech: {e}")
    except RouterCommandError as e:
        raise RouterCommandError(f"Router command error during show tech: {e}")
    except Exception as e:
        raise ShowTechError(f"An unexpected error occurred during show tech: {e}")
    finally:
        if shell:
            logging.info("Exiting CLI session after show tech.")
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


def run_clear_asic_counters(router_ip: str, username: str, password: str, ssh_timeout: int) -> bool:
    """
    Connects to the router and runs the clear ASIC counters command.
    Raises SSHConnectionError, RouterCommandError, AsicErrorShowError.
    """
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    shell = None
    try:
        logging.info(f"Connecting to {router_ip} to clear ASIC counters...")
        client.connect(router_ip, port=22, username=username, password=password, timeout=ssh_timeout,
                       look_for_keys=False)
        logging.info(f"Successfully connected to {router_ip}.")

        shell = client.invoke_shell()
        time.sleep(1)
        logging.info("--- Initial Shell Output (Clear ASIC Counters) ---")
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
            raise RouterCommandError("Failed to establish bash prompt for ASIC counter clearing.")

        # Clear ASIC counters command
        clear_command = 'asic_errors_show "-n" "A" "-a" "0x7" "-i" "0x100" "-C" "0x1" "-e" "0x0" "-c"'
        logging.info(f"Running clear ASIC counters command: {clear_command}")

        shell.send(clear_command + "\n")
        clear_output, prompt_found = read_and_print_realtime(shell, timeout_sec=300, print_realtime=False)

        if not prompt_found:
            logging.warning("Prompt not detected after clear ASIC counters. Attempting to send newline and re-check.")
            shell.send("\n")
            clear_output_retry, prompt_found_retry = read_and_print_realtime(shell, timeout_sec=5, print_realtime=False)
            clear_output += clear_output_retry
            prompt_found = prompt_found_retry

        if not prompt_found:
            raise AsicErrorShowError(f"Failed to reach prompt after clear ASIC counters. Output: {clear_output}")

        # Print the captured output
        print(f"{clear_output}", end='')
        print()

        if not execute_command_in_shell(shell, "exit", "exit bash prompt", timeout=10, print_realtime_output=False):
            logging.warning("Failed to exit bash prompt after clear ASIC counters. Continuing...")

        return True

    except paramiko.AuthenticationException as e:
        raise SSHConnectionError(f"Authentication failed for clear ASIC counters: {e}")
    except paramiko.SSHException as e:
        raise SSHConnectionError(f"SSH error during clear ASIC counters: {e}")
    except RouterCommandError as e:
        raise RouterCommandError(f"Router command error during clear ASIC counters: {e}")
    except Exception as e:
        raise AsicErrorShowError(f"An unexpected error occurred during clear ASIC counters: {e}")
    finally:
        if shell:
            logging.info("Ensuring bash prompt is exited after clear ASIC counters.")
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
    """Prints a summary table of all executed steps."""
    logging.info(f"{'=' * 30} FINAL SCRIPT SUMMARY {'=' * 30}")
    table = PrettyTable()
    table.field_names = ["Step", "Description", "Status"]
    for step_num, result in results.items():
        status_text = result.split(': ')[1]
        table.add_row([step_num, result.split(': ')[0], status_text])

    print(table)
    logging.info(f"{'=' * 75}")