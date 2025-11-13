#!/usr/bin/env python3
import sys
import os
import platform
import subprocess
from pathlib import Path


# Architecture detection and re-execution logic
def ensure_compatible_environment():
    """Ensure script runs with architecture-compatible dependencies (with optional venv setup)."""
    arch = platform.machine()
    script_dir = Path(__file__).parent
    venv_path = script_dir / f".venv_{arch}"
    venv_python = venv_path / "bin" / "python"

    # Check if we're already running in the correct venv
    if sys.prefix == str(venv_path):
        return  # Already in correct environment

    # Check if venv exists and has dependencies
    if venv_python.exists():
        try:
            result = subprocess.run(
                [str(venv_python), "-c", "import paramiko"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                # Re-execute script with venv Python
                os.execv(str(venv_python), [str(venv_python)] + sys.argv)
        except Exception:
            pass

    # Try to create venv, but fall back gracefully if it fails
    try:
        print(f"Setting up {arch}-compatible environment...")
        print(f"This is a one-time setup and may take a minute...\n")

        # Create venv
        import venv
        venv.create(venv_path, with_pip=True)

        # Install dependencies
        pip_path = venv_path / "bin" / "pip"
        subprocess.run([str(pip_path), "install", "--upgrade", "pip"],
                       check=True, capture_output=True)
        subprocess.run([str(pip_path), "install", "paramiko", "prettytable"],
                       check=True, capture_output=True)

        print("✓ Environment setup complete\n")

        # Re-execute with new venv
        os.execv(str(venv_python), [str(venv_python)] + sys.argv)

    except Exception as e:
        print(f"⚠️  Virtual environment setup failed: {e}")
        print("📋 This might be due to missing system packages (e.g., python3-venv on Ubuntu/Debian)")
        print("🔄 Continuing with system Python...")
        print("💡 Note: You can install missing packages with: sudo apt-get install python3-venv python3-pip")

        # Check if required dependencies are available in system Python
        missing_deps = []
        try:
            import paramiko
        except ImportError:
            missing_deps.append("paramiko")

        try:
            import prettytable
        except ImportError:
            missing_deps.append("prettytable")

        if missing_deps:
            print(f"❌ Missing required dependencies: {', '.join(missing_deps)}")
            print(f"📦 Install with: pip3 install {' '.join(missing_deps)}")
            print(f"   or: python3 -m pip install {' '.join(missing_deps)}")
            user_choice = input("Continue anyway? (y/N): ").lower()
            if user_choice not in ['y', 'yes']:
                print("Script execution cancelled.")
                sys.exit(1)

        print("✅ Proceeding with system Python...\n")
        # Continue with system Python as fallback


# Run environment check before any other imports
ensure_compatible_environment()


# This script connects to a Cisco IOS-XR device via SSH to execute a two-phase dummy script process.
# It simulates a scenario where initial scripts are run, followed by a waiting period, and then a second set of scripts.
# The script incorporates comprehensive logging to manage console output and file recording.
#
# It performs the following actions:
# - Establishes an SSH connection to the specified router.
# - Retrieves and sanitizes the router's hostname for directory and log file naming.
# - Configures advanced logging, redirecting all console output to both the terminal and a dedicated raw output file.
# - **Phase 1:** Connects to the router, navigates to the bash prompt, and executes a predefined list of dummy Python scripts
# with the argument '--dummy' yes.
# - Waits for a specified duration (20 minutes) between the two phases.
# - **Phase 2:** Re-establishes an SSH connection (or re-uses the existing one if session is maintained), navigates to
# the bash prompt, and executes the same list of dummy Python scripts with the argument '--dummy' no.
# - Parses the output of the '--dummy' no scripts to identify and report simulated errors (codewords, BER, FLR, RX Link Down Count)
# in a formatted table.
# - Logs all internal script messages and router command outputs to separate files.
# - Handles SSH connection errors, command execution failures, and other unexpected exceptions gracefully.

__author__ = "Pronoy Dasgupta"
__copyright__ = "Copyright 2024 (C) Cisco Systems, Inc."
__credits__ = "Pronoy Dasgupta"
__version__ = "2.0.0"
__maintainer__ = "Pronoy Dasgupta"
__email__ = "prongupt@cisco.com"
__status__ = "production"

import paramiko
import time
import os
import getpass
import re
import logging
import sys
import datetime
from typing import Optional, List, Tuple, Dict, Any

# --- Constants and Configuration ---
SSH_TIMEOUT_SECONDS = 15
COMMAND_TIMEOUT_SECONDS = 30
SCRIPT_EXECUTION_TIMEOUT_SECONDS = 600  # 10 minutes for scripts
PHASE2_ERRORS_DETECTED = False  # Global flag to track Phase 2 errors

PROMPT_PATTERNS = [
    r'#\s*$',
    r'\$\s*$'
]


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


class HostnameRetrievalError(Exception):
    """Custom exception for failures during hostname retrieval."""
    pass


# --- Enhanced Logging Classes ---
class CompactFormatter(logging.Formatter):
    """Enhanced formatter with bright colors for status messages and consistent timestamps"""

    def __init__(self):
        super().__init__(datefmt='%Y-%m-%d %H:%M:%S')

    FORMATS = {
        logging.ERROR: '%(asctime)s - \033[91m%(levelname)s\033[0m - %(message)s',
        logging.WARNING: '%(asctime)s - \033[93m%(levelname)s\033[0m - %(message)s',
        logging.INFO: '%(asctime)s - %(levelname)s - %(message)s',
        logging.CRITICAL: '%(asctime)s - \033[91m%(levelname)s\033[0m - %(message)s',
    }

    def format(self, record):
        msg = record.getMessage()
        if msg.startswith('✓ ') and ('passed' in msg or 'complete' in msg):
            # Bright green for passed checks
            return f'{self.formatTime(record, self.datefmt)} - \033[92m{record.levelname}\033[0m - \033[1;92m{msg}\033[0m'
        elif msg.startswith('✗ ') and ('failed' in msg or 'error' in msg):
            # Bright red for failed checks
            return f'{self.formatTime(record, self.datefmt)} - \033[91m{record.levelname}\033[0m - \033[1;91m{msg}\033[0m'
        else:
            # Use original formatting for other messages
            log_fmt = self.FORMATS.get(record.levelno, '%(asctime)s - %(levelname)s - %(message)s')
            formatter = logging.Formatter(log_fmt, datefmt=self.datefmt)
            return formatter.format(record)


class Tee:
    def __init__(self, stdout_stream, file_object):
        self.stdout = stdout_stream
        self.file_object = file_object

    def write(self, data):
        # Write data as-is without adding extra newlines
        self.stdout.write(data)
        self.stdout.flush()
        self.file_object.write(data)
        self.file_object.flush()

    def flush(self):
        self.stdout.flush()
        self.file_object.flush()


# --- Enhanced SSH and Command Functions ---
def countdown_timer(seconds, console_stream):
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


def read_and_print_realtime(shell_obj, timeout_sec=600, print_realtime: bool = True):
    """
    FIXED version - handle individual dots without newlines
    """
    full_output_buffer = ""
    start_time = time.time()
    prompt_found = False
    prompt_check_buffer = ""
    last_output_was_dots = False

    while time.time() - start_time < timeout_sec:
        if shell_obj.recv_ready():
            data = shell_obj.recv(1024).decode('utf-8', errors='ignore')
            if data:
                if print_realtime:
                    # FIXED: Check for just a single dot (no newline required)
                    if data == '.':
                        print(".", end='', flush=True)  # Print dot without newline
                        last_output_was_dots = True
                    else:
                        print(f"{data}", end='')
                        last_output_was_dots = False

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
                            if print_realtime and last_output_was_dots:
                                print()  # End the dot line
                            elif print_realtime and not data.endswith('\n'):
                                print()
                            return full_output_buffer, prompt_found
            else:
                break
        else:
            time.sleep(0.1)

    if print_realtime and full_output_buffer and not full_output_buffer.endswith('\n'):
        print()
    return full_output_buffer, prompt_found


def execute_command_in_shell(shell, command, command_description, timeout=COMMAND_TIMEOUT_SECONDS,
                             print_realtime_output: bool = True):
    """
    EXACT copy from your original working script with enhanced logging
    """
    logging.info(f"Sending '{command_description}' ('{command}')...")

    # Use your original buffer flushing approach
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
                f"Failed to reach bash prompt after '{command_description}' re-check. Output: {output + output_retry}")
    return True


def run_script_list_phase(shell, scripts_to_run, script_arg_option):
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
        logging.info(f"Sending 'python3 script execution' ('{command_to_execute}')...")
        shell.send(command_to_execute + "\n")
        time.sleep(0.3)

        logging.info(f"Waiting for '{script_name}' to finish (up to 10 minutes) and printing output in real-time...")
        script_output, prompt_found = read_and_print_realtime(shell, timeout_sec=600, print_realtime=True)

        all_scripts_raw_output.append((script_name, script_output))

        if not prompt_found:
            logging.warning(f"Prompt not detected within 600 seconds after running '{script_name}'.")
            logging.warning(f"The remote script might still be running, or the prompt format is unexpected.")
        else:
            logging.info(f"\033[1;92m✓ Prompt detected, '{script_name}' execution assumed complete.\033[0m")

        logging.info(f"{'=' * padding_len}--- Finished execution for: {script_name} ---{'=' * padding_len}")

    return all_scripts_raw_output


def extract_link_components(part_string):
    """Extracts LCx or FCx from a link component string."""
    lc_match = re.search(r'(\d+)/CPU(\d+)', part_string)
    if lc_match:
        return f"LC{lc_match.group(1)}"
    fc_match = re.search(r'FC(\d+)', part_string)
    if fc_match:
        return f"FC{fc_match.group(1)}"
    return part_string.strip()


def parse_and_print_errors(script_name, script_output):
    """Enhanced error parsing with better output coordination"""
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

    # Build the entire table output as a single string
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

    # Print the entire table as one block using true_original_stdout to bypass Tee
    table_output = "\n".join(table_output_lines)
    true_original_stdout.write(table_output + "\n")
    true_original_stdout.flush()

    # Log success message and track global error status
    global PHASE2_ERRORS_DETECTED
    if not errors_found:
        logging.info(f"\033[1;92m✓ No errors detected for Group {group_number}.\033[0m")
    else:
        PHASE2_ERRORS_DETECTED = True  # Set flag if any errors found
        logging.error(f"\033[1;91m✗ {len(errors_found)} errors detected for Group {group_number}.\033[0m")


def execute_script_phase(shell, scripts_to_run, script_arg_option):
    """Enhanced script phase execution"""
    try:
        logging.info(f"--- Initial Shell Output ---")
        initial_output, _ = read_and_print_realtime(shell, timeout_sec=2, print_realtime=False)
        print(f"{initial_output}", end='')
        print()
        logging.info(f"--- End Initial Shell Output ---\n")

        if not execute_command_in_shell(shell, "terminal length 0", "set terminal length to 0", timeout=5,
                                        print_realtime_output=False):
            raise RouterCommandError("Failed to set terminal length 0.")

        if not execute_command_in_shell(shell, "terminal width 511", "set terminal width to 511", timeout=5,
                                        print_realtime_output=False):
            raise RouterCommandError("Failed to set terminal width 511.")

        if not execute_command_in_shell(shell, "attach location 0/RP0/CPU0", "attach location 0/RP0/CPU0",
                                        timeout=COMMAND_TIMEOUT_SECONDS, print_realtime_output=False):
            raise RouterCommandError(f"Failed to establish bash prompt on router.")

        if not execute_command_in_shell(shell, "cd /misc/disk1/", "change directory to /misc/disk1/",
                                        timeout=COMMAND_TIMEOUT_SECONDS, print_realtime_output=False):
            raise RouterCommandError(f"Failed to change directory on router.")

        scripts_outputs = run_script_list_phase(shell, scripts_to_run, script_arg_option)

        if script_arg_option == "'--dummy' no":
            logging.info(
                f"\n{'=' * 70}\n### Analyzing 'dummy no' script outputs for errors ###\n{'=' * 70}\n")
            for s_name, s_output in scripts_outputs:
                parse_and_print_errors(s_name, s_output)

        return True

    except RouterCommandError as e:
        raise RouterCommandError(f"Router command failed: {e}")
    except Exception as e:
        raise ScriptExecutionError(f"An unexpected error occurred: {e}")


def get_hostname_from_router(router_ip, username, password):
    """Enhanced hostname retrieval with full hostname preservation"""
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        logging.info(f"Attempting to connect to {router_ip} to retrieve hostname...")
        connect_with_retry(client, router_ip, username, password)
        logging.info(f"Successfully connected to {router_ip} for hostname retrieval.")

        stdin, stdout, stderr = client.exec_command("show running | i hostname", timeout=COMMAND_TIMEOUT_SECONDS)
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
            raise HostnameRetrievalError(f"Hostname not found in command output: \n{output}")

        # Enhanced hostname processing - preserve full hostname
        sanitized_hostname = hostname.replace('.', '-')  # Only replace dots with dashes
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


def print_final_summary_table(phase_results: Dict[str, str], total_execution_time: float):
    """Enhanced final summary table with execution time and wrapped column headers"""
    print(f"\n--- Final Script Summary ---")

    # Format the execution time
    formatted_time = format_execution_time(total_execution_time)

    # Manual table creation to ensure proper formatting
    execution_time_text = f"Total time for execution: {formatted_time}"
    time_table_width = max(len(execution_time_text) + 4, 60)  # Minimum width of 60

    # Print execution time table
    time_separator = "+" + "-" * (time_table_width - 2) + "+"
    time_content = f"| {execution_time_text:<{time_table_width - 4}} |"

    print(time_separator)
    print(time_content)
    print(time_separator)

    # Create the main summary table using PrettyTable
    from prettytable import PrettyTable

    summary_table = PrettyTable()
    # Use multi-line header for Test number column
    summary_table.field_names = ["Test #", "Section Name", "Status"]

    # Center align Test number, left align others
    summary_table.align["Test #"] = "c"  # Center align for numbers
    summary_table.align["Section Name"] = "l"
    summary_table.align["Status"] = "l"

    def get_phase_status(section, original_status):
        """Determine the correct status based on phase logic"""
        global PHASE2_ERRORS_DETECTED

        if section == "Phase 1 Execution":
            if "Complete" in original_status:
                return "\033[1;94mCollection Only\033[0m"  # Bright Blue
            else:
                return f"\033[1;91m{original_status}\033[0m"  # Bright Red for failures

        elif section == "Phase 2 Execution":
            if "Complete" in original_status:
                if PHASE2_ERRORS_DETECTED:
                    return "\033[1;91mErrors Found\033[0m"  # Bright Red
                else:
                    return "\033[1;92mSuccessful\033[0m"  # Bright Green
            else:
                return f"\033[1;91m{original_status}\033[0m"  # Bright Red for failures

        else:
            # For any other sections, use default coloring
            if "Complete" in original_status or "Success" in original_status:
                return f"\033[1;92m{original_status}\033[0m"  # Bright Green
            elif "Failed" in original_status or "Error" in original_status:
                return f"\033[1;91m{original_status}\033[0m"  # Bright Red
            else:
                return original_status

    test_number = 1
    for section, status in phase_results.items():
        enhanced_status = get_phase_status(section, status)
        summary_table.add_row([str(test_number), section, enhanced_status])
        test_number += 1

    print(summary_table)
    logging.info(f"--- End Final Script Summary ---")


def connect_with_retry(client, router_ip, username, password, max_retries=3):
    """Retry SSH connection with increasing delays for problematic routers"""
    for attempt in range(max_retries):
        try:
            logging.info(f"Connection attempt {attempt + 1} of {max_retries}...")
            client.connect(
                router_ip,
                port=22,
                username=username,
                password=password,
                timeout=SSH_TIMEOUT_SECONDS,
                look_for_keys=False,
                allow_agent=False,
                banner_timeout=120,
                auth_timeout=120,
                disabled_algorithms={'keys': ['rsa-sha2-256', 'rsa-sha2-512']}
            )
            time.sleep(2)  # Let connection stabilize
            logging.info(f"Connection successful on attempt {attempt + 1}")
            return True
        except Exception as e:
            logging.warning(f"Connection attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                wait_time = (attempt + 1) * 5  # 5, 10, 15 seconds
                logging.info(f"Waiting {wait_time} seconds before retry...")
                time.sleep(wait_time)
            else:
                raise e
    return False


if __name__ == "__main__":
    # Enhanced main execution with execution time tracking
    session_log_file_handler = None
    raw_output_file = None
    true_original_stdout = sys.stdout

    # Record script start time
    script_start_time = time.time()

    # Clear existing handlers
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    router_hostname = "unknown_host"

    # Initial console handler with consistent timestamp format
    initial_console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s',
                                                  datefmt='%Y-%m-%d %H:%M:%S')
    initial_console_handler = logging.StreamHandler(true_original_stdout)
    initial_console_handler.setFormatter(initial_console_formatter)
    logging.root.addHandler(initial_console_handler)

    try:
        logging.info(f"--- IOS-XR Router Script Automation (Two-Phase Execution with Re-login) ---")
        ROUTER_IP = input(f"Enter Router IP address or Hostname: ")
        SSH_USERNAME = input(f"Enter SSH Username: ")
        SSH_PASSWORD = getpass.getpass(f"Enter SSH Password for {SSH_USERNAME}@{ROUTER_IP}: ")

        try:
            router_hostname = get_hostname_from_router(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD)
        except HostnameRetrievalError as e:
            logging.error(f"Could not retrieve hostname: {e}. Using IP address for log filename.")
            router_hostname = ROUTER_IP.replace('.', '-')

        hostname_dir = os.path.join(os.getcwd(), router_hostname)

        try:
            os.makedirs(hostname_dir, exist_ok=True)
            logging.info(f"Ensured router log directory exists: {os.path.abspath(hostname_dir)}")
        except OSError as e:
            logging.critical(
                f"Failed to create or access router log directory {hostname_dir}: {e}. Script cannot proceed without a log directory. Exiting.")
            sys.exit(1)

        timestamp_for_logs = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        session_log_path = os.path.join(hostname_dir,
                                        f"{router_hostname}_python_pre_check_session_log_{timestamp_for_logs}.txt")
        raw_output_log_path = os.path.join(hostname_dir,
                                           f"{router_hostname}_python_pre_check_output_{timestamp_for_logs}.txt")

        # Clear handlers and setup file logging
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)

        try:
            session_log_file_handler = logging.FileHandler(session_log_path)
            session_log_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s',
                                                                    datefmt='%Y-%m-%d %H:%M:%S'))
            logging.root.addHandler(session_log_file_handler)
            logging.info(f"Internal script logs will be saved to: {session_log_path}")
        except IOError as e:
            logging.error(
                f"Could not open internal session log file {session_log_path}: {e}. Internal logs will only go to console.")
            session_log_file_handler = None

        try:
            raw_output_file = open(raw_output_log_path, 'w', encoding='utf-8')
            sys.stdout = Tee(true_original_stdout, raw_output_file)
            logging.info(f"All console output (including router raw output) will be logged to: {raw_output_log_path}")
        except IOError as e:
            logging.error(
                f"Could not open raw output log file {raw_output_log_path}: {e}. Raw output will only go to console.")
            raw_output_file = None
            sys.stdout = true_original_stdout

        # Setup console handler with consistent timestamp format
        console_formatter = CompactFormatter()
        console_handler = logging.StreamHandler(true_original_stdout)
        console_handler.setFormatter(console_formatter)
        logging.root.addHandler(console_handler)

        logging.root.setLevel(logging.INFO)

        scripts_to_run = [
            "monitor_8800_system_v2_3_msft_bash_group0.py",
            "monitor_8800_system_v2_3_msft_bash_group1.py",
            "monitor_8800_system_v2_3_msft_bash_group2.py",
            "monitor_8800_system_v2_3_msft_bash_group3.py",
        ]

        script_aborted = False
        phase_results = {}

        # Phase 1 execution
        client_phase1 = None
        shell_phase1 = None
        try:
            logging.info(f"\n{'#' * 70}\n### Starting Phase 1: Running scripts with '--dummy' yes ###\n{'#' * 70}\n")
            client_phase1 = paramiko.SSHClient()
            client_phase1.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            logging.info(f"Attempting to connect to {ROUTER_IP} for Phase 1...")
            connect_with_retry(client_phase1, ROUTER_IP, SSH_USERNAME, SSH_PASSWORD)
            time.sleep(2)  # Wait for banner to complete
            logging.info(f"Successfully connected to {ROUTER_IP} for Phase 1.")

            shell_phase1 = client_phase1.invoke_shell()
            time.sleep(1)

            execute_script_phase(shell_phase1, scripts_to_run, "'--dummy' yes")

            phase_results["Phase 1 Execution"] = "Complete"
            logging.info(f"\033[1;92m✓ Phase 1 Complete. Waiting 20 minute before Phase 2...\033[0m")

        except paramiko.AuthenticationException as e:
            phase_results["Phase 1 Execution"] = "Failed (Authentication)"
            raise SSHConnectionError(
                f"Authentication failed during Phase 1. Please check your username and password. Error: {e}")
        except paramiko.SSHException as e:
            phase_results["Phase 1 Execution"] = "Failed (SSH Error)"
            raise SSHConnectionError(f"SSH error during Phase 1: {e}")
        except Exception as e:
            phase_results["Phase 1 Execution"] = "Failed (Unexpected Error)"
            raise ScriptExecutionError(f"An unexpected error occurred during Phase 1: {e}")
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

        # Countdown between phases
        countdown_timer(20 * 60, true_original_stdout)  # 20 minutes

        # Phase 2 execution
        client_phase2 = None
        shell_phase2 = None
        try:
            logging.info(f"\n{'#' * 70}\n### Starting Phase 2: Running scripts with '--dummy' no ###\n{'#' * 70}\n")
            client_phase2 = paramiko.SSHClient()
            client_phase2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            logging.info(f"Attempting to connect to {ROUTER_IP} for Phase 2...")
            connect_with_retry(client_phase2, ROUTER_IP, SSH_USERNAME, SSH_PASSWORD)
            time.sleep(2)  # Wait for banner to complete
            logging.info(f"Successfully connected to {ROUTER_IP} for Phase 2.")

            shell_phase2 = client_phase2.invoke_shell()
            time.sleep(1)

            execute_script_phase(shell_phase2, scripts_to_run, "'--dummy' no")

            phase_results["Phase 2 Execution"] = "Complete"
            logging.info(f"\033[1;92m✓ Phase 2 Complete.\033[0m")

        except paramiko.AuthenticationException as e:
            phase_results["Phase 2 Execution"] = "Failed (Authentication)"
            raise SSHConnectionError(
                f"Authentication failed during Phase 2. Please check your username and password. Error: {e}")
        except paramiko.SSHException as e:
            phase_results["Phase 2 Execution"] = "Failed (SSH Error)"
            raise SSHConnectionError(f"SSH error during Phase 2: {e}")
        except Exception as e:
            phase_results["Phase 2 Execution"] = "Failed (Unexpected Error)"
            raise ScriptExecutionError(f"An unexpected error occurred during Phase 2: {e}")
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

    except (SSHConnectionError, RouterCommandError, ScriptExecutionError) as e:
        logging.critical(f"\033[1;91m✗ Script execution failed: {e}\033[0m")
        script_aborted = True
        if "Phase 1 Execution" not in phase_results:
            phase_results["Phase 1 Execution"] = "Failed"
        if "Phase 2 Execution" not in phase_results:
            phase_results["Phase 2 Execution"] = "Failed"
    except Exception as e:
        logging.critical(f"\033[1;91m✗ An unhandled critical error occurred: {e}\033[0m", exc_info=True)
        script_aborted = True
        phase_results["Script Execution"] = "Failed (Critical Error)"
    finally:
        # Calculate total execution time
        total_execution_time = time.time() - script_start_time

        if script_aborted:
            logging.info(f"\033[1;91m--- Script Execution Aborted ---\033[0m")
        else:
            logging.info(f"\033[1;92m--- Script Execution Finished Successfully ---\033[0m")

        # Print final summary with execution time
        print_final_summary_table(phase_results, total_execution_time)

        # Restore stdout
        sys.stdout = true_original_stdout

        # Close file handlers
        if session_log_file_handler:
            logging.root.removeHandler(session_log_file_handler)
            session_log_file_handler.close()
            print(f"\nInternal session log closed: {session_log_path}")

        if raw_output_file:
            raw_output_file.close()
            print(f"Raw output log closed: {raw_output_log_path}")

        # Clean up logging handlers
        for handler in logging.root.handlers[:]:
            if isinstance(handler, logging.StreamHandler) and handler.stream == true_original_stdout:
                logging.root.removeHandler(handler)
                break

        print(f"\nTotal script execution time: {format_execution_time(total_execution_time)}")