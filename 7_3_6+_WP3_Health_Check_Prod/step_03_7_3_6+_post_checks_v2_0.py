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


# This script connects to a Cisco IOS-XR device via SSH to execute a comprehensive post-check process.
# It performs dataplane monitoring, script execution phases, show tech collection, and ASIC error clearing.
# The script incorporates comprehensive logging to manage console output and file recording.
#
# It performs the following actions:
# - Phase 1: Executes dummy scripts with '--dummy' yes
# - Dataplane monitoring phases (pre and post)
# - Phase 2 & 3: Executes dummy scripts with '--dummy' no (twice)
# - Concurrent show tech collection with countdown timer
# - ASIC error clearing operations
# - Comprehensive error analysis and reporting

__author__ = "Pronoy Dasgupta"
__copyright__ = "Copyright 2024 (C) Cisco Systems, Inc."
__credits__ = "Pronoy Dasgupta"
__version__ = "2.0.0"
__maintainer__ = "Pronoy Dasgupta"
__email__ = "prongupt@cisco.com"
__status__ = "production"

import paramiko
import time
import getpass
import re
import threading
from prettytable import PrettyTable
import datetime
import logging
#import platform
import os
import sys
from typing import Optional, List, Tuple, Dict, Any


# --- Constants and Configuration ---
SSH_TIMEOUT_SECONDS = 15
DATAPLANE_MONITOR_TIMEOUT_SECONDS = 1500  # 20 minutes
SHOW_TECH_MONITOR_TIMEOUT_SECONDS = 3600  # 60 minutes
COUNTDOWN_DURATION_MINUTES = 15
COMMAND_TIMEOUT_SECONDS = 30
SCRIPT_EXECUTION_TIMEOUT_SECONDS = 600

# Dual error tracking for two dummy no phases
PHASE2_ERRORS_DETECTED = False  # First dummy no run (Step 4)
PHASE3_ERRORS_DETECTED = False  # Second dummy no run (Step 7)

PROMPT_PATTERNS = [
    r'#\s*$',
    r'\$\s*$'
]

# Global variables to store show tech timing information
SHOW_TECH_START_TIMESTAMP_FROM_LOG: Optional[str] = None
SHOW_TECH_END_TIMESTAMP_FROM_LOG: Optional[str] = None

# Global variables for session log files (for existing functionality)
session_log_file_console_mirror = None
session_log_file_raw_output = None


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


class HostnameRetrievalError(Exception):
    """Custom exception for failures during hostname retrieval."""
    pass


# --- Enhanced Logging Classes ---
class CompactFormatter(logging.Formatter):
    """Enhanced formatter with bright colors and timestamps for status messages"""

    def __init__(self):
        super().__init__(datefmt='%Y-%m-%d %H:%M:%S')

    FORMATS = {
        logging.ERROR: '%(asctime)s - \033[91m%(levelname)s\033[0m - %(message)s',
        logging.WARNING: '%(asctime)s - \033[93m%(levelname)s\033[0m - %(message)s',
        logging.INFO: '%(asctime)s - %(levelname)s - %(message)s',
        logging.CRITICAL: '%(asctime)s - \033[91m%(levelname)s\033[0m - %(message)s',
        logging.DEBUG: '%(asctime)s - %(levelname)s - %(message)s',
    }

    def format(self, record):
        msg = record.getMessage()
        if msg.startswith('✓ ') and 'passed' in msg:
            return f'{self.formatTime(record, self.datefmt)} - \033[92m{record.levelname}\033[0m - \033[1;92m{msg}\033[0m'
        elif msg.startswith('✗ ') and 'failed:' in msg:
            return f'{self.formatTime(record, self.datefmt)} - \033[91m{record.levelname}\033[0m - \033[1;91m{msg}\033[0m'
        else:
            log_fmt = self.FORMATS.get(record.levelno, '%(asctime)s - %(levelname)s - %(message)s')
            formatter = logging.Formatter(log_fmt, datefmt=self.datefmt)
            return formatter.format(record)


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


# --- Enhanced Connection Function ---
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


# --- Enhanced Helper Functions ---
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


def colorful_countdown_timer(seconds: int):
    """Displays a countdown timer on the console."""
    logging.info(f'Colorful Countdown Timer: Starting for {seconds // 60:02d}:{seconds % 60:02d}.')

    while seconds:
        mins, secs = divmod(seconds, 60)
        timer = f'{mins:02d}:{secs:02d}'
        print(f'\rWaiting... {timer} remaining', end='', flush=True)
        time.sleep(1)
        seconds -= 1
    print(f'\rWaiting... 00:00 - Time is up! ')


def read_and_print_realtime(shell_obj: paramiko.Channel, timeout_sec: int = 600, print_realtime: bool = True) -> Tuple[
    str, bool]:
    """Enhanced version with proper dot handling and global file logging"""
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
    """Enhanced command execution with proper logging format"""
    logging.info(f"Sending '{command_description}' ('{command}')...")

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
    """Enhanced script execution"""
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


# --- Parsing and Utility Functions (PRESERVED) ---
def parse_version_string(version_str: str) -> Tuple[int, ...]:
    """Parses a version string (e.g., "7.3.5") into a tuple of integers (e.g., (7, 3, 5))."""
    return tuple(map(int, version_str.split('.')))


def get_ios_xr_version(shell: paramiko.Channel) -> str:
    """Retrieves the IOS-XR version from the router."""
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
    """Enhanced hostname retrieval with full hostname preservation"""
    logging.info("Attempting to retrieve hostname using 'show running-config | i hostname'...")
    shell.send("show running-config | i hostname\n")
    output, prompt_found = read_and_print_realtime(shell, timeout_sec=10, print_realtime=False)
    print()

    for line in output.splitlines():
        match = re.search(r"^\s*hostname\s+(\S+)", line)
        if match:
            hostname = match.group(1)
            hostname = hostname.replace('.', '-')  # Only replace dots with dashes
            logging.info(f"Full hostname detected from 'show running-config': {hostname}")
            return hostname

    if prompt_found:
        prompt_match = re.search(r'[:>](\S+)[#$]', output)
        if prompt_match:
            hostname = prompt_match.group(1)
            hostname = hostname.replace('.', '-')
            logging.info(f"Hostname detected from prompt: {hostname}")
            return hostname

    logging.warning(
        "Could not parse hostname from 'show running-config | i hostname' output or from prompt. Using 'unknown_host'.")
    return "unknown_host"


def get_hostname_from_router(router_ip, username, password):
    """Enhanced hostname retrieval with retry mechanism"""
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


def get_router_timestamp(shell: paramiko.Channel) -> datetime.datetime:
    """Gets the current timestamp from the router using 'show clock'."""
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


# --- Dataplane Monitoring Functions (PRESERVED) ---
def poll_dataplane_monitoring_736(shell: paramiko.Channel, max_poll_duration_sec: int) -> bool:
    """PRESERVED - Dataplane monitoring for IOS-XR 7.3.6+"""
    logging.info(f"Running 'monitor dataplane' command (IOS-XR 7.3.6+)...")
    shell.send("monitor dataplane\n")
    time.sleep(2)

    logging.info("Waiting for initial 'monitor dataplane' output to complete and prompt to return...")
    initial_dataplane_output, prompt_found_after_dataplane = read_and_print_realtime(shell, timeout_sec=30,
                                                                                     print_realtime=True)
    if not prompt_found_after_dataplane:
        logging.warning(
            "Prompt not detected after initial 'monitor dataplane' output. Attempting to send newline and re-check.")
        shell.send("\n")
        retry_output, prompt_found_after_dataplane = read_and_print_realtime(shell, timeout_sec=5, print_realtime=True)
        initial_dataplane_output += retry_output
        if not prompt_found_after_dataplane:
            raise RouterCommandError(
                f"Failed to reach prompt after 'monitor dataplane' command. Output: {initial_dataplane_output}")
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


def parse_dataplane_output_for_errors(output_text: str) -> bool:
    """PRESERVED - Parses dataplane output for errors - COMPLETE VERSION"""
    errors_found = []
    explicit_failures_detected = False

    # Check for explicit failure messages but DON'T return yet
    if "Loss detected:" in output_text or "FAILURES DETECTED IN DATAPATH" in output_text:
        logging.error("!!! EXPLICIT DATAPLANE FAILURES DETECTED IN OUTPUT !!!")
        logging.error("Loss detected or failures explicitly mentioned in dataplane output.")
        explicit_failures_detected = True

    # ALWAYS parse tabular data for non-zero values (even if explicit failures found)
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

                # Update current LC/NP context
                if lc_str is not None and lc_str.strip():
                    current_lc = int(lc_str)
                if np_str is not None and np_str.strip():
                    current_np = int(np_str)

                lc = current_lc if current_lc is not None else "N/A"
                npu = current_np if current_np is not None else "N/A"

                slice_val = int(slice_str)
                good_val = int(good_str)
                loss = int(loss_str)
                corrupt = int(corrupt_str)
                error = int(error_str)

                # Check for non-zero LOSS, CORRUPT, or ERROR values
                if loss > 0 or corrupt > 0 or error > 0:
                    errors_found.append({
                        "LC": lc, "NPU": npu, "Slice": slice_val,
                        "GOOD": good_val, "LOSS": loss, "CORRUPT": corrupt, "ERROR": error
                    })

    # Show tabular errors if found
    if errors_found:
        logging.error("!!! DATAPLANE ERRORS DETECTED IN TABULAR DATA !!!")
        table = PrettyTable()
        table.field_names = ["LC", "NPU", "Slice", "GOOD", "LOSS", "CORRUPT", "ERROR"]
        for err in errors_found:
            table.add_row([err["LC"], err["NPU"], err["Slice"], err["GOOD"], err["LOSS"], err["CORRUPT"], err["ERROR"]])
        logging.error(f"\n{table}")
        logging.error("!!! Please investigate the reported non-zero values. !!!")

    # Return False if EITHER explicit failures OR tabular errors detected
    if explicit_failures_detected or errors_found:
        return False
    else:
        logging.info("Dataplane output check: No LOSS, CORRUPT, or ERROR detected.")
        return True


# --- Error Parsing Functions (ENHANCED) ---
def get_group_number_from_script_name(script_name: str) -> str:
    """Extracts the group number from the script name."""
    match = re.search(r'group(\d+)\.py', script_name)
    return match.group(1) if match else "N/A"


def extract_link_components(part_string):
    """Extracts LCx or FCx from a link component string."""
    lc_match = re.search(r'(\d+)/CPU(\d+)', part_string)
    if lc_match:
        return f"LC{lc_match.group(1)}"
    fc_match = re.search(r'FC(\d+)', part_string)
    if fc_match:
        return f"FC{fc_match.group(1)}"
    return part_string.strip()


def parse_script_output_for_errors(script_name: str, script_output: str) -> List[Dict[str, str]]:
    """PRESERVED - Parses script output for faulty link details"""
    errors_found_details = []

    faulty_link_pattern = re.compile(
        r"Link\s+(.*?)\s+---\s+(.*?)\s+between\s+(.*?)\s+and\s+(.*?)\s+is faulty\s+-\s+codewords\s+(.*?),\s+BER\s+([\d.e-]+)\s+FLR\s+([\d\.e-]+)\s+RX Link Down Count\s+(\d+)"
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
            i = j - 1
        i += 1

    return errors_found_details


def format_and_print_error_report(script_name: str, group_number: str, error_details: List[Dict[str, str]], phase_name: str = ""):
    """Enhanced error reporting with consistent table format matching Part II"""
    # Track errors globally for final summary
    global PHASE2_ERRORS_DETECTED, PHASE3_ERRORS_DETECTED

    phase_identifier = f" ({phase_name})" if phase_name else ""

    # Use EXACT same table formatting as Part II - manual column widths
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

    table_output_lines = []
    table_output_lines.append(f"\n--- Error Report for {script_name}{phase_identifier} ---")
    table_output_lines.append(f"Reference Thresholds: BER < 1e-08, FLR < 1e-21")
    table_output_lines.append(f"{separator_line}")
    table_output_lines.append(f"{header}")
    table_output_lines.append(f"{separator_line}")

    if not error_details:
        # CONSISTENT: Use same table format with blank row for no errors
        blank_row_cols = [
            f"{'':<{col_widths['Link Connection']}}",
            f"{group_number:<{col_widths['Group_number']}}",
            f"{'':<{col_widths['Codewords']}}",
            f"{'':<{col_widths['FLR']}}",
            f"{'':<{col_widths['BER']}}",
            f"{'':<{col_widths['Link_flap']}}"
        ]
        table_output_lines.append(f"| {' | '.join(blank_row_cols)} |")
        logging.info(f"\033[1;92m✓ No errors detected for Group {group_number}{phase_identifier}.\033[0m")
    else:
        # Set appropriate global error flag
        if "Phase 2" in phase_name:
            PHASE2_ERRORS_DETECTED = True
        elif "Phase 3" in phase_name:
            PHASE3_ERRORS_DETECTED = True

        for detail in error_details:
            # OPTION A: Simplified link format (extract FC and LC)
            link_full = detail['Link Connection']

            # Extract FC and LC information to match Part II format
            fc_match = re.search(r'0/FC(\d+)', link_full)
            lc_match = re.search(r'0/(\d+)/CPU0', link_full)

            if fc_match and lc_match:
                simplified_link = f"FC{fc_match.group(1)} - LC{lc_match.group(1)}"  # ← CORRECT FORMAT (space + dash)
            else:
                # Fallback to original if pattern doesn't match
                simplified_link = link_full[:25] + "..." if len(link_full) > 25 else link_full

            # DETAILED FORMAT (matching Part II): Show values when Bad
            codewords_display = detail.get('Codewords_Status', 'Good') if detail.get(
                'Codewords_Status') != 'BAD' else "Bad"

            if detail.get('FLR_Status') == 'BAD':
                flr_display = f"Bad ({detail.get('FLR', 'N/A')})"
            else:
                flr_display = "Good"

            if detail.get('BER_Status') == 'BAD':
                ber_display = f"Bad ({detail.get('BER', 'N/A')})"
            else:
                ber_display = "Good"

            # Link flap shows actual count when > 0
            link_flap_count = int(detail.get('Link_flap', '0'))
            link_flap_display = str(link_flap_count) if link_flap_count > 0 else ""

            row_cols = [
                f"{simplified_link:<{col_widths['Link Connection']}}",
                f"{group_number:<{col_widths['Group_number']}}",
                f"{codewords_display:<{col_widths['Codewords']}}",
                f"{flr_display:<{col_widths['FLR']}}",
                f"{ber_display:<{col_widths['BER']}}",
                f"{link_flap_display:<{col_widths['Link_flap']}}"
            ]
            table_output_lines.append(f"| {' | '.join(row_cols)} |")

        logging.error(f"\033[1;91m✗ {len(error_details)} errors detected for Group {group_number}{phase_identifier}.\033[0m")

    table_output_lines.append(f"{separator_line}")

    # Print the entire table as one block
    table_output = "\n".join(table_output_lines)
    print(table_output)


def wait_for_prompt_after_ctrlc(shell: paramiko.Channel, timeout_sec: int = 60) -> bool:
    """PRESERVED - Waits for shell prompt after Ctrl+C"""
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


# --- Show Tech Functions (PRESERVED) ---
def run_show_tech_fabric_threaded(shell: paramiko.Channel, hostname: str,
                                  show_tech_finished_event: threading.Event,
                                  result_dict: Dict) -> None:
    """PRESERVED - Show tech fabric collection in thread"""
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

        if not execute_command_in_shell(shell, "cd /misc/disk1/", "change directory to /misc/disk1/", timeout=10,
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

        try:
            shell.send("\x03")
        except Exception as e:
            logging.warning(f"Error sending Ctrl+C to shell: {e}")

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


# --- Phase Execution Functions (ENHANCED) ---
def run_dataplane_monitor_phase(router_ip: str, username: str, password: str, monitor_description: str,
                                ssh_timeout: int, dataplane_timeout: int) -> bool:
    """PRESERVED - Dataplane monitoring phase with enhanced connection"""
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    shell = None
    try:
        logging.info(f"Connecting to {router_ip} for {monitor_description} dataplane monitor...")
        connect_with_retry(client, router_ip, username, password)
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

        if dataplane_check_clean:
            logging.info(
                f"\033[1;92m✓ {monitor_description} Dataplane monitoring completed and reported no errors.\033[0m")
            return True
        else:
            logging.error(
                f"\033[1;91m✗ {monitor_description} Dataplane monitoring completed, but errors were reported.\033[0m")
            raise DataplaneError(f"Dataplane errors detected during {monitor_description} monitor.")

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
                logging.warning(f"Error during graceful shell exit in {monitor_description} monitor: {e}")
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
    """PRESERVED - Concurrent countdown and show tech with enhanced connection"""
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    shell = None
    try:
        logging.info(f"Connecting to {router_ip} for Concurrent Countdown and Show Tech...")
        connect_with_retry(client, router_ip, username, password)
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
        logging.info(f"\033[1;92m✓ {countdown_duration_minutes}-minute countdown timer has finished.\033[0m")

        show_tech_thread.join()
        logging.info(f"\033[1;92m✓ Show tech collection has finished.\033[0m")

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
        logging.error(f"An unexpected error occurred during concurrent tasks phase: {e}", exc_info=True)
        raise Exception(f"An unexpected error occurred during concurrent tasks phase: {e}")
    finally:
        if shell:
            logging.info("Attempting to gracefully exit CLI session after concurrent tasks phase.")
            try:
                shell.send("exit\n")
                time.sleep(1)
                while shell.recv_ready():
                    shell.recv(65535).decode('utf-8', errors='ignore')
            except Exception as e:
                logging.warning(f"Error during graceful shell exit attempt: {e}")
            finally:
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
                         script_arg_option: str, ssh_timeout: int, phase_name: str = "") -> bool:
    """Enhanced script phase execution with phase tracking"""
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    shell = None
    try:
        logging.info(f"Attempting to connect to {router_ip} for phase with option '{script_arg_option}'...")
        connect_with_retry(client, router_ip, username, password)
        logging.info(f"Successfully connected to {router_ip}.")

        shell = client.invoke_shell()
        time.sleep(1)
        logging.info("--- Initial Shell Output ---")
        initial_output, _ = read_and_print_realtime(shell, timeout_sec=2, print_realtime=False)
        print(f"{initial_output}", end='')
        print()
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

        if not execute_command_in_shell(shell, "cd /misc/disk1/", "change directory to /misc/disk1/", timeout=10,
                                        print_realtime_output=False):
            raise RouterCommandError("Failed to change directory on router.")

        scripts_outputs = run_script_list_phase(shell, scripts_to_run, script_arg_option)

        if script_arg_option == "'--dummy' no":
            logging.info(f"\n{'=' * 70}\n### Analyzing 'dummy no' script outputs for errors ###\n{'=' * 70}\n")
            errors_found_in_dummy_no = False  # Initialize the variable
            for s_name, s_output in scripts_outputs:
                group_num = get_group_number_from_script_name(s_name)
                detailed_errors = parse_script_output_for_errors(s_name, s_output)
                format_and_print_error_report(s_name, group_num, detailed_errors, phase_name)
                if detailed_errors:
                    errors_found_in_dummy_no = True

            # Add the error check that stops execution with intuitive message
            if errors_found_in_dummy_no:
                raise ScriptExecutionError("Degraded links found")

        return True

    except paramiko.AuthenticationException as e:
        raise SSHConnectionError(f"Authentication failed for script phase '{script_arg_option}': {e}")
    except paramiko.SSHException as e:
        raise SSHConnectionError(f"SSH error during script phase '{script_arg_option}': {e}")
    except RouterCommandError as e:
        raise RouterCommandError(f"Router command error during script phase '{script_arg_option}': {e}")
    except Exception as e:
        if script_arg_option == "'--dummy' no":
            # Check if it's our specific degraded links error
            if "Degraded links found" in str(e):
                raise ScriptExecutionError("Degraded links found")
            else:
                raise ScriptExecutionError(f"Script analysis failed during dummy no phase: {e}")
        else:
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
                logging.warning(f"Error during graceful shell exit in script phase: {e}")
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
    """PRESERVED - ASIC errors show command with enhanced connection"""
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    shell = None
    try:
        logging.info(f"Connecting to {router_ip} to run asic_errors_show command...")
        connect_with_retry(client, router_ip, username, password)
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
                logging.warning(f"Error during graceful shell exit after asic_errors_show: {e}")
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


def format_execution_time(seconds):
    """Format execution time in human-readable format"""
    hours, remainder = divmod(int(seconds), 3600)  # 3600 seconds = 1 hour
    minutes, seconds = divmod(remainder, 60)  # 60 seconds = 1 minute

    if hours > 0:
        return f"{hours:02d}h {minutes:02d}m {seconds:02d}s"  # e.g., "01h 23m 45s"
    elif minutes > 0:
        return f"{minutes:02d}m {seconds:02d}s"  # e.g., "23m 45s"
    else:
        return f"{seconds:02d}s"  # e.g., "45s"


def print_final_summary_table(results_summary: Dict[str, str], total_execution_time: float):
    """Enhanced final summary table with execution time and wrapped column headers"""
    print(f"\n--- Final Script Summary ---")

    # Format the execution time
    formatted_time = format_execution_time(total_execution_time)

    # Print execution time table
    execution_time_text = f"Total time for execution: {formatted_time}"
    time_table_width = max(len(execution_time_text) + 4, 60)

    time_separator = "+" + "-" * (time_table_width - 2) + "+"
    time_content = f"| {execution_time_text:<{time_table_width - 4}} |"

    print(time_separator)
    print(time_content)
    print(time_separator)

    # Main summary table
    summary_table = PrettyTable()
    # Use multi-line header for Test number column
    summary_table.field_names = ["Test #", "Section Name", "Status"]

    # Center align Test number, left align others
    summary_table.align["Test #"] = "c"  # Center align for numbers
    summary_table.align["Section Name"] = "l"
    summary_table.align["Status"] = "l"

    def get_enhanced_status(step_name, original_status):
        """Determine status with Part III specific logic"""
        global PHASE2_ERRORS_DETECTED, PHASE3_ERRORS_DETECTED

        if "Phase 1" in original_status and "Success" in original_status:
            return "\033[1;94mCollection Only\033[0m"  # Bright Blue
        elif "Phase 2 (Dummy No)" in original_status and "Success" in original_status:
            if PHASE2_ERRORS_DETECTED:
                return "\033[1;91mErrors Found\033[0m"  # Bright Red
            else:
                return "\033[1;92mSuccessful\033[0m"  # Bright Green
        elif "Final Dummy No" in original_status and "Success" in original_status:
            if PHASE3_ERRORS_DETECTED:
                return "\033[1;91mErrors Found\033[0m"  # Bright Red
            else:
                return "\033[1;92mSuccessful\033[0m"  # Bright Green
        elif "Success" in original_status:
            return f"\033[1;92m{original_status.split(': ')[1]}\033[0m"  # Bright Green
        elif "Failed" in original_status:
            return f"\033[1;91m{original_status.split(': ')[1]}\033[0m"  # Bright Red
        else:
            return original_status.split(': ')[1] if ': ' in original_status else original_status

    test_number = 1
    for step_name, result in results_summary.items():
        section_name = result.split(': ')[0] if ': ' in result else result
        enhanced_status = get_enhanced_status(step_name, result)
        summary_table.add_row([str(test_number), section_name, enhanced_status])
        test_number += 1

    print(summary_table)
    logging.info(f"--- End Final Script Summary ---")


# --- Main execution block ---
if __name__ == "__main__":
    # Record script start time
    script_start_time = time.time()
    # Enhanced main execution with consistent formatting
    session_log_file_handler = None
    raw_output_file = None
    true_original_stdout = sys.stdout

    # Clear existing handlers
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    router_hostname = "unknown_host"

    # Initial console handler
    initial_console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    initial_console_handler = logging.StreamHandler(true_original_stdout)
    initial_console_handler.setFormatter(initial_console_formatter)
    logging.root.addHandler(initial_console_handler)

    try:
        logging.info(f"--- IOS-XR Router Automation Script (Part III - Post Checks) ---")
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
                                        f"{router_hostname}_7_3_6+_post-checks_session_log_{timestamp_for_logs}.txt")
        raw_output_log_path = os.path.join(hostname_dir,
                                           f"{router_hostname}_7_3_6+_post-checks_output_{timestamp_for_logs}.txt")

        # Clear handlers and setup enhanced logging
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)

        try:
            session_log_file_handler = logging.FileHandler(session_log_path)
            session_log_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            logging.root.addHandler(session_log_file_handler)
            logging.info(f"Internal script logs will be saved to: {session_log_path}")
        except IOError as e:
            logging.error(f"Could not open internal session log file {session_log_path}: {e}.")
            session_log_file_handler = None

        try:
            raw_output_file = open(raw_output_log_path, 'w', encoding='utf-8')
            sys.stdout = Tee(true_original_stdout, raw_output_file)
            logging.info(f"All console output will be logged to: {raw_output_log_path}")
        except IOError as e:
            logging.error(f"Could not open raw output log file {raw_output_log_path}: {e}.")
            raw_output_file = None
            sys.stdout = true_original_stdout

        # Setup global file logging for existing functionality
        try:
            session_log_file_console_mirror = open(session_log_path.replace('session_log', 'console_mirror'), 'w',
                                                   encoding='utf-8')
            session_log_file_raw_output = open(raw_output_log_path.replace('output', 'raw_output'), 'w',
                                               encoding='utf-8')
        except IOError:
            session_log_file_console_mirror = None
            session_log_file_raw_output = None

        # Setup enhanced console handler with timestamps
        console_formatter = CompactFormatter()
        console_formatter.datefmt = '%Y-%m-%d %H:%M:%S'
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

        results_summary: Dict[str, str] = {}
        script_aborted = False

        # Step 1: Phase 1: Dummy Yes
        logging.info(
            f"\n{'#' * 70}\n### Step 1: Starting Phase 1: Running scripts with '--dummy' yes ###\n{'#' * 70}\n")
        execute_script_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, scripts_to_run, "'--dummy' yes",
                             SSH_TIMEOUT_SECONDS, "Phase 1")
        results_summary["Step 1"] = "Phase 1 (Dummy Yes): Success"
        logging.info(f"\033[1;92m✓ Phase 1 completed successfully.\033[0m")

        # Step 2: Monitor Dataplane (First instance)
        logging.info(f"\n{'#' * 70}\n### Step 2: Running First Dataplane Monitor ###\n{'#' * 70}\n")
        run_dataplane_monitor_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, "FIRST", SSH_TIMEOUT_SECONDS,
                                    DATAPLANE_MONITOR_TIMEOUT_SECONDS)
        results_summary["Step 2"] = "First Dataplane Monitor: Success"
        logging.info(f"\033[1;92m✓ First Dataplane Monitor completed successfully.\033[0m")

        # Step 3: Wait 15 minutes (Sequential timer)
        logging.info(
            f"\n{'#' * 70}\n### Step 3: Starting Sequential {COUNTDOWN_DURATION_MINUTES}-minute Countdown ###\n{'#' * 70}\n")
        colorful_countdown_timer(COUNTDOWN_DURATION_MINUTES * 60)
        results_summary["Step 3"] = "Sequential 15-minute Countdown: Success"
        logging.info(f"\033[1;92m✓ Sequential {COUNTDOWN_DURATION_MINUTES}-minute countdown finished.\033[0m")

        # Step 4: Phase 2: Dummy no (First dummy no run)
        logging.info(f"\n{'#' * 70}\n### Step 4: Starting Phase 2: Running scripts with '--dummy' no ###\n{'#' * 70}\n")
        execute_script_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, scripts_to_run, "'--dummy' no",
                             SSH_TIMEOUT_SECONDS, "Phase 2")
        results_summary["Step 4"] = "Phase 2 (Dummy No): Success"
        logging.info(f"\033[1;92m✓ Phase 2 completed successfully.\033[0m")

        # Step 5: Monitor dataplane (Second instance)
        logging.info(f"\n{'#' * 70}\n### Step 5: Running Second Dataplane Monitor ###\n{'#' * 70}\n")
        run_dataplane_monitor_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, "SECOND", SSH_TIMEOUT_SECONDS,
                                    DATAPLANE_MONITOR_TIMEOUT_SECONDS)
        results_summary["Step 5"] = "Second Dataplane Monitor: Success"
        logging.info(f"\033[1;92m✓ Second Dataplane Monitor completed successfully.\033[0m")

        # Step 6: Concurrent 15-minute timer and show tech collection
        logging.info(
            f"\n{'#' * 70}\n### Step 6: Starting Concurrent {COUNTDOWN_DURATION_MINUTES}-minute Countdown and Show Tech Collection ###\n{'#' * 70}\n")
        concurrent_success = run_concurrent_countdown_and_show_tech(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD,
                                                                    SSH_TIMEOUT_SECONDS, COUNTDOWN_DURATION_MINUTES,
                                                                    SHOW_TECH_MONITOR_TIMEOUT_SECONDS)
        if concurrent_success:
            results_summary["Step 6"] = "Concurrent 15-minute Countdown and Show Tech: Success"
            logging.info(f"\033[1;92m✓ Concurrent countdown and show tech phase completed successfully.\033[0m")
        else:
            results_summary["Step 6"] = "Concurrent 15-minute Countdown and Show Tech: Failed - Show tech issue"
            logging.critical(
                f"\033[1;91m✗ Concurrent countdown and show tech phase failed due to show tech issue.\033[0m")
            raise ShowTechError("Show tech collection failed during concurrent tasks phase.")

        # Step 7: Final Dummy No Run (Phase 3)
        logging.info(
            f"\n{'#' * 70}\n### Step 7: Starting Phase 3: Running scripts with '--dummy' no again ###\n{'#' * 70}\n")
        execute_script_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, scripts_to_run, "'--dummy' no",
                             SSH_TIMEOUT_SECONDS, "Phase 3")
        results_summary["Step 7"] = "Final Dummy No: Success"
        logging.info(f"\033[1;92m✓ Final 'dummy no' phase completed successfully.\033[0m")

        # Step 8: Run asic_errors_show command
        logging.info(f"\n{'#' * 70}\n### Step 8: Running asic_errors_show command ###\n{'#' * 70}\n")
        run_asic_errors_show_command(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, SSH_TIMEOUT_SECONDS)
        results_summary["Step 8"] = "asic_errors_show Command: Success"
        logging.info(f"\033[1;92m✓ asic_errors_show command completed successfully.\033[0m")

    except (SSHConnectionError, RouterCommandError, ScriptExecutionError, DataplaneError, ShowTechError,
            AsicErrorShowError) as e:
        logging.critical(f"\033[1;91m✗ Script execution failed and aborted: {e}\033[0m")
        script_aborted = True
        # Add appropriate failed status to results_summary based on where it failed
        if "Step 1" not in results_summary:
            results_summary["Step 1"] = f"Phase 1 (Dummy Yes): Failed - {e}"
        elif "Step 2" not in results_summary:
            results_summary["Step 2"] = f"First Dataplane Monitor: Failed - {e}"
        elif "Step 3" not in results_summary:
            results_summary["Step 3"] = f"Sequential 15-minute Countdown: Failed - {e}"
        elif "Step 4" not in results_summary:
            results_summary["Step 4"] = f"Phase 2 (Dummy No): Failed - {e}"
        elif "Step 5" not in results_summary:
            results_summary["Step 5"] = f"Second Dataplane Monitor: Failed - {e}"
        elif "Step 6" not in results_summary:
            results_summary["Step 6"] = f"Concurrent 15-minute Countdown and Show Tech: Failed - {e}"
        elif "Step 7" not in results_summary:
            results_summary["Step 7"] = f"Final Dummy No: Failed - {e}"
        else:
            results_summary["Step 8"] = f"asic_errors_show Command: Failed - {e}"
    except Exception as e:
        logging.critical(f"\033[1;91m✗ An unhandled critical error occurred: {e}\033[0m", exc_info=True)
        script_aborted = True
        results_summary["Critical Error"] = f"Unhandled Error: {e}"
    finally:
        if script_aborted:
            logging.info(f"\033[1;91m--- Script Execution Aborted ---\033[0m")
        else:
            logging.info(f"\033[1;92m--- Script Execution Finished Successfully ---\033[0m")

        # Print final summary
        # Calculate total execution time
        total_execution_time = time.time() - script_start_time

        # Print final summary with execution time
        print_final_summary_table(results_summary, total_execution_time)
        logging.info(f"--- Script Execution Finished ---")

        # Restore stdout
        sys.stdout = true_original_stdout