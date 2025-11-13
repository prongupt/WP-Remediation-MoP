#!/usr/bin/env python3
import sys
import os
import platform
import subprocess
from pathlib import Path


# Architecture detection and re-execution logic
def ensure_compatible_environment():
    """Ensure script runs with architecture-compatible dependencies."""
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

    # Need to create venv and install dependencies
    print(f"Setting up {arch}-compatible environment...")
    print(f"This is a one-time setup and may take a minute...\n")

    try:
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
        print(f"Error setting up environment: {e}")
        print("Attempting to run with system Python...")
        # Continue with system Python as fallback


# Run environment check before any other imports
ensure_compatible_environment()


# This script connects to a Cisco IOS-XR device via SSH to perform a comprehensive health check and comparison.
# It performs the following actions:
# - Establishes an SSH connection and configures terminal settings.
# - Gathers device information such as hostname, chassis model, and IOS-XR version.
# - Executes a series of 'show' commands to collect operational data, including:
#   - Platform status and serial numbers of cards (LCs, FCs, RPs, FTs).
#   - Fabric reachability and link down status.
#   - NPU link information, statistics (UCE/CRC errors), and driver status (ASIC states).
#   - Fabric plane statistics (CE/UCE/PE packets).
#   - ASIC errors on RP0 and Line Cards.
#   - Interface status (summary and brief).
#   - Active alarms (excluding optics/coherent) and install logs.
#   - Fan tray status, including checks for impacted versions and power issues.
#   - Overall environment status (temperature, voltage, power supply).
# - Logs all executed commands and their outputs to a file.
# - Parses the collected data to identify and report potential issues or anomalies for each check.
# - Compares the current device state against a permanent baseline (the earliest saved CLI output file) for:
#   - Optics inventory changes (missing, new, or moved optics).
#   - Hardware changes (LC/FC/RP serial number changes, additions, or removals).
#   - Physical interface status changes (interfaces going down or coming up).
#   - FPD (Field-Programmable Device) status changes.
# - Reports physical interfaces that were found to be operationally down during the current run.
# - Provides a final summary table of all checks and their outcomes.

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
import logging
from prettytable import PrettyTable
import datetime
import os
import sys
from typing import List, Tuple, Dict, Any, Optional, Callable
from functools import wraps
from io import StringIO
from dataclasses import dataclass
from contextlib import contextmanager

# === CONFIGURATION ===
SSH_TIMEOUT_SECONDS = 15
PROMPT_PATTERNS = [
    r'#\s*$',
    r'>\s*$',
    r'\]\s*$',
    r'\)\s*$'
]

FAN_IMPACTED_VERSIONS = {
    "8804-FAN": {"Not Impacted": ["V03"], "Impacted": ["V01", "V02"]},
    "8808-FAN": {"Not Impacted": ["V03"], "Impacted": ["V01", "V02"]},
    "8812-FAN": {"Not Impacted": ["V02"], "Impacted": ["V01"]},
    "8818-FAN": {"Not Impacted": ["V03"], "Impacted": ["V01", "V02"]},
}


# === CUSTOM EXCEPTIONS ===
class DeviceError(Exception):
    """Base exception for device errors"""
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


# === DATA CLASSES ===
@dataclass
class DeviceInfo:
    hostname: str = "unknown_host"
    chassis_model: str = "unknown_chassis"
    ios_version: str = "N/A"


@dataclass
class CheckResult:
    passed: bool
    message: str = ""
    data: Any = None


# === PROGRESS BAR ===
class SimpleProgressBar:
    _active_pbar = None

    def __init__(self, total, original_console_stream, description="", color_code='\033[94m'):
        self.total = total
        self.current = 0
        self.description = description
        self.color_code = color_code
        self.original_console_stream = original_console_stream
        self.start_time = time.time()
        self.bar_length = 50
        self._last_pbar_line_length = 0
        self.update_display()

    def update(self, step=1):
        self.current += step
        if self.current > self.total:
            self.current = self.total
        self.update_display()

    def update_display(self):
        percent = ("{0:.1f}").format(100 * (self.current / float(self.total)))
        filled_length = int(self.bar_length * self.current // self.total)
        bar = '█' * filled_length + '-' * (self.bar_length - filled_length)

        elapsed_time = time.time() - self.start_time

        estimated_remaining_time_str = "--:--"
        if self.current > 0 and self.current < self.total:
            avg_time_per_step = elapsed_time / self.current
            remaining_steps = self.total - self.current
            estimated_remaining_time = avg_time_per_step * remaining_steps
            estimated_remaining_time_str = self._format_time(estimated_remaining_time)
        elif self.current == self.total:
            estimated_remaining_time_str = "00:00"

        time_info = f"[{self._format_time(elapsed_time)}<{estimated_remaining_time_str}]"

        pbar_message = f"{self.color_code}{self.description} |{bar}| {percent}% {time_info}\033[0m"
        self.original_console_stream.write('\r' + ' ' * self._last_pbar_line_length + '\r')
        self.original_console_stream.write(pbar_message)
        self.original_console_stream.flush()
        self._last_pbar_line_length = len(pbar_message)

    def hide(self):
        """Erases the progress bar from the current line."""
        self.original_console_stream.write('\r' + ' ' * self._last_pbar_line_length + '\r')
        self.original_console_stream.flush()

    def show(self):
        """Redraws the progress bar on the current line."""
        self.update_display()

    def _format_time(self, seconds):
        minutes, seconds = divmod(int(seconds), 60)
        hours, minutes = divmod(minutes, 60)
        if hours > 0:
            return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        return f"{minutes:02d}:{seconds:02d}"

    def __enter__(self):
        SimpleProgressBar._active_pbar = self
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.current = self.total
        self.update_display()
        self.original_console_stream.write('\n')
        self.original_console_stream.flush()
        SimpleProgressBar._active_pbar = None


# === LOGGING SETUP ===
class ProgressBarAwareHandler(logging.StreamHandler):
    def emit(self, record):
        pbar = SimpleProgressBar._active_pbar
        if pbar:
            pbar.hide()
            self.stream.write(self.format(record) + '\n')
            self.flush()
            pbar.show()
        else:
            super().emit(record)


class CompactFormatter(logging.Formatter):
    """Enhanced formatter with bright colors for status messages"""
    FORMATS = {
        logging.ERROR: '\033[91m%(levelname)s\033[0m - %(message)s',
        logging.WARNING: '\033[93m%(levelname)s\033[0m - %(message)s',
        logging.INFO: '%(levelname)s - %(message)s',
    }

    def format(self, record):
        msg = record.getMessage()
        if msg.startswith('✓ ') and 'passed' in msg:
            # Bright green for passed checks
            return f'\033[92m{record.levelname}\033[0m - \033[1;92m{msg}\033[0m'
        elif msg.startswith('✗ ') and 'failed:' in msg:
            # Bright red for failed checks
            return f'\033[91m{record.levelname}\033[0m - \033[1;91m{msg}\033[0m'
        else:
            # Use original formatting for other messages
            log_fmt = self.FORMATS.get(record.levelno, '%(levelname)s - %(message)s')
            formatter = logging.Formatter(log_fmt, datefmt='%H:%M:%S')
            return formatter.format(record)


logger = logging.getLogger()
logger.setLevel(logging.INFO)


# === OUTPUT COORDINATION CLASS ===
class Tee:
    def __init__(self, stdout_stream, file_object):
        self.stdout = stdout_stream
        self.file_object = file_object

    def write(self, data):
        pbar = SimpleProgressBar._active_pbar
        if pbar:
            pbar.hide()
            self.stdout.write(data)
            if not data.endswith('\n'):
                self.stdout.write('\n')
            self.stdout.flush()
            pbar.show()
        else:
            self.stdout.write(data)
            self.stdout.flush()
        self.file_object.write(data)
        self.file_object.flush()

    def flush(self):
        self.stdout.flush()
        self.file_object.flush()


# === SSH UTILITIES ===
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
    return full_output_buffer, prompt_found


def execute_command_in_shell(shell: paramiko.Channel, command: str, command_description: str,
                             timeout: int = 60, print_real_time_output: bool = False, cli_output_file=None) -> str:
    logger.info(f"Sending '{command_description}' ('{command}')...")
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
        logger.debug(f"Flushed {len(pre_command_flush_output)} characters from buffer BEFORE '{command_description}'.")
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
        logger.warning(f"Prompt not detected after '{command_description}'. Attempting to send newline and re-check.")
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

    logger.debug(f"Performing post-command buffer flush after '{command_description}'.")
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
        logger.debug(f"Flushed {len(post_command_flush_output)} characters from buffer AFTER '{command_description}'.")
        if cli_output_file:
            cli_output_file.write(f"\n--- Post-command Buffer Flush after '{command_description}' ---\n")
            cli_output_file.write(post_command_flush_output)
            cli_output_file.flush()

    return output


# === UTILITY FUNCTIONS ===
def safe_int_convert(value_str, default=0):
    """Fast integer conversion with fallback"""
    if not value_str or value_str in ('-', 'NA', 'N/A'):
        return default
    try:
        return int(value_str)
    except (ValueError, TypeError):
        return default


def safe_float_convert(value_str, default=0.0):
    """Fast float conversion with fallback"""
    if not value_str or value_str in ('-', 'NA', 'N/A'):
        return default
    try:
        return float(value_str)
    except (ValueError, TypeError):
        return default


# === ENHANCED CONNECTION FUNCTION === (ADD THIS ENTIRE SECTION)
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


def get_hostname(shell: paramiko.Channel, cli_output_file=None) -> str:
    logger.info("Attempting to retrieve hostname using 'show running-config | i hostname'...")
    output = execute_command_in_shell(shell, "show running-config | i hostname", "get hostname", timeout=10,
                                      print_real_time_output=False, cli_output_file=cli_output_file)
    for line in output.splitlines():
        match = re.search(r"^\s*hostname\s+(\S+)", line)
        if match:
            hostname = match.group(1)
            hostname = hostname.replace('.', '-')  # ← KEEP ONLY THIS LINE
            logger.info(f"Full hostname detected: {hostname}")
            return hostname
    logger.warning("Could not parse hostname from 'show running-config | i hostname' output. Using 'unknown_host'.")
    return "unknown_host"


def get_chassis_model(shell: paramiko.Channel, cli_output_file=None) -> str:
    output = execute_command_in_shell(shell, "show inventory chassis", "get chassis model from inventory", timeout=30,
                                      print_real_time_output=False, cli_output_file=cli_output_file)

    match = re.search(r"PID:\s*(\S+)\s*,", output)
    if match:
        chassis_model = match.group(1).strip()
        logger.info(f"Chassis model (PID) detected: {chassis_model}")
        return chassis_model

    logger.warning("Could not parse chassis model (PID) from 'show inventory chassis' output. Using 'unknown_chassis'.")
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
        logger.debug("No optics inventory items parsed from 'show inventory' output.")
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
        logger.warning("No LC/FC/RP inventory items parsed from 'show inventory' output.")
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
                logger.debug(f"Skipping brief line (no regex match): '{line}'")
    else:
        logger.debug("No 'show interface brief' output section found for parsing.")

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

    if not fpd_statuses:
        logger.warning("No FPD status items parsed from 'show hw-module fpd' output.")
    return fpd_statuses


# === CHECK DECORATORS ===
def _run_section_check(section_name: str, check_func: callable, section_statuses: Dict[str, str],
                       overall_script_failed_ref: List[bool], *args, **kwargs):
    try:
        logger.info(f"--- Running {section_name} ---")
        result = check_func(*args, **kwargs)
        logger.info(f"\033[1;92m✓ {section_name} passed\033[0m")
        section_statuses[section_name] = "Good"
        return result if result is not None else ""
    except (RouterCommandError, PlatformStatusError, FabricReachabilityError,
            FabricLinkDownError, NpuLinkError, NpuStatsError, NpuDriverError,
            FabricPlaneStatsError, AsicErrorsError, InterfaceStatusError,
            AlarmError, LcAsicErrorsError, FanTrayError, EnvironmentError, FpdStatusError) as e:
        logger.critical(f"\033[1;91m✗ {section_name} failed: {e}\033[0m")
        overall_script_failed_ref[0] = True
        section_statuses[section_name] = "Bad"
        return ""
    except Exception as e:
        logger.critical(f"\033[1;91m✗ {section_name} failed: An unexpected error occurred: {e}\033[0m", exc_info=True)
        overall_script_failed_ref[0] = True
        section_statuses[section_name] = "Bad"
        return ""


# === HEALTH CHECKS ===
def check_ios_xr_version(shell: paramiko.Channel, cli_output_file=None) -> str:
    logger.info(f"Retrieving IOS-XR Version...")
    version_output = execute_command_in_shell(shell, "show version", "show version", timeout=60,
                                              print_real_time_output=False, cli_output_file=cli_output_file)
    ios_xr_version = "N/A"
    match = re.search(r"Cisco IOS XR Software, Version (\d+\.\d+\.\d+(?:\.\w+)?)", version_output)
    if match:
        ios_xr_version = match.group(1)
        logger.info(f"IOS-XR Version detected: {ios_xr_version}")
    else:
        logger.warning("Could not parse IOS-XR version from 'show version' output.")
    version_table = PrettyTable()
    version_table.field_names = ["Information", "Value"]
    version_table.add_row(["IOS-XR Version", ios_xr_version])
    print(version_table)
    return version_output


def check_platform_and_serial_numbers(shell: paramiko.Channel,
                                      all_card_inventory_info: Dict[str, Dict[str, str]],
                                      all_cpu_locations_from_platform: List[str],
                                      ft_locations_from_platform: List[str],
                                      cli_output_file=None):
    logger.info(f"Retrieving Platform Status and Serial Numbers...")
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
    if platform_issues_found:
        logger.error(
            f"One or more Line Cards, Fabric Cards, or Route Processors are not in the expected state. Please review the table above.")
        raise PlatformStatusError("Platform status check failed.")
    else:
        logger.info(f"All Line Cards, Fabric Cards, and Route Processors are in their expected states.")
    return platform_output


def check_fabric_reachability(shell: paramiko.Channel, cli_output_file=None, chassis_model: str = "unknown_chassis"):
    logger.info(f"Checking Fabric Reachability (show controller fabric fsdb-pla rack 0)...")
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
                    # Removed redundant error logging here
                    problematic_fabric_rows.append([
                        parts[0], parts[1], parts[2], parts[3], parts[4],
                        parts[5], parts[6], parts[7], parts[8],
                        parts[9], parts[11]
                    ])
    if problematic_fabric_rows:
        logger.error(f"!!! FABRIC REACHABILITY ERRORS DETECTED !!!")
        fabric_table = PrettyTable()
        fabric_table.field_names = ["Destination Address", "p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7",
                                    "Reach-mask links/asic", "Oper Up links/asic"]
        for row in problematic_fabric_rows:
            fabric_table.add_row(row)
        print(fabric_table)
        raise FabricReachabilityError("Fabric reachability check failed. Unexpected Reach-mask values detected.")
    else:
        logger.info(f"Fabric Reachability check passed. No issues detected.")


def check_fabric_link_down_status(shell: paramiko.Channel, cli_output_file=None):
    logger.info(f"Checking Fabric Link Down Status...")
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
            logger.warning(f"Unknown command for parsing fabric link down status: {command}")
            continue
        lines = output.splitlines()
        for line in lines:
            stripped_line = line.strip()
            if not stripped_line: continue
            if re.match(r'^\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+$', stripped_line): continue
            if re.match(r'^RP/\d+/\S+:\S+#', stripped_line): continue
            if re.escape(command.strip()) in re.escape(stripped_line): continue
            if re.match(r'Description:', stripped_line) or \
                    re.match(r'R/S/A/P\s+-\s+Rack/Slot/Asic/Port', stripped_line) or \
                    re.match(r'DN\s+-\s+Down,\s+NA\s+-\s+Not Available/Applicable', stripped_line) or \
                    re.match(r'SFE port\s+Admin\s+Retimer RX', stripped_line) or \
                    re.match(r'R/S/A/P\s+/Oper\s+R/I/P', stripped_line) or \
                    re.match(r'FIA Port\s+Admin\s+Other End', stripped_line) or \
                    re.match(r'----------------+', stripped_line) or \
                    re.match(r'R/S/A/P\s+/Oper\s+R/S/A/P', stripped_line): continue
            match = link_pattern.match(stripped_line)
            if match:
                all_down_links_found.append({
                    "Interface": match.group(1),
                    "Admin/Oper State": match.group(2),
                    "Other End": match.group(3)
                })
    if all_down_links_found:
        logger.error(f"!!! FABRIC LINK DOWN STATUS ERRORS DETECTED !!!")
        link_down_table = PrettyTable()
        link_down_table.field_names = headers
        for link_info in all_down_links_found:
            link_down_table.add_row([link_info["Interface"], link_info["Admin/Oper State"], link_info["Other End"]])
        print(link_down_table)
        raise FabricLinkDownError("Fabric link down status check failed. Down links reported.")
    else:
        logger.info(f"Fabric Link Down Status check passed. No issues detected.")


def check_npu_link_info(shell: paramiko.Channel, cli_output_file=None):
    logger.info(f"Checking NPU Link Information...")
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
    if problematic_links:
        logger.error(f"!!! NPU LINK ERRORS DETECTED !!!")
        npu_table = PrettyTable()
        npu_table.field_names = ["Link ID", "Far-End Link (FSDB)"]
        for link in problematic_links:
            npu_table.add_row([link["Link ID"], link["Far-End Link (FSDB)"]])
        print(npu_table)
        raise NpuLinkError("NPU link info check failed. Links are reported as down.")
    else:
        logger.info(f"NPU Link Information check passed. No down links reported.")


def check_npu_stats_link(shell: paramiko.Channel, cli_output_file=None):
    logger.info(f"Checking NPU Stats Link for UCE/CRC Errors...")
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
    if problematic_stats:
        logger.error(f"!!! NPU STATS ERRORS DETECTED (UCE/CRC) !!!")
        stats_table = PrettyTable()
        stats_table.field_names = ["Node ID", "UCE Errors", "CRC Errors"]
        for stat in problematic_stats:
            stats_table.add_row([stat["Node ID"], stat["UCE Errors"], stat["CRC Errors"]])
        print(stats_table)
        raise NpuStatsError("NPU stats link check failed. Non-zero UCE or CRC errors detected.")
    else:
        logger.info(f"NPU Stats Link check passed. No non-zero UCE or CRC errors detected.")


def check_npu_driver_status(shell: paramiko.Channel, cli_output_file=None):
    logger.info(f"Checking NPU Driver Status (Asic states)...")
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
                if slice_state != expected_slice_state: current_asic_issues.append(
                    f"Slice state: {slice_state} (Expected: {expected_slice_state})")
                if admin_state != expected_admin_state: current_asic_issues.append(
                    f"Admin state: {admin_state} (Expected: {expected_admin_state})")
                if oper_state != expected_oper_state: current_asic_issues.append(
                    f"Oper state: {oper_state} (Expected: {expected_oper_state})")
                if asic_state != expected_asic_state: current_asic_issues.append(
                    f"Asic state: {asic_state} (Expected: {expected_asic_state})")
                if current_asic_issues:
                    problematic_asics.append({
                        "Asic Instance": asic_instance,
                        "Issues": ", ".join(current_asic_issues)
                    })
    if problematic_asics:
        logger.error(f"!!! NPU DRIVER STATUS ERRORS DETECTED (Asic states) !!!")
        npu_driver_table = PrettyTable()
        npu_driver_table.field_names = ["Asic Instance", "Problematic States"]
        for asic in problematic_asics:
            npu_driver_table.add_row([asic["Asic Instance"], asic["Issues"]])
        print(npu_driver_table)
        raise NpuDriverError("NPU driver status check failed. Asic states are not as expected.")
    else:
        logger.info(f"NPU Driver Status check passed. All Asic states are as expected.")


def check_fabric_plane_stats(shell: paramiko.Channel, cli_output_file=None):
    logger.info(f"Checking Fabric Plane Statistics (CE/UCE/PE Packets)...")
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
    if problematic_planes:
        logger.error(f"!!! FABRIC PLANE STATISTICS ERRORS DETECTED (Non-zero CE/UCE/PE Packets) !!!")
        stats_table = PrettyTable()
        stats_table.field_names = ["Plane ID", "CE Packets", "UCE Packets", "PE Packets"]
        for plane in problematic_planes:
            stats_table.add_row([plane["Plane ID"], plane["CE Packets"], plane["UCE Packets"], plane["PE Packets"]])
        print(stats_table)
        raise FabricPlaneStatsError("Fabric plane statistics check failed. Non-zero CE/UCE/PE packets detected.")
    else:
        logger.info(f"Fabric Plane Statistics check passed. No issues detected.")


def check_asic_errors(shell: paramiko.Channel, cli_output_file=None):
    logger.info(f"Checking ASIC Errors (rx_link_status_down, count, npu[])...")
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
    if problematic_asic_errors:
        logger.error(f"!!! ASIC ERRORS DETECTED (Non-zero Error Counts) !!!")
        asic_error_table = PrettyTable()
        asic_error_table.field_names = ["FC Location", "NPU number", "Error count"]
        for item in problematic_asic_errors:
            asic_error_table.add_row([item["FC Location"], item["NPU number"], item["Error count"]])
        print(asic_error_table)
        raise AsicErrorsError("ASIC errors check failed. Non-zero error counts detected.")
    else:
        logger.info(f"ASIC Errors check passed. No non-zero error counts detected.")


def run_show_inventory(shell: paramiko.Channel, cli_output_file=None) -> str:
    logger.info(f"Running show inventory (output captured silently)...")
    output = execute_command_in_shell(shell, "show inventory", "show inventory", timeout=120,
                                      print_real_time_output=False, cli_output_file=cli_output_file)
    logger.info("show inventory command executed and output captured.")
    return output


def check_interface_status(shell: paramiko.Channel, cli_output_file=None) -> Tuple[str, str]:
    logger.info(f"Checking Interface Status...")
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
                logger.warning(f"Could not parse numeric values from 'ALL TYPES' line: '{stripped_line}'")
                pass

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
        logger.info(f"Interface summary for ALL TYPES successfully retrieved.")
    else:
        logger.warning(
            f"Could not find or parse 'ALL TYPES' row in 'show interface summary'. Proceeding with other checks.")

    brief_output = execute_command_in_shell(shell, "show interface brief", "show interface brief", timeout=120,
                                            print_real_time_output=False, cli_output_file=cli_output_file)
    logger.info("show interface brief executed silently.")
    execute_command_in_shell(shell, "show interface description | ex admin",
                             "show interface description (excluding admin)", timeout=120, print_real_time_output=False,
                             cli_output_file=cli_output_file)
    logger.info("show interface description | ex admin executed silently.")

    if not brief_output.strip():
        raise InterfaceStatusError(
            "No valid output received from 'show interface brief'. Cannot proceed with interface status checks.")

    return summary_output, brief_output


def check_hw_module_fpd_status(shell: paramiko.Channel, cli_output_file=None) -> str:
    logger.info(f"Checking HW Module FPD Status...")
    output = execute_command_in_shell(shell, "show hw-module fpd", "show hw-module fpd", timeout=120,
                                      print_real_time_output=False, cli_output_file=cli_output_file)
    logger.info("show hw-module fpd executed silently.")
    return output


def check_and_capture_alarms_and_logs(shell: paramiko.Channel, cli_output_file=None):
    logger.info(f"Checking Alarms and Capturing Install Logs...")
    execute_command_in_shell(shell, "show alarms brief system", "show alarms brief system", timeout=60,
                             print_real_time_output=False, cli_output_file=cli_output_file)
    logger.info("show alarms brief system executed and output captured.")
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
        logger.error(f"!!! ACTIVE ALARMS DETECTED (excluding Optics/Coherent) !!!")
        print(f"\nActive Alarms (excluding Optics/Coherent):")
        for alarm_line in cleaned_alarm_lines:
            print(f" {alarm_line}")
        raise AlarmError("Active alarms detected after filtering.")
    else:
        logger.info(f"No active alarms detected (excluding Optics/Coherent).")
    execute_command_in_shell(shell, "show install log detail", "show install log detail", timeout=300,
                             print_real_time_output=False, cli_output_file=cli_output_file)
    logger.info("show install log detail executed and output captured.")


def check_lc_asic_errors(shell: paramiko.Channel, lc_locations: List[str], cli_output_file=None):
    logger.info(f"Checking LC ASIC Errors...")
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
    if problematic_lc_asic_errors:
        logger.error(f"!!! LC ASIC ERRORS DETECTED !!!")
        asic_error_table = PrettyTable()
        asic_error_table.field_names = ["LC Location", "Error Output"]
        for item in problematic_lc_asic_errors:
            asic_error_table.add_row([item["LC Location"], item["Error Output"]])
        print(asic_error_table)
        raise LcAsicErrorsError("LC ASIC errors check failed. Non-blank output detected for some LCs.")
    else:
        logger.info(f"LC ASIC Errors check passed. No non-blank output detected.")


def check_fan_tray_status(shell: paramiko.Channel, ft_locations: List[str],
                          all_card_inventory_info: Dict[str, Dict[str, str]], cli_output_file=None):
    logger.info(f"Checking Fan Tray Status...")

    # NEW: Check for FT-specific active alarms first (Field Notice Condition 1A & 2A)
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
        # Look for FT-related alarms with field notice keywords
        if any(keyword in stripped_line.lower() for keyword in
               ['voltage', 'current', 'sensor', 'absent', 'input_vol', 'input_cur']):
            ft_alarms_detected.append(stripped_line)

    if ft_alarms_detected:
        logger.warning(f"Fan Tray specific alarms detected (Field Notice indicators):")
        for alarm in ft_alarms_detected:
            logger.warning(f"  {alarm}")

    # General fan status command
    execute_command_in_shell(shell, "show environment fan", "show environment fan", timeout=60,
                             print_real_time_output=False, cli_output_file=cli_output_file)
    logger.info("show environment fan executed and output captured.")

    problematic_fan_trays = []

    for ft_location in ft_locations:
        logger.info(f"Checking fan tray: {ft_location}")
        command = f"show environment all location {ft_location}"
        output = execute_command_in_shell(shell, command, f"show environment for {ft_location}", timeout=60,
                                          print_real_time_output=False, cli_output_file=cli_output_file)
        issues = []
        field_notice_symptoms = []  # Track field notice specific symptoms
        replacement_recommended = "No"

        # Field Notice Condition 4: Check if fan tray is missing/absent
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

        # Field Notice Conditions 1B & 2: Check voltage issues
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

                    # Field Notice Condition 2B: Zero or invalid voltage
                    if input_voltage_volts == 0:
                        issues.append("Voltage Issue: Input Voltage is 0V.")
                        field_notice_symptoms.append("0V Fan Tray voltage (Field Notice Condition 2B)")
                    # Field Notice Condition 2B: High voltage (> 60V)
                    elif input_voltage_volts > 60:
                        issues.append(f"Voltage Issue: Input Voltage is {input_voltage_volts:.2f}V (Greater than 60V).")
                        field_notice_symptoms.append(
                            f"High voltage {input_voltage_volts:.2f}V (Field Notice Condition 2A/2B)")
                    # NEW: Field Notice Condition 2A: Low voltage detection
                    elif input_voltage_volts < 40:  # Typical low voltage threshold for 48V systems
                        issues.append(f"Voltage Issue: Input Voltage is {input_voltage_volts:.2f}V (Lower than 40V).")
                        field_notice_symptoms.append(
                            f"Low voltage {input_voltage_volts:.2f}V (Field Notice Condition 2A)")
                except ValueError:
                    issues.append(f"Invalid Sensor Read: Input Voltage '{voltage_str}' is not a valid number.")
                    field_notice_symptoms.append("Invalid voltage sensor data (Field Notice Condition 1A)")
        else:
            issues.append("Input Voltage reading not found.")

        # Field Notice Conditions 1B & 3: Check current issues
        current_line_match = re.search(r'(?:Input_Cur|Input Current)\s+(\S+)', output)
        if current_line_match:
            current_str = current_line_match.group(1).strip()
            if current_str == "-":
                issues.append("Invalid Sensor Read: Input Current is '-'.")
                field_notice_symptoms.append("Invalid read error for input current (Field Notice Condition 1B)")
            else:
                try:
                    input_current_ma = float(current_str)
                    # Field Notice Condition 3: Zero current
                    if input_current_ma == 0:
                        issues.append("Current Issue: Input Current is 0A.")
                        field_notice_symptoms.append("0A Fan Tray current (Field Notice Condition 3)")
                except ValueError:
                    issues.append(f"Invalid Sensor Read: Input Current '{current_str}' is not a valid number.")
                    field_notice_symptoms.append("Invalid current sensor data (Field Notice Condition 1A)")
        else:
            issues.append("Input Current reading not found.")

        # Field Notice Condition 1B: Check Power Used status
        power_line_match = re.search(
            r'^\s*' + re.escape(ft_location) + r'\s+\S+\s+(\S+)\s+(\S+)\s+(ON|OFF|UNPOWERED|POWERED_OFF|SHUTDOWN)',
            output, re.MULTILINE
        )
        if power_line_match:
            power_used = power_line_match.group(2)
            status = power_line_match.group(3)

            # Field Notice Condition 1B: Power Used = "-"
            if power_used == "-":
                issues.append("Power Used is reported as '-' (Not Available/Operational).")
                field_notice_symptoms.append("Power Used shows '-' (Field Notice Condition 1B)")

            if status != "ON":
                issues.append(f"Fan Tray Status is '{status}' (Expected: ON).")
        else:
            issues.append("Could not parse Power Used/Status information for fan tray.")

        # Field Notice Version Assessment
        fan_tray_inventory = all_card_inventory_info.get(ft_location, {})
        pid = fan_tray_inventory.get("PID", "N/A")
        vid = fan_tray_inventory.get("VID", "N/A")

        if pid in FAN_IMPACTED_VERSIONS:
            impacted_versions = FAN_IMPACTED_VERSIONS[pid].get("Impacted", [])
            if vid in impacted_versions:
                # Fan tray has impacted version
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

        # Only add to problematic list if there are actual issues
        if issues:
            problematic_fan_trays.append({
                "Fan Tray Location": ft_location,
                "Detected Issues": "\n".join(issues),
                "Field Notice Symptoms": "\n".join(field_notice_symptoms) if field_notice_symptoms else "None",
                "Replacement Recommended": replacement_recommended,
                "PID": pid,
                "VID": vid
            })

    if problematic_fan_trays:
        logger.error(f"!!! FAN TRAY STATUS ERRORS DETECTED !!!")
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
        logger.info(f"Fan Tray Status check passed. No issues detected.")


def check_environment_status(shell: paramiko.Channel, cli_output_file=None):
    logger.info(f"Checking Environment Status (Temperature, Voltage, Power Supply)...")
    command = "show environment"
    output = execute_command_in_shell(shell, command, "show environment", timeout=180, print_real_time_output=False,
                                      cli_output_file=cli_output_file)

    temp_issues = []
    voltage_issues = []
    power_supply_issues = []

    lines = output.splitlines()
    current_section = None
    current_location = None

    temp_section_pattern = re.compile(r'Location\s+TEMPERATURE')
    voltage_section_pattern = re.compile(r'Location\s+VOLTAGE')
    current_section_pattern = re.compile(r'Location\s+CURRENT')
    power_supply_section_pattern = re.compile(r'Power\s+Module\s+Type')

    location_line_pattern = re.compile(r'^\s*(\d+/\S+)\s*$')

    temp_sensor_data_pattern = re.compile(
        r'^\s*(\S+)\s+([\d\.-]+)\s+([\d\.-]+|NA|-)\s+([\d\.-]+|NA|-)\s+([\d\.-]+|NA|-)\s+([\d\.-]+|NA|-)\s+([\d\.-]+|NA|-)\s*([\d\.-]+|NA|-)?\s*$'
    )

    voltage_sensor_data_pattern = re.compile(
        r'^\s*(\S+)\s+([\d\.-]+)\s+([\d\.-]+|NA|-)\s+([\d\.-]+|NA|-)\s+([\d\.-]+|NA|-)\s*([\d\.-]+|NA|-)?\s*$'
    )

    power_supply_data_pattern = re.compile(
        r'^\s*(\S+)\s+(\S+)\s+([\d\.]+)/([\d\.]+)\s+([\d\.]+)/([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)\s+(.+)$'
    )

    for i, line in enumerate(lines):
        stripped_line = line.strip()

        if not stripped_line or \
                re.match(r'^\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+$', stripped_line) or \
                re.match(r'^RP/\d+/\S+:\S+#', stripped_line) or \
                re.match(r'^-+$', stripped_line) or \
                "================================================================================" in stripped_line or \
                "Flags:" in stripped_line or "Check detail option." in stripped_line:
            continue

        if temp_section_pattern.search(stripped_line):
            current_section = "TEMPERATURE"
            current_location = None
            continue
        elif voltage_section_pattern.search(stripped_line):
            current_section = "VOLTAGE"
            current_location = None
            continue
        elif current_section_pattern.search(stripped_line):
            current_section = "CURRENT"
            current_location = None
            continue
        elif power_supply_section_pattern.search(stripped_line):
            current_section = "POWER_SUPPLY"
            current_location = None
            continue

        if current_section == "TEMPERATURE":
            location_match = location_line_pattern.match(stripped_line)
            if location_match:
                current_location = location_match.group(1)
                continue

            if re.match(r'^\s*Sensor\s+Value\s+Crit\s+Major\s+Minor\s+Minor\s+Major\s+Crit', stripped_line):
                continue

            if current_location:
                match = temp_sensor_data_pattern.match(stripped_line)
                if match:
                    sensor, value_str, crit_lo, major_lo, minor_lo, minor_hi, major_hi, crit_hi = match.groups()

                    try:
                        value = float(value_str)
                        crit_lo = float(crit_lo) if crit_lo is not None and crit_lo not in ['NA', '-'] else None
                        major_lo = float(major_lo) if major_lo is not None and major_lo not in ['NA', '-'] else None
                        minor_lo = float(minor_lo) if minor_lo is not None and minor_lo not in ['NA', '-'] else None
                        minor_hi = float(minor_hi) if minor_hi is not None and minor_hi not in ['NA', '-'] else None
                        major_hi = float(major_hi) if major_hi is not None and major_hi not in ['NA', '-'] else None
                        crit_hi = float(crit_hi) if crit_hi is not None and crit_hi not in ['NA', '-'] else None

                        issue_found = False
                        issue_desc = []

                        if crit_lo is not None and value < crit_lo:
                            issue_desc.append(f"Critical Low (Value: {value}, Threshold: {crit_lo})")
                            issue_found = True
                        elif major_lo is not None and value < major_lo:
                            issue_desc.append(f"Major Low (Value: {value}, Threshold: {major_lo})")
                            issue_found = True
                        elif minor_lo is not None and value < minor_lo:
                            issue_desc.append(f"Minor Low (Value: {value}, Threshold: {minor_lo})")
                            issue_found = True

                        if crit_hi is not None and value > crit_hi:
                            issue_desc.append(f"Critical High (Value: {value}, Threshold: {crit_hi})")
                            issue_found = True
                        elif major_hi is not None and value > major_hi:
                            issue_desc.append(f"Major High (Value: {value}, Threshold: {major_hi})")
                            issue_found = True
                        elif minor_hi is not None and value > minor_hi:
                            issue_desc.append(f"Minor High (Value: {value}, Threshold: {minor_hi})")
                            issue_found = True

                        if issue_found:
                            temp_issues.append({
                                "Location": current_location,
                                "Sensor": sensor,
                                "Problem": "; ".join(issue_desc)
                            })
                    except ValueError:
                        logger.warning(
                            f"Could not parse numeric values for temperature sensor '{sensor}' at '{current_location}'. Line: '{stripped_line}'")
                        pass
        elif current_section == "VOLTAGE":
            location_match = location_line_pattern.match(stripped_line)
            if location_match:
                current_location = location_match.group(1)
                continue

            if re.match(r'^\s*Sensor\s+Value\s+Crit\s+Minor\s+Minor\s+Crit', stripped_line):
                continue

            if current_location:
                match = voltage_sensor_data_pattern.match(stripped_line)
                if match:
                    sensor, value_str, crit_lo, minor_lo, minor_hi, crit_hi = match.groups()
                    try:
                        value = float(value_str)
                        crit_lo = float(crit_lo) if crit_lo is not None and crit_lo not in ['NA', '-'] else None
                        minor_lo = float(minor_lo) if minor_lo is not None and minor_lo not in ['NA', '-'] else None
                        minor_hi = float(minor_hi) if minor_hi is not None and minor_hi not in ['NA', '-'] else None
                        crit_hi = float(crit_hi) if crit_hi is not None and crit_hi not in ['NA', '-'] else None

                        issue_found = False
                        issue_desc = []

                        if crit_lo is not None and value < crit_lo:
                            issue_desc.append(f"Critical Low (Value: {value}mV, Threshold: {crit_lo}mV)")
                            issue_found = True
                        elif minor_lo is not None and value < minor_lo:
                            issue_desc.append(f"Minor Low (Value: {value}mV, Threshold: {minor_lo}mV)")
                            issue_found = True

                        if crit_hi is not None and value > crit_hi:
                            issue_desc.append(f"Critical High (Value: {value}mV, Threshold: {crit_hi}mV)")
                            issue_found = True
                        elif minor_hi is not None and value > minor_hi:
                            issue_desc.append(f"Minor High (Value: {value}mV, Threshold: {minor_hi}mV)")
                            issue_found = True

                        if issue_found:
                            voltage_issues.append({
                                "Location": current_location,
                                "Sensor": sensor,
                                "Problem": "; ".join(issue_desc)
                            })
                    except ValueError:
                        logger.warning(
                            f"Could not parse numeric values for voltage sensor '{sensor}' at '{current_location}'. Line: '{stripped_line}'")
                        pass
        elif current_section == "POWER_SUPPLY":
            if re.match(r'^\s*Power\s+Module\s+Type\s+---Input----\s+---Output---\s+Status', stripped_line):
                continue
            if re.match(r'^\s*Volts\s+A/B\s+Amps\s+A/B\s+Volts\s+Amps', stripped_line):
                continue

            match = power_supply_data_pattern.match(stripped_line)
            if match:
                location, ps_type, in_v_a_str, in_v_b_str, in_a_a_str, in_a_b_str, out_v_str, out_a_str, status = match.groups()
                current_ps_issues = []
                try:
                    in_v_a = float(in_v_a_str)
                    in_v_b = float(in_v_b_str)
                    in_a_a = float(in_a_a_str)
                    in_a_b = float(in_a_b_str)
                    out_v = float(out_v_str)
                    out_a = float(out_a_str)

                    if in_v_a == 0 or in_v_b == 0: current_ps_issues.append("Zero Input Voltage detected.")
                    if in_a_a == 0 or in_a_b == 0: current_ps_issues.append("Zero Input Current detected.")
                    if out_v == 0: current_ps_issues.append("Zero Output Voltage detected.")
                    if out_a == 0: current_ps_issues.append("Zero Output Current detected.")
                except ValueError:
                    current_ps_issues.append("Invalid numeric value in voltage/current fields.")

                if status.strip().upper() != "OK":
                    current_ps_issues.append(f"Status is '{status.strip()}' (Expected: OK).")

                if current_ps_issues:
                    power_supply_issues.append({
                        "Location": location,
                        "Type": ps_type,
                        "Problem": "; ".join(current_ps_issues)
                    })

    all_env_issues_found = False
    if temp_issues:
        all_env_issues_found = True
        logger.error(f"!!! ENVIRONMENT TEMPERATURE ALARMS DETECTED !!!")
        temp_table = PrettyTable()
        temp_table.field_names = ["Location", "Sensor", "Problem"]
        for issue in temp_issues:
            temp_table.add_row([issue["Location"], issue["Sensor"], issue["Problem"]])
        print(temp_table)
    if voltage_issues:
        all_env_issues_found = True
        logger.error(f"!!! ENVIRONMENT VOLTAGE ALARMS DETECTED !!!")
        voltage_table = PrettyTable()
        voltage_table.field_names = ["Location", "Sensor", "Problem"]
        for issue in voltage_issues:
            voltage_table.add_row([issue["Location"], issue["Sensor"], issue["Problem"]])
        print(voltage_table)
    if power_supply_issues:
        all_env_issues_found = True
        logger.error(f"!!! POWER SUPPLY MODULE ISSUES DETECTED !!!")
        ps_table = PrettyTable()
        ps_table.field_names = ["Location", "Type", "Problem"]
        for issue in power_supply_issues:
            ps_table.add_row([issue["Location"], issue["Type"], issue["Problem"]])
        print(ps_table)

    if all_env_issues_found:
        raise EnvironmentError("Environment status check failed. Issues detected.")
    else:
        logger.info(
            f"Environment Status check passed. No critical/major temperature/voltage alarms or power supply issues detected.")


# === COMPARISON UTILITIES ===
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


def compare_optics_inventory(current_optics: Dict[str, Dict[str, str]],
                             previous_optics: Dict[str, Dict[str, str]]) -> Tuple[str, bool]:
    logger.info("Comparing optics inventory...")
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
    logger.info("Comparing LC/FC/RP inventory...")
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
    summary_header_table.junction_char = "+"
    summary_header_table.horizontal_char = "-"
    summary_header_table.vertical_char = "|"
    summary_header_table.border = True
    summary_header_table.hrules = 0

    summary_header_table.min_width["Device"] = max(len(f"Device: {hostname}"), 25)
    summary_header_table.min_width["Tile number"] = 15
    summary_header_table.min_width["Date"] = 15
    summary_header_table.min_width["Status"] = 15

    report_output_parts.append(str(summary_header_table))

    comparison_table = PrettyTable()
    comparison_table.field_names = ["LC / FC / RP / FT Location", "OLD SERIAL", "OLD AT", "NEW SN", "NEW AT", "PID"]
    comparison_table.align = "l"
    comparison_table.junction_char = "+"
    comparison_table.horizontal_char = "-"
    comparison_table.vertical_char = "|"
    comparison_table.border = True
    comparison_table.vrules = True

    comparison_table.min_width["OLD AT"] = 10
    comparison_table.min_width["NEW AT"] = 10

    all_locations = sorted(list(set(current_lcfc.keys()) | set(previous_lcfc.keys())))

    for location in all_locations:
        current_sn = current_lcfc.get(location, {}).get('SN', 'N/A')
        previous_sn = previous_lcfc.get(location, {}).get('SN', 'N/A')
        current_pid = current_lcfc.get(location, {}).get('PID', 'N/A')
        previous_pid = previous_lcfc.get(location, {}).get('PID', 'N/A')

        display_pid = current_pid if current_pid != 'N/A' else previous_pid

        if (location in previous_lcfc and location in current_lcfc and current_sn != previous_sn) or \
                (location in current_lcfc and location not in previous_lcfc) or \
                (location in previous_lcfc and location not in current_lcfc):

            if location in previous_lcfc and location in current_lcfc and current_sn != previous_sn:
                comparison_table.add_row([
                    location,
                    previous_sn,
                    "",
                    current_sn,
                    "",
                    display_pid
                ])
                differences_found = True
            elif location in current_lcfc and location not in previous_lcfc:
                comparison_table.add_row([
                    location,
                    "N/A",
                    "",
                    current_sn,
                    "",
                    display_pid
                ])
                differences_found = True
            elif location in previous_lcfc and location not in current_lcfc:
                comparison_table.add_row([
                    location,
                    previous_sn,
                    "",
                    "N/A",
                    "",
                    display_pid
                ])
                differences_found = True

    if not differences_found:
        no_diff_table = PrettyTable()
        no_diff_table.field_names = ["Message"]
        no_diff_table.add_row(["No LC/FC/RP inventory differences detected."])
        no_diff_table.align = "c"
        no_diff_table.junction_char = "+"
        no_diff_table.horizontal_char = "-"
        no_diff_table.vertical_char = "|"
        no_diff_table.border = True
        no_diff_table.hrules = True
        no_diff_table.vrules = True

        calculated_width = sum(comparison_table.min_width.get(f, len(f)) for f in comparison_table.field_names) + \
                           (len(comparison_table.field_names) - 1) * len(comparison_table.junction_char) + \
                           2 * len(comparison_table.vertical_char)
        no_diff_table.max_width = calculated_width

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

    all_interfaces = sorted(list(set(current_statuses.keys()) | set(previous_statuses.keys())))

    for intf in all_interfaces:
        physical_intf_pattern = re.compile(
            r"^(?:(?:GigabitEthernet|Gi|TenGigE|Te|FortyGigE|Fo|HundredGigE|Hu|FourHundredGigE|FH|Ethernet|Eth|FastEthernet|Fa|Serial|Se|POS|Cellular|Ce|MgmtEth|PTP|nve|Vxlan)\S+)",
            re.IGNORECASE
        )
        if not physical_intf_pattern.match(intf):
            logger.debug(f"Skipping logical interface '{intf}' for comparison.")
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
    logger.info("Comparing FPD statuses...")
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
        report_output += str(comparison_table) + "\n\nPlease review the FPD status changes above.\n"
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


def find_earliest_file_as_permanent_baseline(hostname_prefix: str, output_directory: str) -> Optional[str]:
    pattern = re.compile(rf"^{re.escape(hostname_prefix)}_combined_cli_output_(\d{{8}}_\d{{6}})\.txt$")

    earliest_file, earliest_timestamp = None, None
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
        logger.debug(f"Found earliest baseline file: {earliest_file}")
    else:
        logger.debug("No baseline CLI output files found matching known patterns.")

    return earliest_file


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


def print_final_summary_table(statuses: Dict[str, str], total_execution_time: float):
    """Print enhanced final summary table with execution time and wrapped headers"""
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

    # Sections to exclude from the summary table
    excluded_sections = {
        "Interface Status Check",
        "HW Module FPD Status Check"
    }

    # Filter out excluded sections
    filtered_statuses = {section: status for section, status in statuses.items()
                        if section not in excluded_sections}

    summary_table = PrettyTable()
    # Use multi-line header for Test number column
    summary_table.field_names = ["Test #", "Section Name", "Status"]

    # Center align Test number, left align others
    summary_table.align["Test #"] = "c"  # Center align for numbers
    summary_table.align["Section Name"] = "l"
    summary_table.align["Status"] = "l"

    # Color mapping for different statuses
    def colorize_status(status):
        if status == "Good":
            return f"\033[1;92m{status}\033[0m"  # Bright Green
        elif status == "Bad":
            return f"\033[1;91m{status}\033[0m"  # Bright Red
        elif "Collection Only" in status:
            return f"\033[1;94m{status}\033[0m"  # Bright Blue
        elif status == "Not Run":
            return f"\033[1;93m{status}\033[0m"  # Bright Yellow
        else:
            return status

    # Add rows with test numbers and colored statuses
    test_number = 1
    for section, status in filtered_statuses.items():
        colored_status = colorize_status(status)
        summary_table.add_row([str(test_number), section, colored_status])
        test_number += 1

    print(summary_table)
    logger.info(f"--- End Final Script Summary ---")


# === MAIN EXECUTION ===
def main():
    script_start_time = time.time()
    true_original_stdout = sys.stdout

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()

    initial_console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    initial_console_handler = logging.StreamHandler(true_original_stdout)
    initial_console_handler.setFormatter(initial_console_formatter)
    logger.addHandler(initial_console_handler)

    logger.info(f"--- Cisco IOS-XR Device Status Report & Comparison ---")

    router_ip = input(f"Enter Router IP address or Hostname: ")
    username = input(f"Enter SSH Username: ")
    password = getpass.getpass(f"Enter SSH Password for {username}@{router_ip}: ")

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    shell = None
    overall_script_failed = [False]
    all_cpu_locations_from_platform = []
    ft_locations_from_platform = []
    all_card_inventory_info = {}
    cli_output_file = None
    session_log_file_handle = None
    hostname = "unknown_host"
    chassis_model = "unknown_chassis"

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
        logger.info(f"Attempting to connect to {router_ip}...")
        connect_with_retry(client, router_ip, username, password)
        logger.info(f"Successfully connected to {router_ip}.")

        shell = client.invoke_shell()
        time.sleep(1)
        read_and_print_realtime(shell, timeout_sec=2, print_real_time=False)

        execute_command_in_shell(shell, "terminal length 0", "set terminal length to 0", timeout=5,
                                 print_real_time_output=False)
        execute_command_in_shell(shell, "terminal width 511", "set terminal width to 511", timeout=5,
                                 print_real_time_output=False)

        hostname = get_hostname(shell)
        logger.info(f"Sanitized hostname for file paths: {hostname}")

        chassis_model = get_chassis_model(shell, cli_output_file)
        logger.info(f"Detected chassis model: {chassis_model}")

        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        output_directory = os.path.join(os.getcwd(), hostname)
        os.makedirs(output_directory, exist_ok=True)

        session_log_path = os.path.join(output_directory, f"{hostname}_combined_session_log_{timestamp}.txt")
        session_log_file_handle = open(session_log_path, 'a', encoding='utf-8')

        sys.stdout = Tee(true_original_stdout, session_log_file_handle)

        logger.removeHandler(initial_console_handler)

        file_handler = logging.FileHandler(session_log_path, encoding='utf-8')
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

        pbar_console_handler = ProgressBarAwareHandler(true_original_stdout)
        pbar_console_handler.setFormatter(CompactFormatter())
        logger.addHandler(pbar_console_handler)

        logger.info(f"Created output directory: {output_directory}")
        logger.info(f"Session log will be saved to: {session_log_path}")
        cli_output_path = os.path.join(output_directory, f"{hostname}_combined_cli_output_{timestamp}.txt")
        cli_output_file = open(cli_output_path, 'a')
        logger.info(f"CLI output will be saved to: {cli_output_path}")

        print(f"\n--- Device Information Report (Pre-checks) ---")

        total_steps = 16
        with SimpleProgressBar(total=total_steps, original_console_stream=true_original_stdout,
                               description="Overall Device Checks", color_code='\033[92m') as pbar:
            _run_section_check("IOS-XR Version Check", check_ios_xr_version, section_statuses, overall_script_failed,
                               shell,
                               cli_output_file)
            pbar.update(1)

            _run_section_check("Platform Status & Serial Numbers", check_platform_and_serial_numbers, section_statuses,
                               overall_script_failed, shell, all_card_inventory_info, all_cpu_locations_from_platform,
                               ft_locations_from_platform, cli_output_file)
            pbar.update(1)

            _run_section_check("Fabric Reachability Check", check_fabric_reachability, section_statuses,
                               overall_script_failed, shell, cli_output_file, chassis_model=chassis_model)
            pbar.update(1)

            _run_section_check("Fabric Link Down Status Check", check_fabric_link_down_status, section_statuses,
                               overall_script_failed, shell, cli_output_file)
            pbar.update(1)

            _run_section_check("NPU Link Information Check", check_npu_link_info, section_statuses,
                               overall_script_failed,
                               shell, cli_output_file)
            pbar.update(1)

            _run_section_check("NPU Stats Link Check (UCE/CRC)", check_npu_stats_link, section_statuses,
                               overall_script_failed, shell, cli_output_file)
            pbar.update(1)

            _run_section_check("NPU Driver Status Check", check_npu_driver_status, section_statuses,
                               overall_script_failed,
                               shell, cli_output_file)
            pbar.update(1)

            _run_section_check("Fabric Plane Statistics Check", check_fabric_plane_stats, section_statuses,
                               overall_script_failed, shell, cli_output_file)
            pbar.update(1)

            _run_section_check("ASIC Errors Check (RP0)", check_asic_errors, section_statuses, overall_script_failed,
                               shell,
                               cli_output_file)
            pbar.update(1)

            current_inventory_raw = _run_section_check("Inventory Collection", run_show_inventory, section_statuses,
                                                       overall_script_failed,
                                                       shell, cli_output_file)
            if section_statuses["Inventory Collection"] == "Good":
                section_statuses["Inventory Collection"] = "Collection Only"
            pbar.update(1)

            intf_outputs = _run_section_check("Interface Status Check", check_interface_status, section_statuses,
                                              overall_script_failed,
                                              shell, cli_output_file)
            if intf_outputs:
                current_intf_summary_raw, current_intf_brief_raw = intf_outputs
                current_run_parsed_interface_statuses = parse_interface_status_from_strings(current_intf_summary_raw,
                                                                                            current_intf_brief_raw)
            if section_statuses["Interface Status Check"] == "Good":
                section_statuses["Interface Status Check"] = "Collection Only"
            pbar.update(1)

            current_fpd_raw = _run_section_check("HW Module FPD Status Check", check_hw_module_fpd_status,
                                                 section_statuses,
                                                 overall_script_failed, shell, cli_output_file)
            if section_statuses["HW Module FPD Status Check"] == "Good":
                section_statuses["HW Module FPD Status Check"] = "Collection Only"
            pbar.update(1)

            section_name_alarms = "Active Alarms Check"
            section_name_install_log = "Install Log Collection"
            _run_section_check(section_name_alarms, check_and_capture_alarms_and_logs, section_statuses,
                               overall_script_failed, shell, cli_output_file)
            if section_statuses[section_name_alarms] != "Bad":
                section_statuses[section_name_install_log] = "Collection Only"
            else:
                section_statuses[section_name_install_log] = "Collection Only"
            pbar.update(1)

            section_name = "LC ASIC Errors Check"
            lc_locations_for_asic_check = [loc for loc in all_cpu_locations_from_platform if "RP" not in loc]
            if lc_locations_for_asic_check:
                _run_section_check(section_name, check_lc_asic_errors, section_statuses, overall_script_failed, shell,
                                   lc_locations_for_asic_check, cli_output_file)
            else:
                logger.warning(
                    f"Skipping {section_name} as no non-RP LC locations were identified from 'show platform'.")
                section_statuses[section_name] = "Collection Only (Skipped - No LCs)"
            pbar.update(1)

            section_name = "Fan Tray Status Check"
            if ft_locations_from_platform:
                _run_section_check(section_name, check_fan_tray_status, section_statuses, overall_script_failed, shell,
                                   ft_locations_from_platform, all_card_inventory_info, cli_output_file)
            else:
                logger.warning(
                    f"Skipping {section_name} as no Fan Tray locations were identified from 'show platform'.")
                section_statuses[section_name] = "Collection Only (Skipped - No FTs)"
            pbar.update(1)

            _run_section_check("Overall Environment Status Check", check_environment_status, section_statuses,
                               overall_script_failed, shell, cli_output_file)
            pbar.update(1)

        initially_down_report, _ = get_initially_down_physical_interfaces(current_run_parsed_interface_statuses)
        print(initially_down_report)

        print("\n" + "=" * 80)
        print(f"{'INITIATING COMPARISON WITH PERMANENT BASELINE':^80}")
        print("=" * 80 + "\n")

        permanent_baseline_file_path = find_earliest_file_as_permanent_baseline(hostname, output_directory)
        all_comparison_diffs_found = False

        if permanent_baseline_file_path:
            logger.info(f"Using permanent baseline file for comparison: {permanent_baseline_file_path}")

            try:
                baseline_inventory_raw = extract_command_output_from_file(permanent_baseline_file_path,
                                                                          "show inventory")
                baseline_intf_summary_raw = extract_command_output_from_file(permanent_baseline_file_path,
                                                                             "show interface summary")
                baseline_intf_brief_raw = extract_command_output_from_file(permanent_baseline_file_path,
                                                                           "show interface brief")
                baseline_fpd_raw = extract_command_output_from_file(permanent_baseline_file_path, "show hw-module fpd")

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

                lcfc_report, lcfc_diffs = compare_lcfc_inventory(current_lcfc_data, baseline_lcfc_data, hostname,
                                                                 chassis_model)
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
                logger.error(f"Error processing permanent baseline file for comparison: {e}")
                print(f"\n--- Comparison Skipped (Error processing permanent baseline file) ---")
            except Exception as e:
                logger.error(f"An unexpected error occurred during comparison: {e}", exc_info=True)
                print(f"\n--- Comparison Skipped (Unexpected error) ---")

            if all_comparison_diffs_found:
                print(f"\n--- COMPARISON COMPLETED WITH DIFFERENCES ---")
                overall_script_failed[0] = True
            else:
                print(f"\n--- COMPARISON COMPLETED - NO DIFFERENCES FOUND ---")

        else:
            print(f"No permanent baseline CLI output file found for '{hostname}'. Comparison skipped for this run.")
            print(
                f"The CLI output generated by this run ({cli_output_path}) will serve as the permanent baseline for next comparisons.")


    except (SSHConnectionError, paramiko.SSHException, RouterCommandError) as e:
        logger.critical(f"Critical connection or initial command error: {e}")
        overall_script_failed[0] = True
    except Exception as e:
        logger.critical(f"An unexpected error occurred during script execution: {e}", exc_info=True)
        overall_script_failed[0] = True
    finally:
        if shell:
            logger.info("Exiting CLI session.")
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
        logger.info("SSH connection closed.")

        if cli_output_file:
            cli_output_file.close()
            logger.info(f"CLI output saved to {cli_output_path}")

        # Calculate total execution time
        total_execution_time = time.time() - script_start_time

        # Print final summary with execution time
        print_final_summary_table(section_statuses, total_execution_time)

        if overall_script_failed[0]:
            logger.critical(f"--- Script Execution Finished with ERRORS / DIFFERENCES DETECTED ---")
        else:
            logger.info(f"--- Script Execution Finished Successfully (No Errors or Differences Detected) ---")

        if session_log_file_handle:
            session_log_file_handle.flush()
            session_log_file_handle.close()

        sys.stdout = true_original_stdout


if __name__ == "__main__":
    main()