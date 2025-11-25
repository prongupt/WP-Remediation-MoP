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
import time
import getpass
import re
import threading
from prettytable import PrettyTable
import datetime
import logging
from typing import Optional, List, Tuple, Dict

# --- Constants and Configuration ---
SSH_TIMEOUT_SECONDS = 15
DATAPLANE_MONITOR_TIMEOUT_SECONDS = 1500
SHOW_TECH_MONITOR_TIMEOUT_SECONDS = 3600
COUNTDOWN_DURATION_MINUTES = 15
COMMAND_TIMEOUT_SECONDS = 30
SCRIPT_EXECUTION_TIMEOUT_SECONDS = 600

PHASE2_ERRORS_DETECTED = False
PHASE3_ERRORS_DETECTED = False

PROMPT_PATTERNS = [r'#\s*$', r'\$\s*$']
SHOW_TECH_START_TIMESTAMP_FROM_LOG: Optional[str] = None
SHOW_TECH_END_TIMESTAMP_FROM_LOG: Optional[str] = None
session_log_file_console_mirror = None
session_log_file_raw_output = None


# --- Custom Exceptions ---
class SSHConnectionError(Exception): pass


class RouterCommandError(Exception): pass


class ScriptExecutionError(Exception): pass


class DataplaneError(Exception): pass


class ShowTechError(Exception): pass


class AsicErrorShowError(Exception): pass


class HostnameRetrievalError(Exception): pass


# --- Enhanced Logging & Output Classes ---
class CompactFormatter(logging.Formatter):
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


# --- UTILITY FUNCTIONS ---

def connect_with_retry(client, router_ip, username, password, max_retries=3):
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
                raise SSHConnectionError(str(e))
    return False


def read_and_print_realtime(shell_obj: paramiko.Channel, timeout_sec: int = 600, print_realtime: bool = True) -> Tuple[
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
                                break
                if prompt_found:
                    break
            except Exception as e:
                logging.error(f"Error receiving data: {e}")
                break
        else:
            time.sleep(0.1)
        if prompt_found:
            break

    if prompt_found:
        logging.debug("Prompt found. Soaking for 1.5s to capture any trailing output...")
        soak_start_time = time.time()
        while time.time() - soak_start_time < 1.5:
            if shell_obj.recv_ready():
                final_data = shell_obj.recv(65535).decode('utf-8', errors='ignore')
                if final_data:
                    logging.debug(f"Captured {len(final_data)} bytes of trailing data.")
                    if print_realtime: print(f"{final_data}", end='')
                    full_output_buffer += final_data
            else:
                time.sleep(0.05)

    if print_realtime and full_output_buffer and not full_output_buffer.endswith('\n'):
        print()
    return full_output_buffer, prompt_found


def execute_command_in_shell(shell: paramiko.Channel, command: str, command_description: str, timeout: int = 30,
                             print_realtime_output: bool = True) -> bool:
    logging.info(f"Sending '{command_description}' ('{command}')...")
    time.sleep(0.1)
    while shell.recv_ready():
        shell.recv(65535)
    shell.send(command + "\n")
    time.sleep(0.5)
    output, prompt_found = read_and_print_realtime(shell, timeout_sec=timeout, print_realtime=print_realtime_output)
    if not prompt_found:
        logging.warning(f"Prompt not detected after '{command_description}'. Re-checking...")
        shell.send("\n")
        output_retry, prompt_found_retry = read_and_print_realtime(shell, timeout_sec=5,
                                                                   print_realtime=print_realtime_output)
        if not prompt_found_retry:
            raise RouterCommandError(
                f"Failed to reach prompt after '{command_description}'. Output: {output + output_retry}")
    return True


def format_execution_time(seconds):
    hours, rem = divmod(int(seconds), 3600)
    minutes, secs = divmod(rem, 60)
    if hours > 0:
        return f"{hours:02d}h {minutes:02d}m {secs:02d}s"
    elif minutes > 0:
        return f"{minutes:02d}m {secs:02d}s"
    else:
        return f"{secs:02d}s"


def colorful_countdown_timer(seconds: int):
    logging.info(f'Countdown Timer: Starting for {seconds // 60:02d}:{seconds % 60:02d}.')
    while seconds:
        mins, secs = divmod(seconds, 60)
        timer = f'{mins:02d}:{secs:02d}'
        print(f'\rWaiting... {timer} remaining', end='', flush=True)
        time.sleep(1)
        seconds -= 1
    print(f'\rWaiting... 00:00 - Time is up!   ')


def get_hostname_from_router(router_ip, username, password):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connect_with_retry(client, router_ip, username, password)
        stdin, stdout, stderr = client.exec_command("show running | i hostname", timeout=30)
        output = stdout.read().decode('utf-8', errors='ignore')
        if not output.strip(): raise HostnameRetrievalError("No output for hostname command.")
        match = re.search(r"hostname\s+(\S+)", output)
        if not match: raise HostnameRetrievalError("Hostname not found in output.")
        return match.group(1).replace('.', '-')
    finally:
        client.close()


def parse_version_string(version_str: str) -> Tuple[int, ...]:
    return tuple(map(int, version_str.split('.')))


def get_ios_xr_version(shell: paramiko.Channel) -> str:
    shell.send("show version\n")
    output, _ = read_and_print_realtime(shell, timeout_sec=30, print_realtime=False)
    match = re.search(r"Cisco IOS XR Software, Version (\d+\.\d+\.\d+)", output)
    if match: return match.group(1)
    raise RouterCommandError("Could not parse IOS-XR version.")


def get_router_timestamp(shell: paramiko.Channel) -> datetime.datetime:
    """Gets the current timestamp from the router using 'show clock'."""
    logging.info("Getting router's current timestamp using 'show clock'...")
    shell.send("show clock\n")
    output, prompt_found = read_and_print_realtime(shell, timeout_sec=10, print_realtime=False)

    if not prompt_found:
        raise RouterCommandError("Prompt not found after 'show clock'. Cannot get router timestamp.")

    # A more robust regex that handles different whitespace and day formats
    match = re.search(
        r"(?P<time>\d{2}:\d{2}:\d{2}\.\d{3})\s+(?P<tz>\w+)\s+\w+\s+(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<year>\d{4})",
        output
    )

    if match:
        # Safely access captured groups by name
        time_str = match.group("time")
        month_str = match.group("month")
        day_str = match.group("day")
        year_str = match.group("year")

        timestamp_full_str = f"{month_str} {day_str} {year_str} {time_str}"
        try:
            dt_obj = datetime.datetime.strptime(timestamp_full_str, "%b %d %Y %H:%M:%S.%f")
            logging.info(f"Router timestamp detected: {dt_obj}")
            return dt_obj
        except ValueError as e:
            raise RouterCommandError(f"Failed to parse router timestamp '{timestamp_full_str}': {e}")
    else:
        # Log the output that failed to parse for easier debugging
        logging.error(f"Could not parse 'show clock' output for timestamp. Output was:\n{output}")
        raise RouterCommandError("Could not parse 'show clock' output for timestamp.")


def poll_dataplane_monitoring_736(shell: paramiko.Channel, max_poll_duration_sec: int) -> bool:
    shell.send("monitor dataplane\n")
    read_and_print_realtime(shell, timeout_sec=30, print_realtime=True)
    router_monitor_start_time = get_router_timestamp(shell)
    poll_start_time = time.time()
    while time.time() - poll_start_time < max_poll_duration_sec:
        shell.send('show logging | i "%PLATFORM-DPH_MONITOR-6"\n')
        output, _ = read_and_print_realtime(shell, timeout_sec=60, print_realtime=False)
        latest_completed_time = None
        for line in output.splitlines():
            if "PLATFORM-DPH_MONITOR-6-COMPLETED" in line:
                time_match = re.search(r"(\w{3})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})", line)
                if time_match:
                    log_dt = datetime.datetime.strptime(
                        f"{time_match.group(1)} {time_match.group(2)} {datetime.datetime.now().year} {time_match.group(3)}",
                        "%b %d %Y %H:%M:%S")
                    if log_dt > router_monitor_start_time and (
                            latest_completed_time is None or log_dt > latest_completed_time):
                        latest_completed_time = log_dt
        if latest_completed_time:
            shell.send("show dataplane status\n")
            status_output, _ = read_and_print_realtime(shell, timeout_sec=60, print_realtime=True)
            return parse_dataplane_output_for_errors(status_output)
        colorful_countdown_timer(180)
    raise DataplaneError("Dataplane monitoring did not complete within timeout.")


def parse_dataplane_output_for_errors(output_text: str) -> bool:
    if "FAILURES DETECTED IN DATAPATH" in output_text or "Loss detected" in output_text:
        logging.error("Explicit dataplane failure message detected in output.")
        return False
    data_pattern = re.compile(r"^\s*(\d+)?\s+(\d+)?\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")
    errors_found = False
    for line in output_text.splitlines():
        match = data_pattern.match(line)
        if match:
            try:
                loss, corrupt, error = int(match.group(5)), int(match.group(6)), int(match.group(7))
                if loss > 0 or corrupt > 0 or error > 0:
                    errors_found = True
                    logging.error(f"Dataplane error found in line: {line.strip()}")
            except (ValueError, IndexError):
                continue
    if errors_found:
        logging.error("Non-zero LOSS, CORRUPT, or ERROR values found in dataplane status.")
    return not errors_found


def run_script_list_phase(shell: paramiko.Channel, scripts_to_run: List[str], script_arg_option: str) -> List[
    Tuple[str, str]]:
    all_scripts_raw_output = []
    for script_name in scripts_to_run:
        group_match = re.search(r'group(\d+)\.py', script_name)
        group_number = group_match.group(1) if group_match else "Unknown"
        # --- FIX: Pre-calculate the stripped argument ---
        script_arg_for_log = script_arg_option.strip("'")
        logging.info(f"--- Running Group {group_number} with option {script_arg_for_log} ---")
        command_to_execute = f"python3 {script_name} {script_arg_option}"
        shell.send(command_to_execute + "\n")
        script_output, _ = read_and_print_realtime(shell, timeout_sec=SCRIPT_EXECUTION_TIMEOUT_SECONDS,
                                                   print_realtime=True)
        all_scripts_raw_output.append((script_name, script_output))
    return all_scripts_raw_output


def parse_script_output_for_errors(script_name: str, script_output: str) -> List[Dict[str, str]]:
    """
    Parses script output for faulty link details, matching the format of other scripts.
    """
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

            current_link_status = {
                "Link Connection": link_connection_full,
                "Codewords": match.group(5).strip(),
                "BER": match.group(6).strip(),
                "FLR": match.group(7).strip(),
                "Link_flap": match.group(8).strip(),
                "Codewords_Status": "N/A",
                "BER_Status": "N/A",
                "FLR_Status": "N/A",
                "Link_flap_Status": "N/A"
            }

            # Look ahead for status lines (OK/BAD)
            j = i + 1
            while j < len(lines) and not faulty_link_pattern.search(lines[j]) and not lines[j].strip().startswith(
                    "Total "):
                status_match = status_line_pattern.search(lines[j])
                if status_match:
                    metric, status = status_match.groups()
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
    """
    Formats and prints the error report in the standard, consistent table format.
    """
    global PHASE2_ERRORS_DETECTED, PHASE3_ERRORS_DETECTED
    phase_identifier = f" ({phase_name})" if phase_name else ""

    col_widths = {"Link Connection": 20, "Group_number": 15, "Codewords": 12, "FLR": 22, "BER": 22, "Link_flap": 12}
    header_cols = [f"{'Link Connection':<{col_widths['Link Connection']}}", f"{'Group_number':<{col_widths['Group_number']}}", f"{'Codewords':<{col_widths['Codewords']}}", f"{'FLR':<{col_widths['FLR']}}", f"{'BER':<{col_widths['BER']}}", f"{'Link_flap':<{col_widths['Link_flap']}}"]
    header = f"| {' | '.join(header_cols)} |"
    separator_line = f"+{'-' * (len(header) - 2)}+"

    print(f"\n--- Error Report for {script_name}{phase_identifier} ---")
    print(f"Reference Thresholds: BER < 1e-08, FLR < 1e-21")
    print(separator_line)
    print(header)
    print(separator_line)

    if not error_details:
        blank_row_cols = [f"{'':<{col_widths['Link Connection']}}", f"{group_number:<{col_widths['Group_number']}}", f"{'':<{col_widths['Codewords']}}", f"{'':<{col_widths['FLR']}}", f"{'':<{col_widths['BER']}}", f"{'':<{col_widths['Link_flap']}}"]
        print(f"| {' | '.join(blank_row_cols)} |")
        logging.info(f"✅ No errors detected for Group {group_number}{phase_identifier}.")
    else:
        if "Phase 2" in phase_name: PHASE2_ERRORS_DETECTED = True
        elif "Phase 3" in phase_name: PHASE3_ERRORS_DETECTED = True

        for detail in error_details:
            fc_match = re.search(r'0/FC(\d+)', detail['Link Connection'])
            lc_match = re.search(r'0/(\d+)/CPU0', detail['Link Connection'])
            simplified_link = f"FC{fc_match.group(1)} - LC{lc_match.group(1)}" if fc_match and lc_match else detail['Link Connection'][:20]

            codewords_display = "Bad" if detail.get('Codewords_Status') == 'BAD' else "Good"
            flr_display = f"Bad ({detail.get('FLR', 'N/A')})" if detail.get('FLR_Status') == 'BAD' else "Good"
            ber_display = f"Bad ({detail.get('BER', 'N/A')})" if detail.get('BER_Status') == 'BAD' else "Good"
            link_flap_count = int(detail.get('Link_flap', '0'))
            link_flap_display = str(link_flap_count) if link_flap_count > 0 else ""

            row_cols = [f"{simplified_link:<{col_widths['Link Connection']}}", f"{group_number:<{col_widths['Group_number']}}", f"{codewords_display:<{col_widths['Codewords']}}", f"{flr_display:<{col_widths['FLR']}}", f"{ber_display:<{col_widths['BER']}}", f"{link_flap_display:<{col_widths['Link_flap']}}"]
            print(f"| {' | '.join(row_cols)} |")

        logging.error(f"❌ {len(error_details)} errors detected for Group {group_number}{phase_identifier}.")

    print(separator_line)


def run_show_tech_fabric_threaded(shell: paramiko.Channel, hostname: str, show_tech_finished_event: threading.Event,
                                  result_dict: Dict):
    try:
        timestamp_str = time.strftime("%Y%m%d-%H%M%S")
        show_tech_filename = f"sh-tech-fabric-{hostname}-{timestamp_str}.tgz"
        log_filename = f"{show_tech_filename}.logs"
        show_tech_command = f"show tech-support fabric link-include file harddisk:/{show_tech_filename} background no-timeout compressed"
        shell.send(show_tech_command + "\n")
        read_and_print_realtime(shell, timeout_sec=60)
        execute_command_in_shell(shell, "attach location 0/RP0/CPU0", "attach to RP0", print_realtime_output=False)
        execute_command_in_shell(shell, "cd /misc/disk1/", "cd to /misc/disk1", print_realtime_output=False)
        shell.send(f"tail -f {log_filename}\n")
        full_log_output, _ = read_and_print_realtime(shell, timeout_sec=SHOW_TECH_MONITOR_TIMEOUT_SECONDS)
        shell.send("\x03")  # Ctrl+C
        result_dict["success"] = True
    except Exception as e:
        logging.error(f"Show tech thread failed: {e}")
        result_dict["success"] = False
    finally:
        show_tech_finished_event.set()


def print_final_summary_table(results_summary: Dict[str, str], total_execution_time: float):
    print("\n--- Final Script Summary ---")
    formatted_time = format_execution_time(total_execution_time)
    print(f"+{'Total time for execution: ' + formatted_time:-^60}+")
    table = PrettyTable()
    table.field_names = ["Test #", "Section Name", "Status"]
    table.align["Test #"] = "c"
    table.align["Section Name"] = "l"
    table.align["Status"] = "l"
    for i, (step_name, result) in enumerate(results_summary.items(), 1):
        status_text = "Successful"
        if "Failed" in result:
            # --- FIX: Pre-calculate the split message ---
            status_message = result.split(': ')[-1]
            status_text = f"\033[1;91m{status_message}\033[0m"
        elif "Success" in result:
            status_text = f"\033[1;92mSuccessful\033[0m"

        if "Dummy No" in step_name:
            if (PHASE2_ERRORS_DETECTED and "Phase 2" in step_name) or (
                    PHASE3_ERRORS_DETECTED and "Phase 3" in step_name):
                status_text = "\033[1;91mErrors Found\033[0m"

        table.add_row([i, step_name.split(':')[0], status_text])
    print(table)


def run_dataplane_monitor_phase(router_ip: str, username: str, password: str, monitor_description: str,
                                ssh_timeout: int, dataplane_timeout: int) -> bool:
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    shell = None
    try:
        connect_with_retry(client, router_ip, username, password)
        shell = client.invoke_shell()
        read_and_print_realtime(shell, timeout_sec=5, print_realtime=False)
        execute_command_in_shell(shell, "terminal length 0", "set terminal length", print_realtime_output=False)
        if not poll_dataplane_monitoring_736(shell, dataplane_timeout):
            raise DataplaneError(f"{monitor_description} dataplane monitoring reported errors.")
        return True
    finally:
        if shell: shell.close()
        if client: client.close()


def run_concurrent_countdown_and_show_tech(router_ip: str, username: str, password: str, ssh_timeout: int,
                                           countdown_minutes: int, show_tech_timeout: int) -> bool:
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    shell = None
    try:
        connect_with_retry(client, router_ip, username, password)
        shell = client.invoke_shell()
        read_and_print_realtime(shell, timeout_sec=5, print_realtime=False)
        hostname = get_hostname_from_router(router_ip, username, password)
        show_tech_finished = threading.Event()
        show_tech_result = {}
        timer_thread = threading.Thread(target=colorful_countdown_timer, args=(countdown_minutes * 60,))
        show_tech_thread = threading.Thread(target=run_show_tech_fabric_threaded,
                                            args=(shell, hostname, show_tech_finished, show_tech_result))
        timer_thread.start()
        show_tech_thread.start()
        timer_thread.join()
        show_tech_thread.join()
        return show_tech_result.get("success", False)
    finally:
        if shell: shell.close()
        if client: client.close()


def execute_script_phase(router_ip: str, username: str, password: str, scripts_to_run: List[str], script_arg: str,
                         ssh_timeout: int, phase_name: str = "") -> bool:
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    shell = None
    try:
        connect_with_retry(client, router_ip, username, password)
        shell = client.invoke_shell()
        read_and_print_realtime(shell, timeout_sec=5, print_realtime=False)
        execute_command_in_shell(shell, "attach location 0/RP0/CPU0", "attach to RP0", print_realtime_output=False)
        execute_command_in_shell(shell, "cd /misc/disk1/", "cd to /misc/disk1", print_realtime_output=False)
        outputs = run_script_list_phase(shell, scripts_to_run, script_arg)
        if "'--dummy' no" in script_arg:
            errors_found = False
            for name, output in outputs:
                group_num_match = re.search(r'group(\d+)', name)
                group_num = group_num_match.group(1) if group_num_match else 'N/A'
                details = parse_script_output_for_errors(name, output)
                if details:
                    errors_found = True
                    format_and_print_error_report(name, group_num, details, phase_name)
            if errors_found:
                raise ScriptExecutionError("Degraded links found")
        return True
    finally:
        if shell: shell.close()
        if client: client.close()


def run_asic_errors_show_command(router_ip: str, username: str, password: str, ssh_timeout: int) -> bool:
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    shell = None
    try:
        connect_with_retry(client, router_ip, username, password)
        shell = client.invoke_shell()
        read_and_print_realtime(shell, timeout_sec=5, print_realtime=False)
        version_str = get_ios_xr_version(shell)
        major_version = parse_version_string(version_str)[0]
        asic_command = 'asic_errors_show "-n" "all" "-a" "0x7" "-i" "0x100" "-C" "0x0" "-e" "0x0" "-c"' if major_version == 24 else 'asic_errors_show "-n" "A" "-a" "0x7" "-i" "0x100" "-C" "0x0" "-e" "0x0" "-c"'
        execute_command_in_shell(shell, "attach location 0/RP0/CPU0", "attach to RP0", print_realtime_output=False)
        execute_command_in_shell(shell, asic_command, "clear asic errors", print_realtime_output=True)
        return True
    finally:
        if shell: shell.close()
        if client: client.close()


# === INTERACTIVE FRAMEWORK MANAGER ===
class InteractiveFrameworkManager:
    def __init__(self):
        self.router_ip = None
        self.username = None
        self.password = None
        self.hostname = "unknown_host"
        self.session_start_time = time.time()
        self.true_original_stdout = sys.stdout
        self.session_log_file_handler = None
        self.raw_output_file = None
        self.scripts_to_run = [
            "monitor_8800_system_v2_3_msft_bash_group0.py",
            "monitor_8800_system_v2_3_msft_bash_group1.py",
            "monitor_8800_system_v2_3_msft_bash_group2.py",
            "monitor_8800_system_v2_3_msft_bash_group3.py"
        ]

    def initialize(self):
        print(f"{'=' * 80}")
        print(f"{'🚀 IOS-XR 7.3.6 Fabric Card Remediation Framework':^80}")
        print(f"{'Interactive Post-Check Automation v3.0':^80}")
        print(f"{'=' * 80}")

        self.router_ip = input("Enter Router IP address or Hostname: ")
        self.username = input("Enter SSH Username: ")
        self.password = getpass.getpass(f"Enter SSH Password for {self.username}@{self.router_ip}: ")

        try:
            self.hostname = get_hostname_from_router(self.router_ip, self.username, self.password)
        except HostnameRetrievalError as e:
            logging.error(f"Could not retrieve hostname: {e}. Using IP for logs.")
            self.hostname = self.router_ip.replace('.', '-')

        self._setup_logging()

    def _setup_logging(self):
        hostname_dir = os.path.join(os.getcwd(), self.hostname)
        os.makedirs(hostname_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        session_log_path = os.path.join(hostname_dir, f"{self.hostname}_7_3_6+_interactive_session_{timestamp}.txt")
        raw_output_log_path = os.path.join(hostname_dir, f"{self.hostname}_7_3_6+_interactive_output_{timestamp}.txt")

        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)

        self.session_log_file_handler = logging.FileHandler(session_log_path)
        self.session_log_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.root.addHandler(self.session_log_file_handler)

        self.raw_output_file = open(raw_output_log_path, 'w', encoding='utf-8')
        sys.stdout = Tee(self.true_original_stdout, self.raw_output_file)

        console_handler = logging.StreamHandler(self.true_original_stdout)
        console_handler.setFormatter(CompactFormatter())
        logging.root.addHandler(console_handler)
        logging.root.setLevel(logging.INFO)

    def display_main_menu(self):
        print(f"\n{'=' * 80}")
        print(f"{'IOS-XR 7.3.6+ Post-Check Interactive Framework v3.0':^80}")
        print(f"{'=' * 80}")
        print(f"\nRouter: {self.hostname} ({self.router_ip})")
        print(f"Session Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("\nMAIN WORKFLOW:")
        print("   [1] Execute Full 8-Step Post-Check Workflow - ~3 hours")
        print("\nINDIVIDUAL OPERATIONS:")
        print("   [2] Run Dataplane Monitor Only")
        print("   [3] Run Dummy Scripts Only")
        print("\nUTILITIES:")
        print("   [help]   Help & Documentation")
        print("   [exit]   Exit")
        print(f"\n{'=' * 80}")

    def get_user_choice(self):
        while True:
            choice = input("Select option: ").strip().lower()
            if choice in ["1", "2", "3", "help", "exit", "q"]:
                return choice
            print(f"Invalid choice '{choice}'. Please try again.")

    def confirm_action(self, message: str, default_yes: bool = False) -> bool:
        prompt = " (Y/n): " if default_yes else " (y/N): "
        response = input(f"{message}{prompt}").lower().strip()
        if not response: return default_yes
        return response.startswith('y')

    def run_interactive_framework(self):
        while True:
            try:
                self.display_main_menu()
                choice = self.get_user_choice()
                if choice == '1':
                    self.execute_full_workflow()
                elif choice == '2':
                    self.run_dataplane_monitor_interactive()
                elif choice == '3':
                    self.run_dummy_scripts_interactive()
                elif choice == 'help':
                    self.show_help()
                elif choice in ['exit', 'q']:
                    if self.confirm_action("Are you sure you want to exit?"): break
            except KeyboardInterrupt:
                print("\n\nOperation interrupted by user.")
                if self.confirm_action("Do you want to exit the framework?"): break
            except Exception as e:
                logging.critical(f"A critical error occurred in the framework: {e}", exc_info=True)
                if not self.confirm_action("An error occurred. Continue?"): break
        self.cleanup()

    def execute_full_workflow(self):
        """Executes the complete, linear 8-step post-check workflow."""
        if not self.confirm_action("This will run the full 8-step workflow (~3 hours) and abort on critical errors. Proceed?"):
            return

        workflow_start_time = time.time()
        results_summary: Dict[str, str] = {}
        script_aborted = False

        try:
            # --- FIX: Changed all banner lines from logging.info() to print() ---

            print(f"\n{'#' * 70}\n### Step 1: Phase 1 - Dummy Yes ###\n{'#' * 70}\n")
            execute_script_phase(self.router_ip, self.username, self.password, self.scripts_to_run, "'--dummy' yes", SSH_TIMEOUT_SECONDS, "Phase 1")
            results_summary["Step 1"] = "Phase 1 (Dummy Yes): Success"

            print(f"\n{'#' * 70}\n### Step 2: First Dataplane Monitor ###\n{'#' * 70}\n")
            run_dataplane_monitor_phase(self.router_ip, self.username, self.password, "FIRST", SSH_TIMEOUT_SECONDS, DATAPLANE_MONITOR_TIMEOUT_SECONDS)
            results_summary["Step 2"] = "First Dataplane Monitor: Success"

            print(f"\n{'#' * 70}\n### Step 3: {COUNTDOWN_DURATION_MINUTES}-minute Countdown ###\n{'#' * 70}\n")
            colorful_countdown_timer(COUNTDOWN_DURATION_MINUTES * 60)
            results_summary["Step 3"] = f"{COUNTDOWN_DURATION_MINUTES}-minute Countdown: Success"

            print(f"\n{'#' * 70}\n### Step 4: Phase 2 - Dummy No ###\n{'#' * 70}\n")
            execute_script_phase(self.router_ip, self.username, self.password, self.scripts_to_run, "'--dummy' no", SSH_TIMEOUT_SECONDS, "Phase 2")
            results_summary["Step 4"] = "Phase 2 (Dummy No): Success"

            print(f"\n{'#' * 70}\n### Step 5: Second Dataplane Monitor ###\n{'#' * 70}\n")
            run_dataplane_monitor_phase(self.router_ip, self.username, self.password, "SECOND", SSH_TIMEOUT_SECONDS, DATAPLANE_MONITOR_TIMEOUT_SECONDS)
            results_summary["Step 5"] = "Second Dataplane Monitor: Success"

            print(f"\n{'#' * 70}\n### Step 6: Concurrent Countdown & Show Tech ###\n{'#' * 70}\n")
            if not run_concurrent_countdown_and_show_tech(self.router_ip, self.username, self.password, SSH_TIMEOUT_SECONDS, COUNTDOWN_DURATION_MINUTES, SHOW_TECH_MONITOR_TIMEOUT_SECONDS):
                raise ShowTechError("Concurrent show tech collection failed.")
            results_summary["Step 6"] = "Concurrent Countdown & Show Tech: Success"

            print(f"\n{'#' * 70}\n### Step 7: Phase 3 - Final Dummy No ###\n{'#' * 70}\n")
            execute_script_phase(self.router_ip, self.username, self.password, self.scripts_to_run, "'--dummy' no", SSH_TIMEOUT_SECONDS, "Phase 3")
            results_summary["Step 7"] = "Final Dummy No: Success"

            print(f"\n{'#' * 70}\n### Step 8: ASIC Errors Show Command ###\n{'#' * 70}\n")
            run_asic_errors_show_command(self.router_ip, self.username, self.password, SSH_TIMEOUT_SECONDS)
            results_summary["Step 8"] = "ASIC Errors Show Command: Success"

        except (ScriptExecutionError, DataplaneError, ShowTechError, AsicErrorShowError, RouterCommandError, SSHConnectionError) as e:
            logging.critical(f"CRITICAL FAILURE: Workflow aborted due to: {e}")
            script_aborted = True
            # Update summary with the failure
            failed_step = next((f"Step {i}" for i in range(1, 9) if f"Step {i}" not in results_summary), "Unknown Step")
            results_summary[failed_step] = f"{failed_step.split(':')[0]}: Failed - {e}"
        finally:
            total_time = time.time() - workflow_start_time
            if script_aborted:
                logging.info("--- Workflow Execution Aborted ---")
            else:
                logging.info("--- Workflow Execution Finished Successfully ---")
            print_final_summary_table(results_summary, total_time)

    def run_dataplane_monitor_interactive(self):
        print("\n--- Standalone Dataplane Monitor ---")
        if not self.confirm_action("This will run a single dataplane health check. Proceed?"): return
        try:
            run_dataplane_monitor_phase(self.router_ip, self.username, self.password, "STANDALONE", SSH_TIMEOUT_SECONDS,
                                        DATAPLANE_MONITOR_TIMEOUT_SECONDS)
            logging.info("✅ Standalone dataplane monitor completed successfully.")
        except Exception as e:
            logging.error(f"❌ Standalone dataplane monitor failed: {e}")

    def run_dummy_scripts_interactive(self):
        print("\n--- Standalone Dummy Script Execution ---")
        choice = input("Run with '--dummy yes' (safe) or '--dummy no' (critical)? [yes/no]: ").lower()
        if choice not in ['yes', 'no']:
            print("Invalid choice.")
            return
        dummy_arg = f"'--dummy' {choice}"
        if not self.confirm_action(f"This will run the monitor scripts with {dummy_arg}. Proceed?"): return
        try:
            execute_script_phase(self.router_ip, self.username, self.password, self.scripts_to_run, dummy_arg,
                                 SSH_TIMEOUT_SECONDS, "Standalone")
            logging.info(f"✅ Standalone dummy script execution with {dummy_arg} completed.")
        except Exception as e:
            logging.error(f"❌ Standalone dummy script execution failed: {e}")

    def show_help(self):
        print("\n--- Help & Documentation ---")
        print("This script automates the 8-step post-check process for IOS-XR 7.3.6+ devices.")
        print("\n[1] Execute Full 8-Step Workflow:")
        print("    Runs the complete, linear post-check MoP. This is the primary option.")
        print("    The workflow will automatically stop if a critical error is found.")
        print("\n[2] Run Dataplane Monitor Only:")
        print("    Use this for a quick, standalone health check of the device's dataplane.")
        print("\n[3] Run Dummy Scripts Only:")
        print("    Use this to check for link degradation. '--dummy no' is a critical validation step.")
        print("\nFor support, contact the author at prongupt@cisco.com.")

    def cleanup(self):
        print("\nFramework cleanup...")
        sys.stdout = self.true_original_stdout
        if self.session_log_file_handler: self.session_log_file_handler.close()
        if self.raw_output_file: self.raw_output_file.close()
        total_time = time.time() - self.session_start_time
        print(f"Total Session Time: {format_execution_time(total_time)}")
        print("Framework session ended.")


def main():
    framework = InteractiveFrameworkManager()
    try:
        framework.initialize()
        framework.run_interactive_framework()
    except KeyboardInterrupt:
        print("\n\nFramework interrupted by user.")
    except Exception as e:
        logging.critical(f"A critical framework error occurred: {e}", exc_info=True)
    finally:
        framework.cleanup()


if __name__ == "__main__":
    main()