#!/usr/bin/env python3
import sys
import os
import platform
import subprocess
from pathlib import Path


def ensure_compatible_environment():
    """Smart environment setup - only creates venv when dependencies are missing or incompatible."""

    # First, check if we already have working dependencies in the current environment
    def check_dependencies():
        """Check if required dependencies are available and working."""
        missing_deps = []
        try:
            import paramiko
            # Quick functionality test
            paramiko.SSHClient()  # Test if paramiko works
        except ImportError:
            missing_deps.append("paramiko")
        except Exception as e:
            # Paramiko available but might have issues
            print(f"⚠️  paramiko available but may have compatibility issues: {e}")

        try:
            import prettytable
            # Quick functionality test
            prettytable.PrettyTable()  # Test if prettytable works
        except ImportError:
            missing_deps.append("prettytable")
        except Exception as e:
            print(f"⚠️  prettytable available but may have compatibility issues: {e}")

        return missing_deps

    # Check current environment first
    missing_deps = check_dependencies()

    if not missing_deps:
        print("✅ All required dependencies are available in current environment")
        return  # Everything works, no need for venv

    print(f"📦 Missing dependencies: {', '.join(missing_deps)}")
    print("🔄 Attempting to set up isolated environment...")

    arch = platform.machine()
    script_dir = Path(__file__).parent
    venv_path = script_dir / f".venv_{arch}"
    venv_python = venv_path / "bin" / "python"

    # Check if we're already running in the correct venv
    if sys.prefix == str(venv_path):
        return  # Already in correct environment

    # Check if venv exists and has working dependencies
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
                # Re-execute script with venv Python
                os.execv(str(venv_python), [str(venv_python)] + sys.argv)
        except Exception as e:
            print(f"⚠️  Existing venv test failed: {e}")

    # Only try to create venv if dependencies are missing and system supports it
    print(f"🔧 Creating virtual environment for {arch} architecture...")

    try:
        # Test if system supports venv creation
        import venv

        # Create venv with error handling
        venv.create(venv_path, with_pip=True)
        print("✅ Virtual environment created successfully")

        # Install dependencies
        pip_path = venv_path / "bin" / "pip"

        print("📦 Installing dependencies...")
        subprocess.run([str(pip_path), "install", "--upgrade", "pip"],
                       check=True, capture_output=True, timeout=60)
        subprocess.run([str(pip_path), "install", "paramiko", "prettytable"],
                       check=True, capture_output=True, timeout=120)

        print("✅ Dependencies installed successfully")
        print("🔄 Restarting script with virtual environment...\n")

        # Re-execute with new venv
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

    # Final dependency check before proceeding
    final_missing = check_dependencies()
    if final_missing:
        print(f"\n❌ Still missing dependencies: {', '.join(final_missing)}")
        print(f"📦 Install with: pip3 install {' '.join(final_missing)}")
        print(f"   or: python3 -m pip install {' '.join(final_missing)}")

        user_choice = input("Continue anyway? This may cause script failures. (y/N): ").lower()
        if user_choice not in ['y', 'yes']:
            print("Script execution cancelled.")
            sys.exit(1)
        print("⚠️  Proceeding with missing dependencies - expect potential failures...\n")
    else:
        print("✅ All dependencies now available. Continuing...\n")


# Run environment check before any other imports
ensure_compatible_environment()

import paramiko
import time
import getpass
import re
import threading
from prettytable import PrettyTable
import datetime
import logging
import json
import glob
from typing import Optional, List, Tuple, Dict, Any

# === ENHANCED CONSTANTS ===
SSH_TIMEOUT_SECONDS = 15
DATAPLANE_MONITOR_TIMEOUT_SECONDS = 1200  # 20 minutes
SHOW_TECH_MONITOR_TIMEOUT_SECONDS = 3600  # 60 minutes
WAIT_TIME_MINUTES = 20
COUNTDOWN_DURATION_MINUTES = 65

# Define common prompt patterns for IOS-XR bash and CLI
PROMPT_PATTERNS = [
    r'#\s*$',  # Matches '#' followed by optional whitespace at end of line
    r'\$\s*$'  # Matches '$' for non-root users
]

# Global variables to store show tech timing information
SHOW_TECH_START_TIMESTAMP_FROM_LOG: Optional[str] = None
SHOW_TECH_END_TIMESTAMP_FROM_LOG: Optional[str] = None

# Global variables for session log files
session_log_file_console_mirror = None
session_log_file_raw_output = None
router_log_dir = None


# === ENHANCED EXCEPTIONS ===
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


class WorkflowStateError(Exception):
    """Custom exception for workflow state management failures."""
    pass


# === ENHANCED LOGGING CLASSES ===
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
        if msg.startswith('✓ ') and ('passed' in msg or 'complete' in msg or 'Success' in msg):
            return f'{self.formatTime(record, self.datefmt)} - \033[92m{record.levelname}\033[0m - \033[1;92m{msg}\033[0m'
        elif msg.startswith('✗ ') and ('failed' in msg or 'error' in msg):
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


# === STATE MANAGEMENT (SIMPLIFIED) ===
class WorkflowState:
    """Simplified workflow state management"""

    def __init__(self, hostname):
        self.hostname = hostname
        self.state_dir = os.path.join(os.getcwd(), hostname)
        self.state_file = os.path.join(self.state_dir, f"{hostname}_workflow_state.json")
        self.state = {
            'hostname': hostname,
            'started_at': datetime.datetime.now().isoformat(),
            'completed_phases': {},
            'total_errors': 0
        }

    # Add to WorkflowState class in utils
    def get_workflow_summary(self):
        """Get workflow summary statistics"""
        total_phases = len(self.state.get('completed_phases', {}))
        successful_phases = sum(1 for phase in self.state.get('completed_phases', {}).values()
                                if phase.get('success', False))

        return {
            'completion_rate': f"{(successful_phases / max(total_phases, 1) * 100):.1f}%",
            'successful_phases': successful_phases,
            'total_errors': self.state.get('total_errors', 0)
        }


    def save_phase_completion(self, phase, results, errors=None):
        """Save phase completion status"""
        self.state['completed_phases'][phase] = {
            'timestamp': datetime.datetime.now().isoformat(),
            'results': results,
            'errors': errors or [],
            'success': len(errors or []) == 0
        }
        self.state['total_errors'] += len(errors or [])

        try:
            os.makedirs(self.state_dir, exist_ok=True)
            with open(self.state_file, 'w') as f:
                json.dump(self.state, f, indent=2, default=str)
            logging.debug(f"💾 Saved workflow state to {self.state_file}")
        except Exception as e:
            logging.warning(f"Could not save workflow state: {e}")


class LiveWorkflowDashboard:
    """Simplified live workflow progress tracking"""

    def __init__(self, total_phases=5):
        self.total_phases = total_phases
        self.current_phase = 0
        self.phase_start_time = None
        self.workflow_start_time = time.time()

    def start_phase(self, phase_name):
        """Mark start of new phase"""
        self.current_phase += 1
        self.phase_start_time = time.time()

        elapsed_workflow = time.time() - self.workflow_start_time
        progress = (self.current_phase - 1) / self.total_phases * 100

        print(f"\n📊 Workflow Progress: {progress:5.1f}% | Phase {self.current_phase}/{self.total_phases}: {phase_name}")

    def update_phase_progress(self, phase, step, total_steps, status):
        """Update live dashboard"""
        if self.phase_start_time:
            step_progress = (step / total_steps) * 100
            print(f"🎯 {phase} Step {step}/{total_steps} ({step_progress:4.1f}%) - {status}")

    def complete_phase(self, phase_name, success=True, errors=None):
        """Mark phase completion"""
        if self.phase_start_time:
            phase_time = time.time() - self.phase_start_time
            status_icon = "✅" if success else "❌"

            print(f"{status_icon} {phase_name} completed in {format_execution_time(phase_time)}")

            if errors and len(errors) > 0:
                print(f"⚠️  Errors encountered: {len(errors)}")


def create_enhanced_workflow_manager(hostname):
    """Factory function to create workflow manager"""

    class EnhancedWorkflowManager:
        def __init__(self, hostname):
            self.hostname = hostname
            self.state = WorkflowState(hostname)
            self.dashboard = LiveWorkflowDashboard()

    return EnhancedWorkflowManager(hostname)


# === ENHANCED CONNECTION FUNCTIONS ===
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


def smart_retry_with_context(func, max_retries=3, context=""):
    """FIXED - Enhanced retry that learns from previous failures"""

    def should_retry_based_on_error(error, attempt):
        """Intelligent retry decision based on error type"""
        error_str = str(error).lower()

        # NEVER retry these error types
        no_retry_errors = ["authentication failed", "permission denied", "degraded links found"]
        if any(no_retry in error_str for no_retry in no_retry_errors):
            logging.info(f"❌ Not retrying {context} - error type not suitable for retry")
            return False

        # Always retry connection issues
        retry_errors = ["timeout", "connection refused", "network unreachable", "ssh"]
        if any(retry_err in error_str for retry_err in retry_errors):
            return attempt < max_retries - 1

        return attempt < max_retries - 1

    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            if should_retry_based_on_error(e, attempt):
                wait_time = (attempt + 1) * 5
                logging.info(f"🔄 Smart retry {attempt + 1}/{max_retries} for {context} after {wait_time}s...")
                time.sleep(wait_time)
            else:
                # DON'T log as "not retrying" for expected errors like degraded links
                if "degraded links found" not in str(e).lower():
                    logging.debug(f"Not retrying {context} - error type: {type(e).__name__}")
                raise e

    raise Exception(f"All {max_retries} smart retry attempts failed for {context}")


# === RELIABILITY ENHANCEMENTS (SIMPLIFIED) ===
def pre_flight_check(router_ip, username, password, phase_name):
    """SIMPLIFIED - Basic router readiness check"""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(router_ip, username=username, password=password, timeout=15)

        # Basic responsiveness test
        stdin, stdout, stderr = client.exec_command("show clock", timeout=15)
        output = stdout.read().decode('utf-8', errors='ignore')
        client.close()

        if len(output) > 10:  # Got reasonable output
            logging.info(f"✅ Pre-flight check passed for {phase_name}")
            return True
        else:
            logging.warning(f"⚠️ Pre-flight check questionable for {phase_name}")
            return False

    except Exception as e:
        logging.warning(f"⚠️ Pre-flight check failed for {phase_name}: {e}")
        return False


def suggest_recovery_actions(error_type, phase, context=""):
    """SIMPLIFIED - Provide specific recovery suggestions"""
    error_name = error_type.__name__ if hasattr(error_type, '__name__') else str(error_type)

    if error_name == "ScriptExecutionError" and "degraded links" in context.lower():
        # Don't provide suggestions - the calling script will handle degraded links
        return

    simple_suggestions = {
        'DataplaneError': [
            "🔍 Check fabric card status with 'show platform'",
            "🔧 Verify LC-FC connections are secure"
        ],
        'SSHConnectionError': [
            "🌐 Check network connectivity to router",
            "🔐 Verify SSH credentials are correct"
        ],
        'ShowTechError': [
            "💾 Check available disk space on harddisk:",
            "🕒 Wait for any ongoing show tech to complete"
        ]
    }

    if error_name in simple_suggestions:
        print(f"💡 Recovery suggestions for {phase}:")
        for suggestion in simple_suggestions[error_name]:
            print(f"   {suggestion}")


# === ENHANCED SSH UTILITIES ===
def countdown_timer(seconds, console_stream):
    """Enhanced countdown timer matching other parts"""
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
    logging.info(f'Countdown Timer: Starting for {seconds // 60:02d}:{seconds % 60:02d}.')

    while seconds:
        mins, secs = divmod(seconds, 60)
        timer = f'{mins:02d}:{secs:02d}'
        print(f'\rWaiting... {timer} remaining', end='', flush=True)
        time.sleep(1)
        seconds -= 1
    print(f'\rWaiting... 00:00 - Time is up!   ')


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
    """Enhanced script execution with better logging"""
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


# === VERSION-SPECIFIC FUNCTIONS ===
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

        stdin, stdout, stderr = client.exec_command("show running | i hostname", timeout=30)
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


# === EXECUTION TIME UTILITIES ===
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


# === 7.3.5 DATAPLANE MONITORING ===
def parse_dataplane_output_for_errors(output_text: str) -> bool:
    """Enhanced dataplane error parsing with explicit failure detection"""
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


def poll_dataplane_monitoring_735(shell: paramiko.Channel, max_poll_duration_sec: int) -> bool:
    """7.3.5 specific dataplane monitoring (foreground mode)"""
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


def run_dataplane_monitor_phase(router_ip: str, username: str, password: str, monitor_description: str,
                                ssh_timeout: int, dataplane_timeout: int) -> bool:
    """7.3.5 dataplane monitoring phase with enhanced connection"""
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

        logging.info(f"Running 'monitor dataplane-health' for IOS-XR 7.3.5.")
        dataplane_check_clean = poll_dataplane_monitoring_735(shell, dataplane_timeout)

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


def suggest_dataplane_recovery_actions(part: object, step: object, monitor_description: object) -> None:
    """Enhanced dataplane-specific recovery guidance
    :rtype: None
    """
    restart_instructions = {
        '3a': {
            'step_b': "Re-run Part 3a from Step a (restart entire Phase 1)",
        },
        '3b': {
            'step_f': "Re-run Part 3a from Step e (restart from Phase 1 manual reload step)",
            'step_h': "Re-run Part 3a from Step e (restart from Phase 1 manual reload step)",
        },
        '3c': {
            'step_l': "Re-run Part 3c from Step k (restart entire Phase 3)",
            'step_o': "Re-run Part 3c from Step k (restart entire Phase 3)",
        }
    }

    print(f"🚨 DATAPLANE MONITORING FAILURE - {step}")
    print(f"📋 DATAPLANE ERROR RECOVERY PROCEDURE:")
    print(f"   🔍 1. Review dataplane error details above")
    print(f"   📊 2. Check system status: 'show platform'")
    print(f"   🔧 3. Verify all fabric cards show OPERATIONAL status")
    print(f"   🔗 4. Inspect LC-FC physical connections")
    print(f"   ⚡ 5. Consider fabric card reload if errors persist")
    print(f"   ⏰ 6. Wait for system stabilization (10-15 minutes)")

    # Specific restart instruction based on part and step
    restart_info = restart_instructions.get(part, {}).get(step, "Contact support for guidance")
    print(f"   🔄 7. {restart_info}")
    print(f"   ❌ 8. Do NOT proceed to next phase with dataplane errors")
    print(f"   📞 9. Escalate to hardware team if issues persist after restart")


def execute_script_phase(router_ip: str, username: str, password: str, scripts_to_run: List[str],
                         script_arg_option: str, ssh_timeout: int, phase_name: str = "") -> bool:
    """FIXED - 7.3.5 script phase execution with proper error handling"""
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
            errors_found_in_dummy_no = False
            for s_name, s_output in scripts_outputs:
                group_num = get_group_number_from_script_name(s_name)
                detailed_errors = parse_script_output_for_errors(s_name, s_output)
                format_and_print_error_report(s_name, group_num, detailed_errors, phase_name)
                if detailed_errors:
                    errors_found_in_dummy_no = True

            # FIXED: Simply raise the error, don't double-handle
            if errors_found_in_dummy_no:
                raise ScriptExecutionError("Degraded links found")

        return True

    except paramiko.AuthenticationException as e:
        raise SSHConnectionError(f"Authentication failed for script phase '{script_arg_option}': {e}")
    except paramiko.SSHException as e:
        raise SSHConnectionError(f"SSH error during script phase '{script_arg_option}': {e}")
    except RouterCommandError as e:
        raise RouterCommandError(f"Router command error during script phase '{script_arg_option}': {e}")
    except ScriptExecutionError:
        # FIXED: Just re-raise ScriptExecutionError as-is, don't modify
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


# [Continue with all other existing functions from the original utils...]

# === ERROR PARSING FUNCTIONS ===
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
    """7.3.5 compatible script output parsing for faulty link details"""
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


def format_and_print_error_report(script_name: str, group_number: str, error_details: List[Dict[str, str]],
                                  phase_name: str = ""):
    """7.3.5 compatible error reporting with consistent table format"""
    phase_identifier = f" ({phase_name})" if phase_name else ""

    # Use EXACT same table formatting as Parts II/III - manual column widths
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
        for detail in error_details:
            # Extract FC and LC information for simplified display
            link_full = detail['Link Connection']
            fc_match = re.search(r'0/FC(\d+)', link_full)
            lc_match = re.search(r'0/(\d+)/CPU0', link_full)

            if fc_match and lc_match:
                simplified_link = f"FC{fc_match.group(1)} - LC{lc_match.group(1)}"
            else:
                simplified_link = link_full[:25] + "..." if len(link_full) > 25 else link_full

            # DETAILED FORMAT (matching Parts II/III): Show values when Bad
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

        logging.error(
            f"\033[1;91m✗ {len(error_details)} errors detected for Group {group_number}{phase_identifier}.\033[0m")

    table_output_lines.append(f"{separator_line}")

    # Print the entire table as one block
    table_output = "\n".join(table_output_lines)
    print(table_output)


def wait_for_prompt_after_ctrlc(shell: paramiko.Channel, timeout_sec: int = 60) -> bool:
    """Waits for shell prompt after Ctrl+C"""
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


# === SHOW TECH FUNCTIONS ===
def run_show_tech_fabric(shell: paramiko.Channel, hostname: str) -> bool:
    """7.3.5 show tech fabric collection"""
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


def run_show_tech_phase(router_ip: str, username: str, password: str, ssh_timeout: int) -> bool:
    """7.3.5 show tech phase with retry connection"""
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    shell = None
    try:
        logging.info(f"Connecting to {router_ip} for Show Tech collection...")
        connect_with_retry(client, router_ip, username, password)
        logging.info(f"Successfully connected for Show Tech collection.")

        shell = client.invoke_shell()
        time.sleep(1)
        logging.info("--- Initial Shell Output (Show Tech) ---")
        read_and_print_realtime(shell, timeout_sec=2)
        logging.info("--- End Initial Shell Output ---")

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
            try:
                shell.send("exit\n")
                time.sleep(1)
                while shell.recv_ready():
                    shell.recv(65535).decode('utf-8', errors='ignore')
            except Exception as e:
                logging.warning(f"Error clearing shell buffer on exit: {e}")
            finally:
                try:
                    shell.close()
                except Exception as e:
                    logging.warning(f"Error closing Paramiko shell channel: {e}")
        if client:
            try:
                client.close()
            except Exception as e:
                logging.warning(f"Error closing Paramiko SSH client: {e}")
        logging.info("SSH connection closed.")


def run_clear_asic_counters(router_ip: str, username: str, password: str, ssh_timeout: int) -> bool:
    """7.3.5 ASIC counter clearing with retry connection"""
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    shell = None
    try:
        logging.info(f"Connecting to {router_ip} to clear ASIC counters...")
        connect_with_retry(client, router_ip, username, password)
        logging.info(f"Successfully connected to {router_ip}.")

        shell = client.invoke_shell()
        time.sleep(1)
        logging.info("--- Initial Shell Output (Clear ASIC Counters) ---")
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
            raise RouterCommandError("Failed to establish bash prompt for ASIC counter clearing.")

        clear_command = 'asic_errors_show "-n" "A" "-a" "0x7" "-i" "0x100" "-C" "0x1" "-e" "0x0" "-c"'
        logging.info(f"Running command: {clear_command}")

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
            try:
                shell.send("exit\n")
                time.sleep(1)
                while shell.recv_ready():
                    shell.recv(65535).decode('utf-8', errors='ignore')
            except Exception as e:
                logging.warning(f"Error clearing shell buffer on exit: {e}")
            finally:
                try:
                    shell.close()
                except Exception as e:
                    logging.warning(f"Error closing Paramiko shell channel: {e}")
        if client:
            try:
                client.close()
            except Exception as e:
                logging.warning(f"Error closing Paramiko SSH client: {e}")
        logging.info("SSH connection closed.")


# === FINAL SUMMARY FUNCTIONS ===
def print_final_summary(results: Dict[str, str], total_execution_time: float = None):
    """Enhanced final summary table with execution time"""
    print(f"\n--- Final Script Summary ---")

    # Add execution time display if provided
    if total_execution_time is not None:
        formatted_time = format_execution_time(total_execution_time)
        execution_time_text = f"Total time for execution: {formatted_time}"
        time_table_width = max(len(execution_time_text) + 4, 60)

        time_separator = "+" + "-" * (time_table_width - 2) + "+"
        time_content = f"| {execution_time_text:<{time_table_width - 4}} |"

        print(time_separator)
        print(time_content)
        print(time_separator)

    # Enhanced summary table
    summary_table = PrettyTable()
    summary_table.field_names = ["Test #", "Section Name", "Status"]

    # Center align Test number, left align others
    summary_table.align["Test #"] = "c"
    summary_table.align["Section Name"] = "l"
    summary_table.align["Status"] = "l"

    def colorize_status(status):
        if "Success" in status:
            return f"\033[1;92m{status}\033[0m"  # Bright Green
        elif "Failed" in status:
            return f"\033[1;91m{status}\033[0m"  # Bright Red
        elif "Collection Only" in status or "Instructed User" in status:
            return f"\033[1;94m{status}\033[0m"  # Bright Blue
        else:
            return status

    test_number = 1
    for step_num, result in results.items():
        section_name = result.split(': ')[0] if ': ' in result else result
        status_text = result.split(': ')[1] if ': ' in result else result
        colored_status = colorize_status(status_text)
        summary_table.add_row([str(test_number), section_name, colored_status])
        test_number += 1

    print(summary_table)
    logging.info(f"--- End Final Script Summary ---")


# ADD these placeholder functions to utils (at the end):


def correlate_errors_across_phases(hostname_dir):
    """DISABLED - Placeholder to prevent import errors"""
    logging.debug("Cross-phase error correlation disabled")
    return []  # Return empty list


def analyze_workflow_performance(hostname_dir):
    """DISABLED - Placeholder to prevent import errors"""
    logging.debug("Performance analysis disabled")
    return {}, []  # Return empty dict and list