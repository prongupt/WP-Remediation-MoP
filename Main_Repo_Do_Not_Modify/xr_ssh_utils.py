# xr_ssh_utils.py

import paramiko
import time
import re
import logging
import sys
import os
import datetime
from typing import List, Tuple, Dict, Any, Optional

# --- Constants ---
SSH_TIMEOUT_SECONDS = 15
# PROMPT_PATTERNS from the original script 1, which includes more specific patterns
# for IOS-XR CLI prompts like '>', ']', ')' in addition to '#' and '$'.
PROMPT_PATTERNS = [
    r'#\s*$',
    r'>\s*$',
    r'\]\s*$',
    r'\)\s*$',
    r'\$\s*$'  # Added for completeness, usually for bash prompts
]


# --- Custom Exceptions ---
class SSHConnectionError(Exception):
    """Custom exception for SSH connection failures."""
    pass


class RouterCommandError(Exception):
    """Custom exception for command execution failures on the router."""
    pass


class HostnameRetrievalError(Exception):
    """Custom exception for failures during hostname retrieval."""
    pass


# You can add other generic exceptions here if they are truly reusable across scripts.
# For now, I'll keep the more specific ones in the main script.


# --- Custom Tee class for logging stdout to file and console ---
class Tee(object):
    """
    A class that redirects stdout to multiple file-like objects.
    Used to simultaneously print to console and log to a file.
    """

    def __init__(self, *files):
        self.files = files

    def write(self, obj):
        for f in self.files:
            f.write(obj)
            # Flush immediately to ensure real-time logging
            f.flush()

    def flush(self):
        for f in self.files:
            f.flush()


# --- Core SSH Interaction Functions ---

def read_and_print_realtime(shell_obj: paramiko.Channel, timeout_sec: int = 60, print_real_time: bool = True) -> Tuple[
    str, bool]:
    """
    Reads shell output and prints in real-time until a prompt is found or timeout occurs.
    Returns the full accumulated output and a boolean indicating if a prompt was found.
    Ensures a newline is printed at the end if the output didn't already end with one,
    when print_real_time is True.
    """
    full_output_buffer = ""
    start_time = time.time()
    prompt_found = False
    prompt_check_buffer = ""

    while time.time() - start_time < timeout_sec:
        if shell_obj.recv_ready():
            # Use smaller chunks for more responsive real-time printing
            data = shell_obj.recv(1024).decode('utf-8', errors='ignore')
            if data:
                if print_real_time:
                    print(f"{data}", end='')
                full_output_buffer += data
                prompt_check_buffer += data

                # Keep only the last few lines for prompt checking to avoid large buffer
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
            else:
                # No data received, but recv_ready() was true, might mean connection closed
                break
        else:
            time.sleep(0.1)

    # If timeout occurs, and we were printing real-time, ensure a newline
    if print_real_time and full_output_buffer and not full_output_buffer.endswith('\n'):
        print()
    return full_output_buffer, prompt_found


def execute_command_in_shell(shell: paramiko.Channel, command: str, command_description: str,
                             timeout: int = 60, print_real_time_output: bool = False) -> str:
    """
    Sends a command to the shell, prints output in real-time (or not), and waits for prompt.
    Returns the full command output string.
    Raises RouterCommandError if prompt is not found.
    """
    # The Tee class handles writing to the raw output file, so we just print to stdout
    # and return the string.
    print(f"\n--- Command: {command} ---")  # This will go to console and raw output file
    logging.info(f"Sending '{command_description}' ('{command}')...")  # This will go to session log and console

    shell.send(command + "\n")
    # Small delay after sending to allow initial output to buffer
    time.sleep(0.5)
    output, prompt_found = read_and_print_realtime(shell, timeout_sec=timeout, print_real_time=print_real_time_output)

    if not prompt_found:
        logging.warning(f"Prompt not detected after '{command_description}'. Attempting to send newline and re-check.")
        shell.send("\n")
        output_retry, prompt_found_retry = read_and_print_realtime(shell, timeout_sec=5,
                                                                   print_real_time=print_real_time_output)
        output += output_retry
        if not prompt_found_retry:
            raise RouterCommandError(
                f"Failed to reach prompt after '{command_description}' re-check. Output: {output}")
    return output


def get_sanitized_hostname_from_router(router_ip: str, username: str, password: str,
                                       ssh_timeout: int = SSH_TIMEOUT_SECONDS,
                                       command_timeout: int = 30) -> str:
    """
    Connects to the router, executes 'show running | i hostname', and extracts a sanitized hostname.
    Returns the sanitized hostname string.
    Raises HostnameRetrievalError on failure.
    """
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        logging.info(f"Attempting to connect to {router_ip} to retrieve hostname...")
        client.connect(router_ip, port=22, username=username, password=password, timeout=ssh_timeout,
                       look_for_keys=False)  # <--- ADDED look_for_keys=False HERE
        logging.info(f"Successfully connected to {router_ip} for hostname retrieval.")

        stdin, stdout, stderr = client.exec_command("show running | i hostname", timeout=command_timeout)
        output = stdout.read().decode('utf-8', errors='ignore')
        error_output = stderr.read().decode('utf-8', errors='ignore')

        if error_output:
            logging.error(f"Error during hostname retrieval command: {error_output}")
            raise HostnameRetrievalError(f"Command execution failed: {error_output}")

        hostname = None
        for line in output.strip().splitlines():
            line = line.strip()
            if line.startswith("hostname "):
                hostname = line.split(" ", 1)[1].strip()
                break

        if not hostname:
            raise HostnameRetrievalError(f"Hostname not found in command output: \n{output}")

        # Sanitize the hostname
        temp_hostname = hostname.replace('.', '-')
        sanitized_hostname = re.sub(r'[^a-zA-Z0-9_-]', '', temp_hostname)
        logging.info(f"Retrieved hostname: {hostname}, Sanitized for directory: {sanitized_hostname}")
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


# --- Logging and File Management Utilities ---

def setup_dynamic_logging(sanitized_hostname: str, script_name_prefix: str, original_stdout: Any) -> Tuple[
    str, Any, Any, str]:
    """
    Sets up dynamic logging to console and files based on hostname and script prefix.
    Returns (hostname_dir, session_log_file_handle, raw_output_file_handle, timestamp).
    """
    # Ensure a clean slate for logging handlers before custom setup
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    # Add a basic console handler for initial messages
    console_handler = logging.StreamHandler(original_stdout)
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    logging.root.addHandler(console_handler)
    logging.root.setLevel(logging.INFO)  # Ensure base level is INFO

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname_dir = os.path.join(os.getcwd(), sanitized_hostname)

    try:
        os.makedirs(hostname_dir, exist_ok=True)
        logging.info(f"Ensured router log directory exists: {os.path.abspath(hostname_dir)}")
    except OSError as e:
        logging.critical(
            f"Failed to create or access router log directory {hostname_dir}: {e}. Script cannot proceed without a log directory. Exiting.")
        sys.exit(1)

    session_log_path = os.path.join(hostname_dir,
                                    f"{sanitized_hostname}_{script_name_prefix}_session_log_{timestamp}.txt")
    raw_output_log_path = os.path.join(hostname_dir,
                                       f"{sanitized_hostname}_{script_name_prefix}_raw_output_{timestamp}.txt")

    session_log_file_handle = None
    raw_output_file_handle = None

    try:
        session_log_file_handle = logging.FileHandler(session_log_path, encoding='utf-8')
        session_log_file_handle.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.root.addHandler(session_log_file_handle)
        logging.info(f"Internal script logs will be saved to: {session_log_path}")
    except IOError as e:
        logging.error(
            f"Could not open internal session log file {session_log_path}: {e}. Internal logs will only go to console.")

    try:
        raw_output_file_handle = open(raw_output_log_path, 'w', encoding='utf-8')
        sys.stdout = Tee(original_stdout, raw_output_file_handle)
        print(f"All console output (including router raw output) will be logged to: {raw_output_log_path}")
    except IOError as e:
        logging.error(
            f"Could not open raw output log file {raw_output_log_path}: {e}. Raw output will only go to console.")
        # If Tee fails, ensure sys.stdout is restored to original
        sys.stdout = original_stdout

    return hostname_dir, session_log_file_handle, raw_output_file_handle, timestamp


def cleanup_logging(original_stdout: Any, session_log_file_handle: Optional[Any],
                    raw_output_file_handle: Optional[Any]):
    """Restores original stdout and closes log files."""
    sys.stdout = original_stdout  # Restore original stdout first

    # Remove and close file handlers
    for handler in logging.root.handlers[:]:
        if isinstance(handler, logging.FileHandler):
            if session_log_file_handle and handler.baseFilename == session_log_file_handle.baseFilename:
                logging.root.removeHandler(handler)
                handler.close()
                break  # Assuming only one session log file handler

    if raw_output_file_handle:
        raw_output_file_handle.close()

    # Remove any remaining StreamHandlers that might have been added by setup_dynamic_logging
    # (excluding the initial one that might have been there before script execution)
    for handler in logging.root.handlers[:]:
        if isinstance(handler, logging.StreamHandler) and handler.stream == original_stdout:
            logging.root.removeHandler(handler)
            break