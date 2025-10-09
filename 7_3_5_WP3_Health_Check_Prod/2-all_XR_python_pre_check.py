import paramiko
import time
import os
import getpass
import re
import logging
import sys # Import sys for stdout redirection
import datetime # Import datetime for timestamp in log filenames

# --- Constants and Configuration ---
# SCRIPT_LOG_FILE is removed as its function is now split and dynamically named
# based on hostname and log type.

# Default values for timeouts
SSH_TIMEOUT_SECONDS = 15
COMMAND_TIMEOUT_SECONDS = 30
SCRIPT_EXECUTION_TIMEOUT_SECONDS = 600 # 10 minutes for scripts

# Define common prompt patterns for IOS-XR bash
PROMPT_PATTERNS = [
    r'#\s*$', # Matches '#' followed by optional whitespace at end of line (e.g., router# or root@host:~# )
    r'\$\s*$' # Matches '$' for non-root users (less likely after 'attach location')
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


# --- SimpleProgressBar Class Definition ---
class SimpleProgressBar:
    _active_pbar = None  # Class-level variable to hold the active pbar instance

    def __init__(self, total, original_console_stream, description="", color_code='\033[94m'):
        self.total = total
        self.current = 0
        self.description = description
        self.color_code = color_code
        self.original_console_stream = original_console_stream
        self.start_time = time.time()
        self.bar_length = 50
        self._last_pbar_line_length = 0  # To track length for clearing
        self.update_display()

    def update(self, step=1):
        self.current += step
        if self.current > self.total:  # Cap current at total
            self.current = self.total
        self.update_display()

    def update_display(self):
        percent = ("{0:.1f}").format(100 * (self.current / float(self.total)))
        filled_length = int(self.bar_length * self.current // self.total)
        bar = '█' * filled_length + '-' * (self.bar_length - filled_length)

        elapsed_time = time.time() - self.start_time

        # Estimate remaining time if enough progress has been made
        estimated_remaining_time_str = "--:--"
        if self.current > 0 and self.current < self.total:
            avg_time_per_step = elapsed_time / self.current
            remaining_steps = self.total - self.current
            estimated_remaining_time = avg_time_per_step * remaining_steps
            estimated_remaining_time_str = self._format_time(estimated_remaining_time)
        elif self.current == self.total:
            estimated_remaining_time_str = "00:00"  # No remaining time if done

        time_info = f"[{self._format_time(elapsed_time)}<{estimated_remaining_time_str}]"

        # Construct the message and write it
        pbar_message = f"{self.color_code}{self.description} |{bar}| {percent}% {time_info}\033[0m"
        self.original_console_stream.write('\r' + pbar_message)
        self.original_console_stream.flush()
        self._last_pbar_line_length = len(pbar_message)  # Store length of the actual pbar message

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
        # Ensure the progress bar is at 100% and on a new line when finished
        self.current = self.total  # Ensure it shows 100%
        self.update_display()
        self.original_console_stream.write('\n')  # Ensure newline at the very end
        self.original_console_stream.flush()
        SimpleProgressBar._active_pbar = None


# Custom logging handler to interact with the progress bar
class ProgressBarAwareHandler(logging.StreamHandler):
    def emit(self, record):
        pbar = SimpleProgressBar._active_pbar
        if pbar:
            pbar.hide()  # Hide the progress bar
            self.stream.write(self.format(record) + '\n')  # Print log message on its own line
            self.flush()
            pbar.show()  # Show the progress bar again
        else:
            # If no active progress bar, emit normally to the stream
            super().emit(record)


# The modified Tee class (FIXED: Removed logic that adds extra newlines)
class Tee:
    def __init__(self, stdout_stream, file_object):
        self.stdout = stdout_stream  # Using user's original variable name for console stream
        self.file_object = file_object

    def write(self, data):
        pbar = SimpleProgressBar._active_pbar
        if pbar:
            pbar.hide()  # Hide the progress bar
            self.stdout.write(data)  # Write print() output as received
            self.stdout.flush()
            pbar.show()  # Show the progress bar again
        else:
            self.stdout.write(data) # Write print() output as received
            self.stdout.flush()
        self.file_object.write(data)  # Always write to file
        self.file_object.flush()

    def flush(self):
        self.stdout.flush()
        self.file_object.flush()


# --- Initial Logging Configuration (minimal, to be reconfigured later) ---
# Removed basicConfig here, will be set up dynamically in main()


def countdown_timer(seconds):
    initial_mins, initial_secs = divmod(seconds, 60)
    logging.info(f'Countdown Timer: Starting for {initial_mins:02d}:{initial_secs:02d}.') # Log once at start

    while seconds:
        mins, secs = divmod(seconds, 60)
        timer = f'{mins:02d}:{secs:02d}'
        # This print will go through the Tee class, which correctly handles flushing and file writing.
        # Since no progress bar is active during the countdown, Tee will print directly.
        print(f'\rCountdown Timer: {timer}', end='', flush=True)
        time.sleep(1)
        seconds -= 1
    # Clear the countdown line and print final message
    print(f'\rCountdown Timer: 00:00 - Time is up! ')
    logging.info('Countdown Timer: 00:00 - Time is up!') # Log once at end


def read_and_print_realtime(shell_obj, timeout_sec=600, print_realtime: bool = True):
    """
    Reads shell output and prints in real-time until a prompt is found or timeout occurs.
    Returns the full accumulated output and a boolean indicating if a prompt was found.
    Ensures a newline is printed at the end if the output didn't already end with one,
    when print_realtime is True.
    """
    full_output_buffer = ""
    start_time = time.time()
    prompt_found = False
    prompt_check_buffer = ""
    last_output_was_dots = False # Flag to track if the last output was a horizontal dot sequence

    while time.time() - start_time < timeout_sec:
        if shell_obj.recv_ready():
            data = shell_obj.recv(1024).decode('utf-8', errors='ignore') # Read in smaller chunks
            if data:
                if print_realtime:
                    # Check if the data consists solely of dots followed by a newline
                    # This pattern matches one or more dots followed by a newline.
                    if re.fullmatch(r'\.+\n', data):
                        # Replace the newline with a space to make dots appear horizontally
                        processed_data = data.replace('\n', ' ')
                        # Print the processed data without adding any extra newline
                        print(f"{processed_data}", end='', flush=True)
                        last_output_was_dots = True
                    else:
                        # For all other output, print as usual (via Tee, which now won't add extra newlines)
                        print(f"{data}", end='')
                        last_output_was_dots = False # Reset flag if other output is printed

                full_output_buffer += data
                prompt_check_buffer += data

                # Keep only the last few lines for prompt checking to avoid large buffer
                if len(prompt_check_buffer) > 500: # Keep last 500 chars for prompt check
                    prompt_check_buffer = prompt_check_buffer[-500:]

                # Check for prompt in the last line of the prompt_check_buffer
                lines = prompt_check_buffer.strip().splitlines()
                if lines:
                    last_line = lines[-1]
                    for pattern in PROMPT_PATTERNS:
                        if re.search(pattern, last_line):
                            prompt_found = True
                            # If a prompt is found, and we were printing real-time,
                            # ensure the cursor is on a new line for subsequent logs.
                            if print_realtime and last_output_was_dots:
                                print() # Add a newline to separate horizontal dots from next output
                            elif print_realtime and not data.endswith('\n'):
                                print() # Add a newline if the last data didn't have one
                            return full_output_buffer, prompt_found
            else: # No data received, but recv_ready() was true, might mean connection closed
                break # Exit loop if no data is received on a ready channel
        else:
            time.sleep(0.1) # Short sleep to avoid busy-waiting

    # If timeout occurs, and we were printing real-time, ensure a newline
    if print_realtime and full_output_buffer and not full_output_buffer.endswith('\n'):
        print() # This print will also go through Tee
    return full_output_buffer, prompt_found


def execute_command_in_shell(shell, command, command_description, timeout=COMMAND_TIMEOUT_SECONDS,
                             print_realtime_output: bool = True):
    """
    Sends a command to the shell, prints output in real-time (or not), and waits for prompt.
    Returns True on success (prompt found).
    Raises RouterCommandError if prompt is not found.
    """
    logging.info(f"Sending '{command_description}'...")
    shell.send(command + "\n")
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


def run_script_list_phase(shell, scripts_to_run, script_arg_option, pbar=None): # Added pbar argument
    """
    Executes a list of Python scripts sequentially within an already established shell session.
    Returns a list of tuples: (script_name, full_script_output_string).
    """
    all_scripts_raw_output = [] # To store (script_name, output_string) for later parsing

    for script_name in scripts_to_run:
        # Extract group number from script name
        group_match = re.search(r'group(\d+)\.py', script_name)
        group_number = group_match.group(1) if group_match else "Unknown"

        # Clean up script_arg_option for logging (remove surrounding quotes if present)
        script_arg_option_for_log = script_arg_option.strip("'")

        # Adjust padding to ensure it fits on one line
        padding_len = 15 # Reduced from 50 to make it fit better in logs
        logging.info(
            f"{'=' * padding_len}--- Running Group {group_number} with option {script_arg_option_for_log} ---{'=' * padding_len}")

        command_to_execute = f"python3 {script_name} {script_arg_option}"
        logging.info(f"Sending '{command_to_execute}'...")
        shell.send(command_to_execute + "\n")

        logging.info(
            f"Waiting for '{script_name}' to finish (up to 10 minutes) and printing output in real-time...")
        script_output, prompt_found = read_and_print_realtime(shell, timeout_sec=SCRIPT_EXECUTION_TIMEOUT_SECONDS)

        all_scripts_raw_output.append((script_name, script_output)) # Capture the output

        if not prompt_found:
            logging.warning(
                f"Warning: Prompt not detected within {SCRIPT_EXECUTION_TIMEOUT_SECONDS} seconds after running '{script_name}'.")
            logging.warning(
                f"The remote script might still be running, or the prompt format is unexpected.")
            logging.warning(
                f"Proceeding to next script, but this one might not have finished cleanly.")
        else:
            logging.info(f"Prompt detected, '{script_name}' execution assumed complete.")
        logging.info(f"{'=' * padding_len}--- Finished execution for: {script_name} ---{'=' * padding_len}\n")

        if pbar: # Update progress bar after each script
            pbar.update(1)

    return all_scripts_raw_output # Return the collected outputs


def extract_link_components(part_string):
    """Extracts LCx or FCx from a link component string."""
    lc_match = re.search(r'(\d+)/CPU(\d+)', part_string)
    if lc_match:
        # Assuming the first group is the slot number for LC, e.g., 0/9/CPU0 -> LC9
        return f"LC{lc_match.group(1)}"
    fc_match = re.search(r'FC(\d+)', part_string)
    if fc_match:
        # Assuming FC followed by number, e.g., 0/FC6 -> FC6
        return f"FC{fc_match.group(1)}"
    # If neither CPU nor FC pattern matches, return the original string (e.g., 0/4/2/150)
    return part_string.strip()


def parse_and_print_errors(script_name, script_output):
    """
    Parses the script output for error codewords, BER, FLR, and RX Link Down Count
    and prints them in a formatted table. Includes reference thresholds for BER and FLR.
    Prints a blank row if no errors are found.
    """
    errors_found = []
    lines = script_output.splitlines()

    group_number_match = re.search(r'group(\d+)\.py', script_name)
    group_number = group_number_match.group(1) if group_number_match else "N/A"

    # Define exact thresholds for reference from the dummy scripts
    BER_THRESHOLD_REFERENCE = "1e-08"
    FLR_THRESHOLD_REFERENCE = "1e-21"

    i = 0
    while i < len(lines):
        # Look for the line indicating a faulty link and extract BER, FLR, and RX Link Down Count values
        # Updated regex to capture BER and FLR values directly from the line
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

            # Apply extract_link_components to each part and combine in their original order
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

            # Look for the BAD/OK statuses in the next few lines
            j = i + 1
            # Check up to 5 lines after the faulty link line to find all statuses
            while j < len(lines) and j < i + 6:
                if "Codewords: BAD" in lines[j]:
                    current_error["Codewords_status"] = "Bad"
                if "BER: BAD" in lines[j]:
                    current_error["BER_status"] = "Bad"
                if "FLR: BAD" in lines[j]:
                    current_error["FLR_status"] = "Bad"
                j += 1

            # Only add to errors_found if any of the statuses indicate an issue
            if current_error["Codewords_status"] == "Bad" or \
            current_error["BER_status"] == "Bad" or \
            current_error["FLR_status"] == "Bad" or \
            current_error["Link_flap"] > 0:
                errors_found.append(current_error)

            i = j # Move index past the processed status lines
        else:
            i += 1 # Move to the next line if no faulty link found

    print(f"\n--- Error Report for {script_name} ---")

    # Print threshold values here, between the header and the table
    print(f"Reference Thresholds: BER < {BER_THRESHOLD_REFERENCE}, FLR < {FLR_THRESHOLD_REFERENCE}")

    # Define column widths and headers - REMOVED THRESHOLD COLUMNS FROM TABLE
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

    # Calculate separator line length based on the header string length
    separator_line_len = len(header)
    separator_line = f"{'+'}{'-' * (separator_line_len - 2)}{'+'}"

    print(f"{separator_line}")
    print(f"{header}")
    print(f"{separator_line}")

    if errors_found:
        for error in errors_found:
            # Determine display value for each column
            codewords_display = error["Codewords_status"]

            # FLR display logic: "Bad (value)" or "Good"
            if error["FLR_status"] == "Bad":
                flr_display = f"Bad ({error['FLR_value']})"
            else:
                flr_display = "Good"

            # BER display logic: "Bad (value)" or "Good"
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
            print(f"| {' | '.join(row_cols)} |")
    else:
        # Print a blank row if no errors were found
        blank_row_cols = [
            f"{'':<{col_widths['Link Connection']}}",
            f"{group_number:<{col_widths['Group_number']}}",
            f"{'':<{col_widths['Codewords']}}",
            f"{'':<{col_widths['FLR']}}",
            f"{'':<{col_widths['BER']}}",
            f"{'':<{col_widths['Link_flap']}}"
        ]
        print(f"| {' | '.join(blank_row_cols)} |")
        logging.info(f"No errors detected for this group.")

    print(f"{separator_line}")


def execute_script_phase(shell, scripts_to_run, script_arg_option, pbar=None): # Added pbar argument
    """
    Handles the SSH connection, initial commands, and execution of scripts for a single phase.
    Closes the connection after completion.
    Raises RouterCommandError, ScriptExecutionError.
    """
    try:
        logging.info(f"--- Initial Shell Output ---")
        # Read initial prompt silently, then print its content as a block
        initial_output, _ = read_and_print_realtime(shell, timeout_sec=2, print_realtime=False)
        print(f"{initial_output}", end='') # Explicitly print captured output
        print() # Ensure a newline after printing
        logging.info(f"--- End Initial Shell Output ---\n")

        # Set terminal length and width to prevent pagination
        if not execute_command_in_shell(shell, "terminal length 0", "set terminal length to 0", timeout=5,
                                        print_realtime_output=False):
            raise RouterCommandError("Failed to set terminal length 0.")
        if not execute_command_in_shell(shell, "terminal width 511", "set terminal width to 511", timeout=5,
                                        print_realtime_output=False):
            raise RouterCommandError("Failed to set terminal width 511.")

        # 1. Go to the RP bash prompt
        if not execute_command_in_shell(shell, "attach location 0/RP0/CPU0", "attach location 0/RP0/CPU0",
                                        timeout=COMMAND_TIMEOUT_SECONDS, print_realtime_output=False):
            raise RouterCommandError(f"Failed to establish bash prompt on router.")

        # 2. Change directory
        if not execute_command_in_shell(shell, "cd /misc/disk1/", "cd /misc/disk1/", timeout=COMMAND_TIMEOUT_SECONDS,
                                        print_realtime_output=False):
            raise RouterCommandError(f"Failed to change directory on router.")

        # Run the list of scripts for this phase and capture their outputs
        scripts_outputs = run_script_list_phase(shell, scripts_to_run, script_arg_option, pbar) # Pass pbar

        # Process outputs for errors if this is the 'dummy no' phase
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
    """
    Connects to the router, executes 'show running | i hostname', and extracts the hostname.
    Returns the hostname string.
    Raises HostnameRetrievalError on failure.
    """
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        logging.info(f"Attempting to connect to {router_ip} to retrieve hostname...")
        client.connect(router_ip, port=22, username=username, password=password, timeout=SSH_TIMEOUT_SECONDS,
                       look_for_keys=False)
        logging.info(f"Successfully connected to {router_ip} for hostname retrieval.")

        # Use exec_command for a single command execution
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

        # --- CHANGE 1: Sanitize the hostname for use as a directory name ---
        # First, replace dots with hyphens as requested.
        temp_hostname = hostname.replace('.', '-')
        # Then, remove any other characters that are not alphanumeric, hyphens, or underscores.
        # This ensures that characters invalid for filenames (like '/', '\', ':', etc.) are removed,
        # while preserving hyphens and underscores.
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


# --- Main execution block ---
if __name__ == "__main__":
    # Initialize variables for file handling outside the try block
    session_log_file_handler = None
    raw_output_file = None
    original_stdout = sys.stdout # Store original stdout

    # Ensure a clean slate for logging handlers before custom setup
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    # No initial basic console handler needed now, as it will be replaced by ProgressBarAwareHandler

    router_hostname = "unknown_host" # Default fallback hostname

    try:
        logging.info(f"--- IOS-XR Router Script Automation (Two-Phase Execution with Re-login) ---")
        ROUTER_IP = input(f"Enter Router IP_add / Host: ")
        SSH_USERNAME = input(f"Enter SSH Username: ")
        SSH_PASSWORD = getpass.getpass(
            f"Enter SSH Password: ") # Uses getpass for secure password input

        # --- CHANGE 2: Retrieve hostname before setting up specific logging ---
        try:
            # get_hostname_from_router now returns a sanitized hostname
            router_hostname = get_hostname_from_router(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD)
        except HostnameRetrievalError as e:
            logging.error(f"Could not retrieve hostname: {e}. Using IP address for log filename.")
            # Sanitize IP for filename by replacing dots with hyphens
            router_hostname = ROUTER_IP.replace('.', '-')

        # --- CHANGE 3: Set up specific logging paths and handlers ---
        # This will be the directory where all logs for this router will be stored.
        # It will be named after the sanitized router_hostname.
        hostname_dir = os.path.join(os.getcwd(), router_hostname)

        # --- CHANGE 4: Create the directory if it doesn't exist ---
        try:
            os.makedirs(hostname_dir, exist_ok=True)
            logging.info(f"Ensured router log directory exists: {os.path.abspath(hostname_dir)}")
        except OSError as e:
            logging.critical(
                f"Failed to create or access router log directory {hostname_dir}: {e}. Script cannot proceed without a log directory. Exiting.")
            sys.exit(1) # Exit if it cannot create/access directory

        # Generate unique filenames using a timestamp
        timestamp_for_logs = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        # Renamed session log file
        session_log_path = os.path.join(hostname_dir, f"{router_hostname}_pre_check_python_session_log_{timestamp_for_logs}.txt")
        # Renamed raw output log file
        raw_output_log_path = os.path.join(hostname_dir, f"{router_hostname}_pre_check_python_output_{timestamp_for_logs}.txt")

        # Reconfigure root logger:
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)

        # Add FileHandler for internal script messages (session log)
        try:
            session_log_file_handler = logging.FileHandler(session_log_path)
            session_log_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            logging.root.addHandler(session_log_file_handler)
            logging.info(f"Internal script logs will be saved to: {session_log_path}")
        except IOError as e:
            logging.error(f"Could not open internal session log file {session_log_path}: {e}. Internal logs will only go to console.")
            session_log_file_handler = None # Ensure it's None if opening failed

        # Open the raw output file and redirect sys.stdout using Tee
        try:
            raw_output_file = open(raw_output_log_path, 'w', encoding='utf-8')
            sys.stdout = Tee(original_stdout, raw_output_file) # Redirect sys.stdout here
            logging.info(f"All console output (including router raw output) will be logged to: {raw_output_log_path}")
        except IOError as e:
            logging.error(f"Could not open raw output log file {raw_output_log_path}: {e}. Raw output will only go to console.")
            raw_output_file = None
            sys.stdout = original_stdout # Restore if Tee fails

        # Add ProgressBarAwareHandler for console logging, coordinating with the progress bar
        pbar_console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        pbar_console_handler = ProgressBarAwareHandler(original_stdout)
        pbar_console_handler.setFormatter(pbar_console_formatter)
        logging.root.addHandler(pbar_console_handler)

        # Set overall logging level after all handlers are added
        logging.root.setLevel(logging.INFO)

        # List of your scripts to run sequentially within the same SSH session
        scripts_to_run = [
            "monitor_8800_system_v2_3_msft_bash_group0.py",
            "monitor_8800_system_v2_3_msft_bash_group1.py",
            "monitor_8800_system_v2_3_msft_bash_group2.py",
            "monitor_8800_system_v2_3_msft_bash_group3.py",
        ]

        script_aborted = False

        # --- Phase 1: Run scripts with '--dummy' yes ---
        client_phase1 = None
        shell_phase1 = None
        try:
            logging.info(f"\n{'#' * 70}\n### Starting Phase 1: Running scripts with '--dummy' yes ###\n{'#' * 70}\n")
            client_phase1 = paramiko.SSHClient()
            client_phase1.load_system_host_keys()
            client_phase1.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            logging.info(f"Attempting to connect to {ROUTER_IP} for Phase 1...")
            client_phase1.connect(ROUTER_IP, port=22, username=SSH_USERNAME, password=SSH_PASSWORD,
                                  timeout=SSH_TIMEOUT_SECONDS,
                                  look_for_keys=False)
            logging.info(f"Successfully connected to {ROUTER_IP} for Phase 1.")

            shell_phase1 = client_phase1.invoke_shell()
            time.sleep(1) # Give the shell a moment to initialize

            # Progress bar for Phase 1
            total_scripts_phase1 = len(scripts_to_run)
            with SimpleProgressBar(total=total_scripts_phase1, original_console_stream=original_stdout,
                                   description="Phase 1 (Dummy Yes) Progress", color_code='\033[94m') as pbar_phase1:
                execute_script_phase(shell_phase1, scripts_to_run, "'--dummy' yes", pbar_phase1) # Pass pbar
            logging.info(f"\n{'#' * 70}\n### Phase 1 Complete. Waiting 20 minutes before re-logging... ###\n{'#' * 70}\n")

        except paramiko.AuthenticationException as e:
            raise SSHConnectionError(
                f"Authentication failed during Phase 1. Please check your username and password. Error: {e}")
        except paramiko.SSHException as e:
            raise SSHConnectionError(f"SSH error during Phase 1: {e}")
        except Exception as e:
            raise ScriptExecutionError(f"An unexpected error occurred during Phase 1: {e}")
        finally:
            if shell_phase1:
                logging.info(f"Exiting bash prompt for Phase 1...")
                try:
                    shell_phase1.send("exit\n")
                    time.sleep(1)
                    shell_phase1.recv(65535).decode('utf-8', errors='ignore') # Clear buffer
                except Exception as e:
                    logging.warning(f"Error during shell exit for Phase 1: {e}")
            if client_phase1:
                client_phase1.close()
                logging.info(f"SSH connection for Phase 1 closed.")

        # --- Wait for 20 minutes ---
        countdown_timer(20 * 60) # This will print via Tee, which is fine since no pbar is active

        # --- Phase 2: Run scripts with '--dummy' no ---
        client_phase2 = None
        shell_phase2 = None
        try:
            logging.info(
                f"\n{'#' * 70}\n### Starting Phase 2: Running scripts with '--dummy' no ###\n{'#' * 70}\n")
            client_phase2 = paramiko.SSHClient()
            client_phase2.load_system_host_keys()
            client_phase2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            logging.info(f"Attempting to connect to {ROUTER_IP} for Phase 2...")
            client_phase2.connect(ROUTER_IP, port=22, username=SSH_USERNAME, password=SSH_PASSWORD,
                                  timeout=SSH_TIMEOUT_SECONDS,
                                  look_for_keys=False)
            logging.info(f"Successfully connected to {ROUTER_IP} for Phase 2.")

            shell_phase2 = client_phase2.invoke_shell()
            time.sleep(1) # Give the shell a moment to initialize

            # Progress bar for Phase 2
            total_scripts_phase2 = len(scripts_to_run)
            with SimpleProgressBar(total=total_scripts_phase2, original_console_stream=original_stdout,
                                   description="Phase 2 (Dummy No) Progress", color_code='\033[92m') as pbar_phase2:
                execute_script_phase(shell_phase2, scripts_to_run, "'--dummy' no", pbar_phase2) # Pass pbar
            logging.info(f"\n{'#' * 70}\n### Phase 2 Complete. ###\n{'#' * 70}\n")

        except paramiko.AuthenticationException as e:
            raise SSHConnectionError(
                f"Authentication failed during Phase 2. Please check your username and password. Error: {e}")
        except paramiko.SSHException as e:
            raise SSHConnectionError(f"SSH error during Phase 2: {e}")
        except Exception as e:
            raise ScriptExecutionError(f"An unexpected error occurred during Phase 2: {e}")
        finally:
            if shell_phase2:
                logging.info(f"Exiting bash prompt for Phase 2...")
                try:
                    shell_phase2.send("exit\n")
                    time.sleep(1)
                    shell_phase2.recv(65535).decode('utf-8', errors='ignore') # Clear buffer
                except Exception as e:
                    logging.warning(f"Error during shell exit for Phase 2: {e}")
            if client_phase2:
                client_phase2.close()
                logging.info(f"SSH connection for Phase 2 closed.")


    except (SSHConnectionError, RouterCommandError, ScriptExecutionError) as e:
        logging.critical(f"\nScript execution failed: {e}")
        script_aborted = True
    except Exception as e:
        logging.critical(f"\nAn unhandled critical error occurred: {e}", exc_info=True)
        script_aborted = True
    finally:
        if script_aborted:
            logging.info(f"\n--- Script Execution Aborted ---")
        else:
            logging.info(f"\n--- Script Execution Finished Successfully ---")

        # Restore original stdout and close the log files
        sys.stdout = original_stdout # Restore original stdout first

        if session_log_file_handler:
            logging.root.removeHandler(session_log_file_handler)
            session_log_file_handler.close()
            print(f"\nInternal session log closed: {session_log_path}")

        if raw_output_file:
            raw_output_file.close()
            print(f"Raw output log closed: {raw_output_log_path}")

        # Remove the ProgressBarAwareHandler
        for handler in logging.root.handlers[:]:
            if isinstance(handler, ProgressBarAwareHandler):
                logging.root.removeHandler(handler)
                break
        # Also remove any other StreamHandlers that might have used original_stdout
        for handler in logging.root.handlers[:]:
            if isinstance(handler, logging.StreamHandler) and handler.stream == original_stdout:
                logging.root.removeHandler(handler)
                break