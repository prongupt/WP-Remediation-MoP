# 2-all_XR_pre_check_python.py This script run the dummy scripts on the router as part of the pre-checks.
# It runs dummy yes first, waits for 20 minutes and then runs dummy no
# Part 1 of 2

import paramiko
import time
import os
import getpass
import re
import logging
import sys
import datetime

# Import shared utilities
from xr_ssh_utils import (
    SSHConnectionError,
    RouterCommandError,
    HostnameRetrievalError,
    read_and_print_realtime,
    execute_command_in_shell,
    get_sanitized_hostname_from_router,
    setup_dynamic_logging,
    cleanup_logging,
    SSH_TIMEOUT_SECONDS, # Use constant from utility
    PROMPT_PATTERNS # Use constant from utility
)

# --- Constants and Configuration ---
# Default values for timeouts
# SSH_TIMEOUT_SECONDS is now imported from xr_ssh_utils
COMMAND_TIMEOUT_SECONDS = 30 # This is specific to this script's command execution
SCRIPT_EXECUTION_TIMEOUT_SECONDS = 600  # 10 minutes for scripts

# PROMPT_PATTERNS is now imported from xr_ssh_utils


# --- Custom Exceptions (specific to this script) ---
class ScriptExecutionError(Exception):
    """Custom exception for failures during script execution phases."""
    pass

# --- Initial Logging Configuration (minimal, to be reconfigured later) ---
# The initial logging setup is now handled by setup_dynamic_logging
# We just need to get the logger instance.
logger = logging.getLogger()
logger.setLevel(logging.INFO) # Set logger level back to INFO

# Clear existing handlers to prevent duplicate logging if script is run multiple times in same session
# This is still good practice before any specific logging setup.
if logger.handlers:
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()


def countdown_timer(seconds):
    initial_mins, initial_secs = divmod(seconds, 60)
    logger.info(f'Countdown Timer: Starting for {initial_mins:02d}:{initial_secs:02d}.')

    while seconds:
        mins, secs = divmod(seconds, 60)
        timer = f'{mins:02d}:{secs:02d}'
        print(f'\rCountdown Timer: {timer}', end='', flush=True)
        time.sleep(1)
        seconds -= 1
    logger.info('Countdown Timer: 00:00 - Time is up!')
    print(f'\rCountdown Timer: 00:00 - Time is up!   ')


def run_script_list_phase(shell, scripts_to_run, script_arg_option):
    """
    Executes a list of Python scripts sequentially within an already established shell session.
    Returns a list of tuples: (script_name, full_script_output_string).
    """
    all_scripts_raw_output = []  # To store (script_name, output_string) for later parsing

    for script_name in scripts_to_run:
        # Extract group number from script name
        group_match = re.search(r'group(\d+)\.py', script_name)
        group_number = group_match.group(1) if group_match else "Unknown"

        # Clean up script_arg_option for logging (remove surrounding quotes if present)
        script_arg_option_for_log = script_arg_option.strip("'")

        # Adjust padding to ensure it fits on one line
        padding_len = 15
        logger.info(
            f"{'=' * padding_len}--- Running Group {group_number} with option {script_arg_option_for_log} ---{'=' * padding_len}")

        command_to_execute = f"python3 {script_name} {script_arg_option}"
        logger.info(f"Sending '{command_to_execute}'...")
        shell.send(command_to_execute + "\n")

        logger.info(
            f"Waiting for '{script_name}' to finish (up to 10 minutes) and printing output in real-time...")
        # Use the imported read_and_print_realtime
        script_output, prompt_found = read_and_print_realtime(shell, timeout_sec=SCRIPT_EXECUTION_TIMEOUT_SECONDS)

        all_scripts_raw_output.append((script_name, script_output))  # Capture the output

        if not prompt_found:
            logger.warning(
                f"Warning: Prompt not detected within {SCRIPT_EXECUTION_TIMEOUT_SECONDS} seconds after running '{script_name}'.")
            logger.warning(
                f"The remote script might still be running, or the prompt format is unexpected.")
            logger.warning(
                f"Proceeding to next script, but this one might not have finished cleanly.")
        else:
            logger.info(f"Prompt detected, '{script_name}' execution assumed complete.")
        logger.info(f"{'=' * padding_len}--- Finished execution for: {script_name} ---{'=' * padding_len}\n")

    return all_scripts_raw_output


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

            i = j  # Move index past the processed status lines
        else:
            i += 1  # Move to the next line if no faulty link found

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
        logger.info(f"No errors detected for this group.")

    print(f"{separator_line}")


def execute_script_phase(shell, scripts_to_run, script_arg_option):
    """
    Handles the SSH connection, initial commands, and execution of scripts for a single phase.
    Closes the connection after completion.
    Raises RouterCommandError, ScriptExecutionError.
    """
    try:
        logger.info(f"--- Initial Shell Output ---")
        # read_and_print_realtime is now imported from xr_ssh_utils
        initial_output, _ = read_and_print_realtime(shell, timeout_sec=2, print_real_time=False)
        print(f"{initial_output}", end='')
        print()
        logger.info(f"--- End Initial Shell Output ---\n")

        # execute_command_in_shell is now imported from xr_ssh_utils
        # No cli_output_file argument needed, as Tee handles it.
        if not execute_command_in_shell(shell, "terminal length 0", "set terminal length to 0", timeout=5,
                                        print_real_time_output=False):
            raise RouterCommandError("Failed to set terminal length 0.")
        if not execute_command_in_shell(shell, "terminal width 511", "set terminal width to 511", timeout=5,
                                        print_real_time_output=False):
            raise RouterCommandError("Failed to set terminal width 511.")

        # 1. Go to the RP bash prompt
        if not execute_command_in_shell(shell, "attach location 0/RP0/CPU0", "attach location 0/RP0/CPU0",
                                        timeout=COMMAND_TIMEOUT_SECONDS, print_real_time_output=False):
            raise RouterCommandError(f"Failed to establish bash prompt on router.")

        # 2. Change directory
        if not execute_command_in_shell(shell, "cd /misc/disk1/", "cd /misc/disk1/", timeout=COMMAND_TIMEOUT_SECONDS,
                                        print_real_time_output=False):
            raise RouterCommandError(f"Failed to change directory on router.")

        # Run the list of scripts for this phase and capture their outputs
        scripts_outputs = run_script_list_phase(shell, scripts_to_run, script_arg_option)

        # Process outputs for errors if this is the 'dummy no' phase
        if script_arg_option == "'--dummy' no":
            logger.info(
                f"\n{'=' * 70}\n### Analyzing 'dummy no' script outputs for errors ###\n{'=' * 70}\n")
            for s_name, s_output in scripts_outputs:
                parse_and_print_errors(s_name, s_output)

        return True

    except RouterCommandError as e:
        raise RouterCommandError(f"Router command failed: {e}")
    except Exception as e:
        raise ScriptExecutionError(f"An unexpected error occurred: {e}")


# --- Main execution block ---
if __name__ == "__main__":
    original_stdout = sys.stdout

    # Initialize variables for file handling outside the try block
    router_hostname = "unknown_host"
    hostname_dir = None
    session_log_file_handle = None
    raw_output_file_handle = None
    timestamp = None

    try:
        logger.info(f"--- IOS-XR Router Script Automation (Two-Phase Execution with Re-login) ---")
        ROUTER_IP = input(f"Enter Router IP_add / Host: ")
        SSH_USERNAME = input(f"Enter SSH Username: ")
        SSH_PASSWORD = getpass.getpass(f"Enter SSH Password: ")

        # --- Retrieve hostname before setting up specific logging ---
        try:
            # get_sanitized_hostname_from_router is now imported from xr_ssh_utils
            router_hostname = get_sanitized_hostname_from_router(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, SSH_TIMEOUT_SECONDS)
        except HostnameRetrievalError as e:
            logger.error(f"Could not retrieve hostname: {e}. Using IP address for log filename.")
            router_hostname = ROUTER_IP.replace('.', '-')

        # --- Set up specific logging paths and handlers using the utility ---
        # The script name prefix is "pre_check_python" for this script
        hostname_dir, session_log_file_handle, raw_output_file_handle, timestamp = \
            setup_dynamic_logging(router_hostname, "pre_check_python", original_stdout)

        # Re-get logger after handlers are cleared and re-added by setup_dynamic_logging
        global logger
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)

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
            logger.info(f"\n{'#' * 70}\n### Starting Phase 1: Running scripts with '--dummy' yes ###\n{'#' * 70}\n")
            client_phase1 = paramiko.SSHClient()
            client_phase1.load_system_host_keys()
            client_phase1.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            logger.info(f"Attempting to connect to {ROUTER_IP} for Phase 1...")
            client_phase1.connect(ROUTER_IP, port=22, username=SSH_USERNAME, password=SSH_PASSWORD,
                                  timeout=SSH_TIMEOUT_SECONDS,
                                  look_for_keys=False)
            logger.info(f"Successfully connected to {ROUTER_IP} for Phase 1.")

            shell_phase1 = client_phase1.invoke_shell()
            time.sleep(1)

            execute_script_phase(shell_phase1, scripts_to_run, "'--dummy' yes")
            logger.info(
                f"\n{'#' * 70}\n### Phase 1 Complete. Waiting 20 minutes before re-logging... ###\n{'#' * 70}\n")

        except paramiko.AuthenticationException as e:
            raise SSHConnectionError(
                f"Authentication failed during Phase 1. Please check your username and password. Error: {e}")
        except paramiko.SSHException as e:
            raise SSHConnectionError(f"SSH error during Phase 1: {e}")
        except Exception as e:
            raise ScriptExecutionError(f"An unexpected error occurred during Phase 1: {e}")
        finally:
            if shell_phase1:
                logger.info(f"Exiting bash prompt for Phase 1...")
                try:
                    shell_phase1.send("exit\n")
                    time.sleep(1)
                    shell_phase1.recv(65535).decode('utf-8', errors='ignore')
                except Exception as e:
                    logger.warning(f"Error during shell exit for Phase 1: {e}")
            if client_phase1:
                client_phase1.close()
                logger.info(f"SSH connection for Phase 1 closed.")

        # --- Wait for 20 minutes ---
        countdown_timer(20 * 60)

        # --- Phase 2: Run scripts with '--dummy' no ---
        client_phase2 = None
        shell_phase2 = None
        try:
            logger.info(
                f"\n{'#' * 70}\n### Starting Phase 2: Running scripts with '--dummy' no ###\n{'#' * 70}\n")
            client_phase2 = paramiko.SSHClient()
            client_phase2.load_system_host_keys()
            client_phase2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            logger.info(f"Attempting to connect to {ROUTER_IP} for Phase 2...")
            client_phase2.connect(ROUTER_IP, port=22, username=SSH_USERNAME, password=SSH_PASSWORD,
                                  timeout=SSH_TIMEOUT_SECONDS,
                                  look_for_keys=False)
            logger.info(f"Successfully connected to {ROUTER_IP} for Phase 2.")

            shell_phase2 = client_phase2.invoke_shell()
            time.sleep(1)

            execute_script_phase(shell_phase2, scripts_to_run, "'--dummy' no")
            logger.info(f"\n{'#' * 70}\n### Phase 2 Complete. ###\n{'#' * 70}\n")

        except paramiko.AuthenticationException as e:
            raise SSHConnectionError(
                f"Authentication failed during Phase 2. Please check your username and password. Error: {e}")
        except paramiko.SSHException as e:
            raise SSHConnectionError(f"SSH error during Phase 2: {e}")
        except Exception as e:
            raise ScriptExecutionError(f"An unexpected error occurred during Phase 2: {e}")
        finally:
            if shell_phase2:
                logger.info(f"Exiting bash prompt for Phase 2...")
                try:
                    shell_phase2.send("exit\n")
                    time.sleep(1)
                    shell_phase2.recv(65535).decode('utf-8', errors='ignore')
                except Exception as e:
                    logger.warning(f"Error during shell exit for Phase 2: {e}")
            if client_phase2:
                client_phase2.close()
                logger.info(f"SSH connection for Phase 2 closed.")


    except (SSHConnectionError, RouterCommandError, ScriptExecutionError, HostnameRetrievalError) as e:
        logger.critical(f"\nScript execution failed: {e}")
        script_aborted = True
    except Exception as e:
        logger.critical(f"\nAn unhandled critical error occurred: {e}", exc_info=True)
        script_aborted = True
    finally:
        if script_aborted:
            logger.info(f"\n--- Script Execution Aborted ---")
        else:
            logger.info(f"\n--- Script Execution Finished Successfully ---")

        # Call the utility cleanup function
        cleanup_logging(original_stdout, session_log_file_handle, raw_output_file_handle)