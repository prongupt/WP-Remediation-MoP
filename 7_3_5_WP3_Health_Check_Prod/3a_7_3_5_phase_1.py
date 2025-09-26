import paramiko
import time
import getpass
import datetime
import logging
import os
from typing import Dict

# Import the entire module to access its global variables
import utils_7_3_5_common

# Import specific functionalities from utils_7_3_5_common.py
from utils_7_3_5_common import (
    SSHConnectionError, RouterCommandError, ScriptExecutionError, DataplaneError,
    colorful_countdown_timer, execute_command_in_shell,
    get_hostname, run_dataplane_monitor_phase, execute_script_phase,
    print_final_summary,
    SSH_TIMEOUT_SECONDS, DATAPLANE_MONITOR_TIMEOUT_SECONDS, WAIT_TIME_MINUTES,
    # This might become unused if the countdown is removed entirely
    # Import global variables
)

# --- Initial Logging Configuration (temporary, will be reconfigured after hostname) ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

# --- Main execution block for Script 1 (Steps a-e) ---
if __name__ == "__main__":
    logging.info(f"--- IOS-XR Router Automation Script - Part 1 (Steps a-e) ---")

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
        initial_client.connect(ROUTER_IP, port=22, username=SSH_USERNAME, password=SSH_PASSWORD,
                               timeout=SSH_TIMEOUT_SECONDS, look_for_keys=False)
        initial_shell = initial_client.invoke_shell()
        time.sleep(1)
        execute_command_in_shell(initial_shell, "terminal length 0", "set terminal length to 0", timeout=5,
                                 print_realtime_output=False)
        execute_command_in_shell(initial_shell, "terminal width 511", "set terminal width to 511", timeout=5,
                                 print_realtime_output=False)
        hostname_for_log = get_hostname(initial_shell)
        logging.info(f"Retrieved hostname: {hostname_for_log}")
    except Exception as e:
        logging.error(
            f"Failed to retrieve hostname during initial connection: {e}. Using 'unknown_host' for log directory and filenames.")
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
    router_log_dir = hostname_for_log  # This is a local variable, not the common_utils global
    try:
        os.makedirs(router_log_dir, exist_ok=True)
        logging.info(f"Ensured router log directory exists: {os.path.abspath(router_log_dir)}")
    except OSError as e:
        logging.critical(
            f"Failed to create or access router log directory {router_log_dir}: {e}. Script cannot proceed without a log directory. Exiting.")
        exit(1)

    # --- Reconfigure Application Logging to the new directory ---
    timestamp_for_app_log = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    app_log_filename = os.path.join(router_log_dir, f"{hostname_for_log}_automation_7_3_5_log_{timestamp_for_app_log}.log")

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
    console_mirror_filename = os.path.join(router_log_dir, f"{hostname_for_log}_post_check_7_3_5_session_log_{timestamp_for_session_logs}.txt")
    raw_output_filename = os.path.join(router_log_dir, f"{hostname_for_log}_post_check7_3_5_outputs_{timestamp_for_session_logs}.txt")

    try:
        # Assign to the global variable imported from utils_7_3_5_common
        utils_7_3_5_common.session_log_file_console_mirror = open(console_mirror_filename, 'w', encoding='utf-8')
        logging.info(f"Console mirror session output will be logged to: {console_mirror_filename}")
    except IOError as e:
        logging.error(
            f"Could not open console mirror session log file {console_mirror_filename}: {e}. Console mirror output will not be logged to file.")
        utils_7_3_5_common.session_log_file_console_mirror = None

    try:
        # Assign to the global variable imported from utils_7_3_5_common
        utils_7_3_5_common.session_log_file_raw_output = open(raw_output_filename, 'w', encoding='utf-8')
        logging.info(f"Raw SSH output will be logged to: {raw_output_filename}")
    except IOError as e:
        logging.error(
            f"Could not open raw SSH output log file {raw_output_filename}: {e}. Raw SSH output will not be logged to file.")
        utils_7_3_5_common.session_log_file_raw_output = None

    # --- List of scripts to run (hardcoded) ---
    scripts_to_run = [
        "monitor_8800_system_v2_3_msft_bash_group0.py",
        "monitor_8800_system_v2_3_msft_bash_group1.py",
        "monitor_8800_system_v2_3_msft_bash_group2.py",
        "monitor_8800_system_v2_3_msft_bash_group3.py",
    ]

    results_summary: Dict[str, str] = {}
    script_aborted = False

    try:
        # a) Dummy yes
        logging.info(f"\n{'#' * 70}")
        logging.info("### Step a: Running scripts with '--dummy' yes ###")
        try:
            execute_script_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, scripts_to_run, "'--dummy' yes",
                                 SSH_TIMEOUT_SECONDS)
            results_summary["Step a"] = "Dummy Yes: Success"
            logging.info("Dummy yes phase completed successfully.")
        except (SSHConnectionError, RouterCommandError, ScriptExecutionError) as e:
            results_summary["Step a"] = f"Dummy Yes: Failed - {e}"
            logging.critical(f"Dummy yes phase failed: {e}")
            script_aborted = True
            raise

        # b) Monitor dataplane
        logging.info(f"\n{'#' * 70}")
        logging.info("### Step b: First Dataplane Monitor ###")
        try:
            run_dataplane_monitor_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, "FIRST", SSH_TIMEOUT_SECONDS,
                                        DATAPLANE_MONITOR_TIMEOUT_SECONDS)
            results_summary["Step b"] = "First Dataplane Monitor: Success"
            logging.info("First Dataplane Monitor completed successfully.")
        except (SSHConnectionError, RouterCommandError, DataplaneError) as e:
            results_summary["Step b"] = f"First Dataplane Monitor: Failed - {e}"
            logging.critical(f"First Dataplane Monitor failed: {e}")
            script_aborted = True
            raise

        # c) Wait time of 20 minutes
        logging.info(f"\n{'#' * 70}")
        logging.info(f"### Step c: {WAIT_TIME_MINUTES}-minute Wait Time ###")
        try:
            colorful_countdown_timer(WAIT_TIME_MINUTES * 60)
            results_summary["Step c"] = f"{WAIT_TIME_MINUTES}-minute Wait: Success"
            logging.info(f"{WAIT_TIME_MINUTES}-minute wait completed.")
        except Exception as e:
            results_summary["Step c"] = f"{WAIT_TIME_MINUTES}-minute Wait: Failed - {e}"
            logging.critical(f"{WAIT_TIME_MINUTES}-minute wait failed: {e}")
            script_aborted = True
            raise

        # d) Dummy no
        logging.info(f"\n{'#' * 70}")
        logging.info("### Step d: Running scripts with '--dummy' no ###")
        try:
            execute_script_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, scripts_to_run, "'--dummy' no",
                                 SSH_TIMEOUT_SECONDS)
            results_summary["Step d"] = "Dummy No: Success"
            logging.info("Dummy no phase completed successfully.")
        except (SSHConnectionError, RouterCommandError, ScriptExecutionError) as e:
            results_summary["Step d"] = f"Dummy No: Failed - {e}"
            logging.critical(f"Dummy no phase failed: {e}")
            script_aborted = True
            raise

        # e) Placeholder for reloads
        logging.info(f"\n{'#' * 70}")
        logging.critical("### Step e: MANUAL INTERVENTION REQUIRED ###")
        logging.critical("Please perform the two reloads now.")
        results_summary["Step e"] = "Manual Reload Step: Instructed User"
        # No exception handling here as it's a manual step, and we want the message to always appear.
        # If the script were to wait for confirmation, that logic would go here.
        # For now, it just prints the message and continues.

    except Exception as e:
        logging.critical(f"An unhandled critical error occurred during script execution: {e}", exc_info=True)
        script_aborted = True
    finally:
        pass

    # Print Final Summary
    logging.info(f"\n{'#' * 70}")
    logging.info("### Final Summary for Part 1 ###")
    if script_aborted:
        logging.critical("Script Part 1 execution was aborted due to a critical error.")
    else:
        logging.info("All planned steps for Part 1 completed.")
    print_final_summary(results_summary)
    logging.info(f"--- Script Part 1 Execution Finished ---")

    # Close the session log files at the very end
    if utils_7_3_5_common.session_log_file_console_mirror:
        utils_7_3_5_common.session_log_file_console_mirror.close()
        logging.info(f"Console mirror session log file closed.")
    if utils_7_3_5_common.session_log_file_raw_output:
        utils_7_3_5_common.session_log_file_raw_output.close()
        logging.info(f"Raw SSH output log file closed.")