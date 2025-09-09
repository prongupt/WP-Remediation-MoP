import paramiko
import time
import getpass
import datetime
import logging
import os
from typing import Dict

# Import all common functionalities from common_utils.py
from common_utils import (
    SSHConnectionError, RouterCommandError, ScriptExecutionError, DataplaneError, ShowTechError, AsicErrorShowError,
    colorful_countdown_timer, read_and_print_realtime, execute_command_in_shell,
    run_script_list_phase, get_hostname, parse_script_output_for_errors,
    format_and_print_error_report, run_dataplane_monitor_phase, run_show_tech_phase,  # <--- ADDED run_show_tech_phase
    run_clear_asic_counters, print_final_summary,  # <--- ADDED run_clear_asic_counters
    SSH_TIMEOUT_SECONDS, DATAPLANE_MONITOR_TIMEOUT_SECONDS, WAIT_TIME_MINUTES,
    COUNTDOWN_DURATION_MINUTES,
    session_log_file_console_mirror, session_log_file_raw_output  # Import global variables
)

# --- Initial Logging Configuration (temporary, will be reconfigured after hostname) ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

# --- Main execution block for Script 2 (Steps f-j) ---
if __name__ == "__main__":
    logging.info(f"--- IOS-XR Router Automation Script - Part 2 (Steps f-j) ---")

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
    app_log_filename = os.path.join(router_log_dir,
                                    f"{hostname_for_log}_automation_7_3_5_log_{timestamp_for_app_log}_part2.log")  # Added _part2

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
    console_mirror_filename = os.path.join(router_log_dir,
                                           f"{hostname_for_log}_post_check_7_3_5_session_log_{timestamp_for_session_logs}_part2.txt")  # Added _part2
    raw_output_filename = os.path.join(router_log_dir,
                                       f"{hostname_for_log}_post_check7_3_5_outputs_{timestamp_for_session_logs}_part2.txt")  # Added _part2

    try:
        # Assign to the global variable imported from common_utils
        import common_utils

        common_utils.session_log_file_console_mirror = open(console_mirror_filename, 'w', encoding='utf-8')
        logging.info(f"Console mirror session output will be logged to: {console_mirror_filename}")
    except IOError as e:
        logging.error(
            f"Could not open console mirror session log file {console_mirror_filename}: {e}. Console mirror output will not be logged to file.")
        common_utils.session_log_file_console_mirror = None

    try:
        # Assign to the global variable imported from common_utils
        common_utils.session_log_file_raw_output = open(raw_output_filename, 'w', encoding='utf-8')
        logging.info(f"Raw SSH output will be logged to: {raw_output_filename}")
    except IOError as e:
        logging.error(
            f"Could not open raw SSH output log file {raw_output_filename}: {e}. Raw SSH output will not be logged to file.")
        common_utils.session_log_file_raw_output = None

    # --- List of scripts to run (hardcoded) ---
    # This list is included for consistency but not directly used in steps f-j
    scripts_to_run = [
        "monitor_8800_system_v2_3_msft_bash_group0.py",
        "monitor_8800_system_v2_3_msft_bash_group1.py",
        "monitor_8800_system_v2_3_msft_bash_group2.py",
        "monitor_8800_system_v2_3_msft_bash_group3.py",
    ]

    results_summary: Dict[str, str] = {}
    script_aborted = False

    try:
        # f) Monitor dataplane
        logging.info(f"\n{'#' * 70}")
        logging.info("### Step f: Second Dataplane Monitor ###")
        try:
            run_dataplane_monitor_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, "SECOND", SSH_TIMEOUT_SECONDS,
                                        DATAPLANE_MONITOR_TIMEOUT_SECONDS)
            results_summary["Step f"] = "Second Dataplane Monitor: Success"
            logging.info("Second Dataplane Monitor completed successfully.")
        except (SSHConnectionError, RouterCommandError, DataplaneError) as e:
            results_summary["Step f"] = f"Second Dataplane Monitor: Failed - {e}"
            logging.critical(f"Second Dataplane Monitor failed: {e}")
            script_aborted = True
            raise

        # g) Wait time of 20 minutes
        logging.info(f"\n{'#' * 70}")
        logging.info(f"### Step g: Second {WAIT_TIME_MINUTES}-minute Wait Time ###")
        try:
            colorful_countdown_timer(WAIT_TIME_MINUTES * 60)
            results_summary["Step g"] = f"Second {WAIT_TIME_MINUTES}-minute Wait: Success"
            logging.info(f"Second {WAIT_TIME_MINUTES}-minute wait completed.")
        except Exception as e:
            results_summary["Step g"] = f"Second {WAIT_TIME_MINUTES}-minute Wait: Failed - {e}"
            logging.critical(f"Second {WAIT_TIME_MINUTES}-minute wait failed: {e}")
            script_aborted = True
            raise

        # h) Monitor dataplane
        logging.info(f"\n{'#' * 70}")
        logging.info("### Step h: Third Dataplane Monitor ###")
        try:
            run_dataplane_monitor_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, "THIRD", SSH_TIMEOUT_SECONDS,
                                        DATAPLANE_MONITOR_TIMEOUT_SECONDS)
            results_summary["Step h"] = "Third Dataplane Monitor: Success"
            logging.info("Third Dataplane Monitor completed successfully.")
        except (SSHConnectionError, RouterCommandError, DataplaneError) as e:
            results_summary["Step h"] = f"Third Dataplane Monitor: Failed - {e}"
            logging.critical(f"Third Dataplane Monitor failed: {e}")
            script_aborted = True
            raise

        # i) Show tech collection
        logging.info(f"\n{'#' * 70}")
        logging.info("### Step i: Show Tech Collection ###")
        try:
            run_show_tech_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, SSH_TIMEOUT_SECONDS)
            results_summary["Step i"] = "Show Tech Collection: Success"
            logging.info("Show tech collection completed successfully.")
        except (SSHConnectionError, RouterCommandError, ShowTechError) as e:
            results_summary["Step i"] = f"Show Tech Collection: Failed - {e}"
            logging.critical(f"Show tech collection failed: {e}")
            # Don't abort on show tech failure, continue to clear counters

        # j) Clear ASIC counters
        logging.info(f"\n{'#' * 70}")
        logging.info("### Step j: Clear ASIC Counters ###")
        try:
            run_clear_asic_counters(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, SSH_TIMEOUT_SECONDS)
            results_summary["Step j"] = "Clear ASIC Counters: Success"
            logging.info("Clear ASIC counters completed successfully.")
        except (SSHConnectionError, RouterCommandError, AsicErrorShowError) as e:
            results_summary["Step j"] = f"Clear ASIC Counters: Failed - {e}"
            logging.critical(f"Clear ASIC counters failed: {e}")
            # Don't abort on final step failure

    except Exception as e:
        logging.critical(f"An unhandled critical error occurred during script execution: {e}", exc_info=True)
        script_aborted = True
    finally:
        pass

    # Print Final Summary
    logging.info(f"\n{'#' * 70}")
    logging.info("### Final Summary for Part 2 ###")
    if script_aborted:
        logging.critical("Script Part 2 execution was aborted due to a critical error.")
    else:
        logging.info("All planned steps for Part 2 completed.")
    print_final_summary(results_summary)
    logging.info(f"--- Script Part 2 Execution Finished ---")

    # Close the session log files at the very end
    if common_utils.session_log_file_console_mirror:
        common_utils.session_log_file_console_mirror.close()
        logging.info(f"Console mirror session log file closed.")
    if common_utils.session_log_file_raw_output:
        common_utils.session_log_file_raw_output.close()
        logging.info(f"Raw SSH output log file closed.")