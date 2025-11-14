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

# This script connects to a Cisco IOS-XR device via SSH to execute Phase 3 of 7.3.5 post-check process.
# It performs the following actions:
# - Step k: Executes dummy scripts with '--dummy' yes (Part 3)
# - Step l: Runs fourth dataplane monitor
# - Step m: Waits for specified duration (20 minutes)
# - Step n: Executes dummy scripts with '--dummy' no (First time in Part 3)
# - Step o: Runs fifth dataplane monitor
# - Step p: Waits for specified duration (20 minutes)
# - Step q: Executes dummy scripts with '--dummy' no (Second time in Part 3)

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
import datetime
import logging
import os
import sys
from typing import Dict

# Import utilities with consistent alias
import testing_utils_7_3_5_common as utils
from testing_utils_7_3_5_common import (
    SSHConnectionError, RouterCommandError, ScriptExecutionError, DataplaneError,
    colorful_countdown_timer, execute_command_in_shell, connect_with_retry,
    get_hostname, get_hostname_from_router, run_dataplane_monitor_phase, execute_script_phase,
    print_final_summary, format_execution_time, CompactFormatter, Tee,
    SSH_TIMEOUT_SECONDS, DATAPLANE_MONITOR_TIMEOUT_SECONDS, WAIT_TIME_MINUTES,
    HostnameRetrievalError
)

# Global error tracking for two dummy no phases in Part 3c
PHASE3_DUMMY_NO_1_ERRORS_DETECTED = False  # Step n errors
PHASE3_DUMMY_NO_2_ERRORS_DETECTED = False  # Step q errors

# --- Main execution block for Part 3c (Phase 3 - Steps k-q) ---
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
    initial_console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s',
                                                  datefmt='%Y-%m-%d %H:%M:%S')
    initial_console_handler = logging.StreamHandler(true_original_stdout)
    initial_console_handler.setFormatter(initial_console_formatter)
    logging.root.addHandler(initial_console_handler)

    try:
        logging.info(f"--- IOS-XR Router Automation Script (Part 3c - Phase 3 - Steps k-q) ---")
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
                                        f"{router_hostname}_7_3_5_post-checks_session_log_phase_3_{timestamp_for_logs}.txt")
        raw_output_log_path = os.path.join(hostname_dir,
                                           f"{router_hostname}_7_3_5_post-checks_output_phase_3_{timestamp_for_logs}.txt")

        # Clear handlers and setup enhanced logging
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)

        try:
            session_log_file_handler = logging.FileHandler(session_log_path)
            session_log_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s',
                                                                    datefmt='%Y-%m-%d %H:%M:%S'))
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

        # Setup global file logging for utils functionality
        try:
            utils.session_log_file_console_mirror = open(session_log_path.replace('session_log', 'console_mirror'), 'w',
                                                         encoding='utf-8')
            utils.session_log_file_raw_output = open(raw_output_log_path.replace('output', 'raw_output'), 'w',
                                                     encoding='utf-8')
            logging.info(
                f"Console mirror session output will be logged to: {session_log_path.replace('session_log', 'console_mirror')}")
            logging.info(f"Raw SSH output will be logged to: {raw_output_log_path.replace('output', 'raw_output')}")
        except IOError as e:
            logging.error(f"Could not open global session log files: {e}.")
            utils.session_log_file_console_mirror = None
            utils.session_log_file_raw_output = None

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

        # Step k: Run dummy yes python scripts (Part 3)
        logging.info(f"\n{'#' * 70}\n### Step k: Running scripts with '--dummy' yes (Part 3) ###\n{'#' * 70}\n")
        execute_script_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, scripts_to_run, "'--dummy' yes",
                             SSH_TIMEOUT_SECONDS, "Phase 3")
        results_summary["Step k"] = "Dummy Yes (Part 3): Success"
        logging.info(f"\033[1;92m✓ Dummy yes phase (Part 3) completed successfully.\033[0m")

        # Step l: Run monitor dataplane (Fourth instance)
        logging.info(f"\n{'#' * 70}\n### Step l: Fourth Dataplane Monitor ###\n{'#' * 70}\n")
        run_dataplane_monitor_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, "FOURTH", SSH_TIMEOUT_SECONDS,
                                    DATAPLANE_MONITOR_TIMEOUT_SECONDS)
        results_summary["Step l"] = "Fourth Dataplane Monitor: Success"
        logging.info(f"\033[1;92m✓ Fourth Dataplane Monitor completed successfully.\033[0m")

        # Step m: Wait for 20 minutes
        logging.info(f"\n{'#' * 70}\n### Step m: Third {WAIT_TIME_MINUTES}-minute Wait Time ###\n{'#' * 70}\n")
        colorful_countdown_timer(WAIT_TIME_MINUTES * 60)
        results_summary["Step m"] = f"Third {WAIT_TIME_MINUTES}-minute Wait: Success"
        logging.info(f"\033[1;92m✓ Third {WAIT_TIME_MINUTES}-minute wait completed.\033[0m")

        # Step n: Run python dummy no scripts (First time in Part 3)
        logging.info(
            f"\n{'#' * 70}\n### Step n: Running scripts with '--dummy' no (First time in Part 3) ###\n{'#' * 70}\n")
        try:
            execute_script_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, scripts_to_run, "'--dummy' no",
                                 SSH_TIMEOUT_SECONDS, "Phase 3 - First Dummy No")
        except ScriptExecutionError as e:
            if "Degraded links found" in str(e):
                PHASE3_DUMMY_NO_1_ERRORS_DETECTED = True
                results_summary["Step n"] = "Dummy No (First in Part 3): Failed - Degraded links found"
                logging.critical(f"\033[1;91m✗ Dummy no phase (First in Part 3) failed: Degraded links found\033[0m")
                script_aborted = True
                raise
            else:
                results_summary["Step n"] = f"Dummy No (First in Part 3): Failed - {e}"
                logging.critical(f"\033[1;91m✗ Dummy no phase (First in Part 3) failed: {e}\033[0m")
                script_aborted = True
                raise

        if not PHASE3_DUMMY_NO_1_ERRORS_DETECTED:
            results_summary["Step n"] = "Dummy No (First in Part 3): Success"
            logging.info(f"\033[1;92m✓ Dummy no phase (First in Part 3) completed successfully.\033[0m")

        # Step o: Run monitor dataplane (Fifth instance)
        logging.info(f"\n{'#' * 70}\n### Step o: Fifth Dataplane Monitor ###\n{'#' * 70}\n")
        run_dataplane_monitor_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, "FIFTH", SSH_TIMEOUT_SECONDS,
                                    DATAPLANE_MONITOR_TIMEOUT_SECONDS)
        results_summary["Step o"] = "Fifth Dataplane Monitor: Success"
        logging.info(f"\033[1;92m✓ Fifth Dataplane Monitor completed successfully.\033[0m")

        # Step p: Wait for 20 minutes
        logging.info(f"\n{'#' * 70}\n### Step p: Fourth {WAIT_TIME_MINUTES}-minute Wait Time ###\n{'#' * 70}\n")
        colorful_countdown_timer(WAIT_TIME_MINUTES * 60)
        results_summary["Step p"] = f"Fourth {WAIT_TIME_MINUTES}-minute Wait: Success"
        logging.info(f"\033[1;92m✓ Fourth {WAIT_TIME_MINUTES}-minute wait completed.\033[0m")

        # Step q: Run python dummy no scripts (Second time in Part 3)
        logging.info(
            f"\n{'#' * 70}\n### Step q: Running scripts with '--dummy' no (Second time in Part 3) ###\n{'#' * 70}\n")
        try:
            execute_script_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, scripts_to_run, "'--dummy' no",
                                 SSH_TIMEOUT_SECONDS, "Phase 3 - Second Dummy No")
        except ScriptExecutionError as e:
            if "Degraded links found" in str(e):
                PHASE3_DUMMY_NO_2_ERRORS_DETECTED = True
                results_summary["Step q"] = "Dummy No (Second in Part 3): Failed - Degraded links found"
                logging.critical(f"\033[1;91m✗ Dummy no phase (Second in Part 3) failed: Degraded links found\033[0m")
                script_aborted = True
                raise
            else:
                results_summary["Step q"] = f"Dummy No (Second in Part 3): Failed - {e}"
                logging.critical(f"\033[1;91m✗ Dummy no phase (Second in Part 3) failed: {e}\033[0m")
                script_aborted = True
                raise

        if not PHASE3_DUMMY_NO_2_ERRORS_DETECTED:
            results_summary["Step q"] = "Dummy No (Second in Part 3): Success"
            logging.info(f"\033[1;92m✓ Dummy no phase (Second in Part 3) completed successfully.\033[0m")

    except (SSHConnectionError, RouterCommandError, DataplaneError) as e:
        logging.critical(f"\033[1;91m✗ Script execution failed and aborted: {e}\033[0m")
        script_aborted = True
        # Add appropriate failed status based on where it failed
        if "Step k" not in results_summary:
            results_summary["Step k"] = f"Dummy Yes (Part 3): Failed - {e}"
        elif "Step l" not in results_summary:
            results_summary["Step l"] = f"Fourth Dataplane Monitor: Failed - {e}"
        elif "Step m" not in results_summary:
            results_summary["Step m"] = f"Third {WAIT_TIME_MINUTES}-minute Wait: Failed - {e}"
        elif "Step n" not in results_summary:
            results_summary["Step n"] = f"Dummy No (First in Part 3): Failed - {e}"
        elif "Step o" not in results_summary:
            results_summary["Step o"] = f"Fifth Dataplane Monitor: Failed - {e}"
        elif "Step p" not in results_summary:
            results_summary["Step p"] = f"Fourth {WAIT_TIME_MINUTES}-minute Wait: Failed - {e}"
        else:
            results_summary["Step q"] = f"Dummy No (Second in Part 3): Failed - {e}"
    except Exception as e:
        logging.critical(f"\033[1;91m✗ An unhandled critical error occurred: {e}\033[0m", exc_info=True)
        script_aborted = True
        results_summary["Critical Error"] = f"Unhandled Error: {e}"
    finally:
        if script_aborted:
            logging.info(f"\033[1;91m--- Script Execution Aborted ---\033[0m")
        else:
            logging.info(f"\033[1;92m--- Script Execution Finished Successfully ---\033[0m")

        # Calculate total execution time
        total_execution_time = time.time() - script_start_time

        # Print Final Summary with enhanced status logic
        logging.info(f"\n{'#' * 70}\n### Final Summary for Part 3c (Phase 3) ###\n{'#' * 70}\n")

        # Update results summary with error detection status
        if "Step n" in results_summary and "Success" in results_summary["Step n"]:
            if PHASE3_DUMMY_NO_1_ERRORS_DETECTED:
                results_summary["Step n"] = "Dummy No (First in Part 3): Errors Found"
            else:
                results_summary["Step n"] = "Dummy No (First in Part 3): Successful"

        if "Step q" in results_summary and "Success" in results_summary["Step q"]:
            if PHASE3_DUMMY_NO_2_ERRORS_DETECTED:
                results_summary["Step q"] = "Dummy No (Second in Part 3): Errors Found"
            else:
                results_summary["Step q"] = "Dummy No (Second in Part 3): Successful"

        print_final_summary(results_summary, total_execution_time)
        logging.info(f"--- Script Part 3c Execution Finished ---")

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

        # Close global session files
        if utils.session_log_file_console_mirror:
            utils.session_log_file_console_mirror.close()
            logging.info(f"Console mirror session log file closed.")
        if utils.session_log_file_raw_output:
            utils.session_log_file_raw_output.close()
            logging.info(f"Raw SSH output log file closed.")

        # Clean up logging handlers
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)

        print(f"\nTotal script execution time: {format_execution_time(total_execution_time)}")