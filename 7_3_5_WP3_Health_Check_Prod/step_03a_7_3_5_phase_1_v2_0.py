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

# This script connects to a Cisco IOS-XR device via SSH to execute Phase 1 of 7.3.5 post-check process.
# It performs the following actions:
# - Step a: Executes dummy scripts with '--dummy' yes
# - Step b: Runs first dataplane monitor
# - Step c: Waits for specified duration (20 minutes)
# - Step d: Executes dummy scripts with '--dummy' no
# - Step e: Provides manual intervention instructions for reloads

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
import utils_7_3_5_common as utils
from utils_7_3_5_common import (
    SSHConnectionError, RouterCommandError, ScriptExecutionError, DataplaneError,
    colorful_countdown_timer, execute_command_in_shell, connect_with_retry,
    get_hostname, get_hostname_from_router, run_dataplane_monitor_phase, execute_script_phase,
    print_final_summary, format_execution_time, CompactFormatter, Tee,
    SSH_TIMEOUT_SECONDS, DATAPLANE_MONITOR_TIMEOUT_SECONDS, WAIT_TIME_MINUTES,
    HostnameRetrievalError
)

# --- Main execution block for Part 3a (Phase 1 - Steps a-e) ---
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
        logging.info(f"--- IOS-XR Router Automation Script (Part 3a - Phase 1 - Steps a-e) ---")
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
                                        f"{router_hostname}_7_3_5_post-checks_session_log_phase_1_{timestamp_for_logs}.txt")
        raw_output_log_path = os.path.join(hostname_dir,
                                           f"{router_hostname}_7_3_5_post-checks_output_phase_1_{timestamp_for_logs}.txt")

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

        # Step a: Dummy yes
        logging.info(f"\n{'#' * 70}\n### Step a: Running scripts with '--dummy' yes ###\n{'#' * 70}\n")
        execute_script_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, scripts_to_run, "'--dummy' yes",
                             SSH_TIMEOUT_SECONDS, "Phase 1")
        results_summary["Step a"] = "Dummy Yes: Success"
        logging.info(f"\033[1;92m✓ Dummy yes phase completed successfully.\033[0m")

        # Step b: Monitor dataplane
        logging.info(f"\n{'#' * 70}\n### Step b: First Dataplane Monitor ###\n{'#' * 70}\n")
        run_dataplane_monitor_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, "FIRST", SSH_TIMEOUT_SECONDS,
                                    DATAPLANE_MONITOR_TIMEOUT_SECONDS)
        results_summary["Step b"] = "First Dataplane Monitor: Success"
        logging.info(f"\033[1;92m✓ First Dataplane Monitor completed successfully.\033[0m")

        # Step c: Wait time
        logging.info(f"\n{'#' * 70}\n### Step c: {WAIT_TIME_MINUTES}-minute Wait Time ###\n{'#' * 70}\n")
        colorful_countdown_timer(WAIT_TIME_MINUTES * 60)
        results_summary["Step c"] = f"{WAIT_TIME_MINUTES}-minute Wait: Success"
        logging.info(f"\033[1;92m✓ {WAIT_TIME_MINUTES}-minute wait completed.\033[0m")

        # Step d: Dummy no
        logging.info(f"\n{'#' * 70}\n### Step d: Running scripts with '--dummy' no ###\n{'#' * 70}\n")
        execute_script_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, scripts_to_run, "'--dummy' no",
                             SSH_TIMEOUT_SECONDS, "Phase 1")
        results_summary["Step d"] = "Dummy No: Success"
        logging.info(f"\033[1;92m✓ Dummy no phase completed successfully.\033[0m")

        # Step e: Manual intervention
        logging.info(f"\n{'#' * 70}\n### Step e: MANUAL INTERVENTION REQUIRED ###\n{'#' * 70}\n")
        logging.critical("Please perform the two reloads now.")
        results_summary["Step e"] = "Manual Reload Step: Instructed User"
        logging.info(f"\033[1;94m✓ Manual reload instructions provided to user.\033[0m")

    except (SSHConnectionError, RouterCommandError, ScriptExecutionError, DataplaneError) as e:
        logging.critical(f"\033[1;91m✗ Script execution failed and aborted: {e}\033[0m")
        script_aborted = True
        # Add appropriate failed status based on where it failed
        if "Step a" not in results_summary:
            results_summary["Step a"] = f"Dummy Yes: Failed - {e}"
        elif "Step b" not in results_summary:
            results_summary["Step b"] = f"First Dataplane Monitor: Failed - {e}"
        elif "Step c" not in results_summary:
            results_summary["Step c"] = f"{WAIT_TIME_MINUTES}-minute Wait: Failed - {e}"
        elif "Step d" not in results_summary:
            # Check for specific error types
            if "Degraded links found" in str(e):
                results_summary["Step d"] = f"Dummy No: Failed - Degraded links found"
            else:
                results_summary["Step d"] = f"Dummy No: Failed - {e}"
        else:
            results_summary["Step e"] = f"Manual Reload Step: Failed - {e}"
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

        # Print Final Summary
        logging.info(f"\n{'#' * 70}\n### Final Summary for Part 3a (Phase 1) ###\n{'#' * 70}\n")
        print_final_summary(results_summary, total_execution_time)
        logging.info(f"--- Script Part 3a Execution Finished ---")

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