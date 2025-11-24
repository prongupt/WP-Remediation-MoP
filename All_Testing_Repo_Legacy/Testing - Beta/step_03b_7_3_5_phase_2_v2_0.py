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

# This script connects to a Cisco IOS-XR device via SSH to execute Phase 2 of 7.3.5 post-check process.
# It performs the following actions:
# - Step f: Runs second dataplane monitor
# - Step g: Waits for specified duration (20 minutes)
# - Step h: Runs third dataplane monitor
# - Step i: Performs show tech collection
# - Step j: Clears ASIC counters

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
    SSHConnectionError, RouterCommandError, DataplaneError, ShowTechError, AsicErrorShowError,
    colorful_countdown_timer, execute_command_in_shell, connect_with_retry,
    get_hostname, get_hostname_from_router, run_dataplane_monitor_phase, run_show_tech_phase,
    run_clear_asic_counters, print_final_summary, format_execution_time, CompactFormatter, Tee,
    SSH_TIMEOUT_SECONDS, DATAPLANE_MONITOR_TIMEOUT_SECONDS, WAIT_TIME_MINUTES,
    HostnameRetrievalError, suggest_dataplane_recovery_actions
)

# ADD enhanced imports:
from utils_7_3_5_common import (
    WorkflowState, LiveWorkflowDashboard, pre_flight_check,
    suggest_recovery_actions, smart_retry_with_context,
    create_enhanced_workflow_manager, correlate_errors_across_phases
)

# --- Main execution block for Part 3b (Phase 2 - Steps f-j) ---
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
    workflow_manager = None

    # Initial console handler
    initial_console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s',
                                                  datefmt='%Y-%m-%d %H:%M:%S')
    initial_console_handler = logging.StreamHandler(true_original_stdout)
    initial_console_handler.setFormatter(initial_console_formatter)
    logging.root.addHandler(initial_console_handler)

    try:
        logging.info(f"--- IOS-XR Router Automation Script (Part 3b - Phase 2 - Steps f-j) ---")
        ROUTER_IP = input(f"Enter Router IP address or Hostname: ")
        SSH_USERNAME = input(f"Enter SSH Username: ")
        SSH_PASSWORD = getpass.getpass(f"Enter SSH Password for {SSH_USERNAME}@{ROUTER_IP}: ")

        try:
            router_hostname = get_hostname_from_router(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD)
        except HostnameRetrievalError as e:
            logging.error(f"Could not retrieve hostname: {e}. Using IP address for log filename.")
            router_hostname = ROUTER_IP.replace('.', '-')

        # ENHANCED: Create workflow manager
        workflow_manager = create_enhanced_workflow_manager(router_hostname)

        # ENHANCED: Pre-flight check
        if not pre_flight_check(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, "Part 3b - Phase 2"):
            logging.warning("⚠️ Pre-flight checks failed - proceeding with caution")
            user_choice = input("Continue despite pre-flight check failures? (y/N): ").lower()
            if user_choice not in ['y', 'yes']:
                logging.info("Script execution cancelled by user due to pre-flight check failures")
                sys.exit(1)

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
                                        f"{router_hostname}_7_3_5_post-checks_session_log_phase_2_{timestamp_for_logs}.txt")
        raw_output_log_path = os.path.join(hostname_dir,
                                           f"{router_hostname}_7_3_5_post-checks_output_phase_2_{timestamp_for_logs}.txt")

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

        results_summary: Dict[str, str] = {}
        script_aborted = False

        # ENHANCED: Start phase tracking
        workflow_manager.dashboard.start_phase("Phase 2 - Steps f-j")

        # ENHANCED Step f: Monitor dataplane (Second instance) with lambda wrapper
        logging.info(f"\n{'#' * 70}\n### Step f: Second Dataplane Monitor ###\n{'#' * 70}\n")
        try:
            smart_retry_with_context(
                lambda: run_dataplane_monitor_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, "SECOND",
                                                    SSH_TIMEOUT_SECONDS, DATAPLANE_MONITOR_TIMEOUT_SECONDS),
                max_retries=2,
                context="Step f - Second Dataplane Monitor"
            )
            results_summary["Step f"] = "Second Dataplane Monitor: Success"
            workflow_manager.dashboard.update_phase_progress("Phase 2", 1, 5, "Step f Complete")
            logging.info(f"\033[1;92m✓ Second Dataplane Monitor completed successfully.\033[0m")
        except DataplaneError as e:
            utils.suggest_dataplane_recovery_actions('3b', 'step_f', 'SECOND')
            results_summary["Step f"] = f"Second Dataplane Monitor: Failed - {e}"
            script_aborted = True
        except Exception as e:
            suggest_recovery_actions(type(e), "Step f", "Second dataplane monitoring")
            results_summary["Step f"] = f"Second Dataplane Monitor: Failed - {e}"
            script_aborted = True

        # ENHANCED Step g: Wait time with progress tracking
        logging.info(f"\n{'#' * 70}\n### Step g: Second {WAIT_TIME_MINUTES}-minute Wait Time ###\n{'#' * 70}\n")
        try:
            workflow_manager.dashboard.update_phase_progress("Phase 2", 2, 5, f"Step g - {WAIT_TIME_MINUTES}min Wait")
            colorful_countdown_timer(WAIT_TIME_MINUTES * 60)
            results_summary["Step g"] = f"Second {WAIT_TIME_MINUTES}-minute Wait: Success"
            workflow_manager.dashboard.update_phase_progress("Phase 2", 2, 5, "Step g Complete")
            logging.info(f"\033[1;92m✓ Second {WAIT_TIME_MINUTES}-minute wait completed.\033[0m")
        except Exception as e:
            suggest_recovery_actions(type(e), "Step g", "Wait time countdown")
            results_summary["Step g"] = f"Second {WAIT_TIME_MINUTES}-minute Wait: Failed - {e}"
            script_aborted = True
            raise

        # ENHANCED Step h: Monitor dataplane (Third instance) with lambda wrapper
        logging.info(f"\n{'#' * 70}\n### Step h: Third Dataplane Monitor ###\n{'#' * 70}\n")
        try:
            smart_retry_with_context(
                lambda: run_dataplane_monitor_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, "THIRD", SSH_TIMEOUT_SECONDS,
                                                    DATAPLANE_MONITOR_TIMEOUT_SECONDS),
                max_retries=2,
                context="Step h - Third Dataplane Monitor"
            )
            results_summary["Step h"] = "Third Dataplane Monitor: Success"
            workflow_manager.dashboard.update_phase_progress("Phase 2", 3, 5, "Step h Complete")
            logging.info(f"\033[1;92m✓ Third Dataplane Monitor completed successfully.\033[0m")
        except DataplaneError as e:
            utils.suggest_dataplane_recovery_actions('3b', 'step_h', 'THIRD')
            results_summary["Step h"] = f"Third Dataplane Monitor: Failed - {e}"
            script_aborted = True
        except Exception as e:
            suggest_recovery_actions(type(e), "Step h", "Third dataplane monitoring")
            results_summary["Step h"] = f"Third Dataplane Monitor: Failed - {e}"
            script_aborted = True


        # ENHANCED Step i: Show tech collection with enhanced error handling
        logging.info(f"\n{'#' * 70}\n### Step i: Show Tech Collection ###\n{'#' * 70}\n")
        try:
            smart_retry_with_context(
                lambda: run_show_tech_phase(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, SSH_TIMEOUT_SECONDS),
                max_retries=2,
                context="Step i - Show Tech Collection"
            )
            results_summary["Step i"] = "Show Tech Collection: Success"
            workflow_manager.dashboard.update_phase_progress("Phase 2", 4, 5, "Step i Complete")
            logging.info(f"\033[1;92m✓ Show tech collection completed successfully.\033[0m")
        except (SSHConnectionError, RouterCommandError, ShowTechError) as e:
            results_summary["Step i"] = f"Show Tech Collection: Failed - {e}"
            suggest_recovery_actions(type(e), "Step i", "Show tech collection")
            logging.critical(f"\033[1;91m✗ Show tech collection failed: {e}\033[0m")

            # ENHANCED: Show tech specific guidance
            print("💡 SHOW TECH FAILURE GUIDANCE:")
            print("   💾 Check available disk space: 'show filesystem harddisk:'")
            print("   🕒 Wait for any ongoing show tech to complete")
            print("   📁 Clean up old files: 'delete harddisk:/sh-tech-*'")
            print("   ✅ Phase 2 can continue - show tech is non-critical for Phase 3")

            # Don't abort on show tech failure, continue to clear counters

        # ENHANCED Step j: Clear ASIC counters with enhanced error handling
        logging.info(f"\n{'#' * 70}\n### Step j: Clear ASIC Counters ###\n{'#' * 70}\n")
        try:
            smart_retry_with_context(
                lambda: run_clear_asic_counters(ROUTER_IP, SSH_USERNAME, SSH_PASSWORD, SSH_TIMEOUT_SECONDS),
                max_retries=2,
                context="Step j - Clear ASIC Counters"
            )
            results_summary["Step j"] = "Clear ASIC Counters: Success"
            workflow_manager.dashboard.update_phase_progress("Phase 2", 5, 5, "Step j Complete")
            logging.info(f"\033[1;92m✓ Clear ASIC counters completed successfully.\033[0m")
        except (SSHConnectionError, RouterCommandError, AsicErrorShowError) as e:
            results_summary["Step j"] = f"Clear ASIC Counters: Failed - {e}"
            suggest_recovery_actions(type(e), "Step j", "ASIC counter clearing")
            logging.critical(f"\033[1;91m✗ Clear ASIC counters failed: {e}\033[0m")

            # ENHANCED: ASIC clearing specific guidance
            print("💡 ASIC COUNTER CLEARING GUIDANCE:")
            print("   ⏰ Wait for router to stabilize (5-10 minutes)")
            print("   🔧 Verify router is not in maintenance mode")
            print("   📋 ASIC clearing failure is non-critical for workflow")
            print("   ✅ Phase 3 can proceed normally")

            # Don't abort on final step failure

    except (SSHConnectionError, RouterCommandError, DataplaneError) as e:
        logging.critical(f"\033[1;91m✗ Script execution failed and aborted: {e}\033[0m")

        # ENHANCED: Automatic recovery suggestions based on error type
        suggest_recovery_actions(type(e), "Part 3b", str(e))

        script_aborted = True
        # Add appropriate failed status based on where it failed
        if "Step f" not in results_summary:
            results_summary["Step f"] = f"Second Dataplane Monitor: Failed - {e}"
        elif "Step g" not in results_summary:
            results_summary["Step g"] = f"Second {WAIT_TIME_MINUTES}-minute Wait: Failed - {e}"
        elif "Step h" not in results_summary:
            results_summary["Step h"] = f"Third Dataplane Monitor: Failed - {e}"
    except Exception as e:
        logging.critical(f"\033[1;91m✗ An unhandled critical error occurred: {e}\033[0m", exc_info=True)
        script_aborted = True
        results_summary["Critical Error"] = f"Unhandled Error: {e}"

        # ENHANCED: Generic recovery suggestions for unknown errors
        suggest_recovery_actions("UnknownError", "Part 3b", str(e))

    finally:
        # ENHANCED: Workflow state management and comprehensive reporting
        if workflow_manager:
            # Save phase completion to persistent state
            errors = [v for v in results_summary.values() if "Failed" in v]
            workflow_manager.state.save_phase_completion("step_03b", results_summary, errors)
            workflow_manager.dashboard.complete_phase("Phase 2", success=not script_aborted, errors=errors)

            # ENHANCED: Cross-phase error analysis
            if errors:
                logging.info("🔍 Analyzing errors in context of overall workflow...")
                recurring_issues = correlate_errors_across_phases(hostname_dir)
                if recurring_issues:
                    print("⚠️ These issues have appeared in previous phases:")
                    for issue in recurring_issues:
                        print(f"   • {issue}")

        if script_aborted:
            logging.info(f"\033[1;91m--- Script Execution Aborted ---\033[0m")

            # ENHANCED: Failure analysis and next steps
            if workflow_manager:
                print("🚨 FAILURE ANALYSIS:")
                print("   📊 Phase 2 did not complete successfully")
                print("   ⚠️ Phase 3 execution is at risk")
                print("   🔧 Resolve the issues identified above")
                print("   🔄 Consider re-running from Part 3a if critical dataplane errors occurred")
        else:
            logging.info(f"\033[1;92m--- Script Execution Finished Successfully ---\033[0m")

            # ENHANCED: Success guidance for next steps
            if workflow_manager:
                print("✅ SUCCESS GUIDANCE:")
                print("   🎯 Phase 2 completed successfully")
                print("   ➡️  Next step: Execute Part 3c (Phase 3)")
                print("   📋 Phase 3 contains dual dummy no validation")
                print("   ⚠️  Phase 3 is critical - ensure system is stable")

                # Check workflow state for recommendations --> Negated because there is no workflow management
                #next_phase = workflow_manager.state.get_next_recommended_phase()
                #if next_phase:
                #    print(f"   🚀 Next recommended script: {next_phase}")
                # FIXED (SIMPLE):
                print(f"   🚀 Next recommended script: step_03c_7_3_5_phase_3_v2_0.py")

        # Calculate total execution time
        total_execution_time = time.time() - script_start_time

        # ENHANCED: Performance analysis
        if workflow_manager and total_execution_time > 0:
            logging.info("📊 Analyzing Phase 2 performance...")
            if total_execution_time > 6000:  # > 100 minutes
                print("⚠️ PERFORMANCE ALERT:")
                print("   ⏱️ Phase 2 took longer than expected (>100 minutes)")
                print("   🔍 Show tech collection may have been slow")
                print("   💡 Check router disk space and performance")

        # Print Final Summary with enhanced context
        logging.info(f"\n{'#' * 70}\n### Final Summary for Part 3b (Phase 2) ###\n{'#' * 70}\n")

        # ENHANCED: Add workflow context to summary
        print("📊 PHASE 2 EXECUTION SUMMARY:")
        print_final_summary(results_summary, total_execution_time)

        # ENHANCED: Generate comprehensive workflow report
        if workflow_manager:
            workflow_summary = workflow_manager.state.get_workflow_summary()
            print(f"\n🎯 WORKFLOW CONTEXT:")
            print(f"   📈 Overall Progress: {workflow_summary['completion_rate']}")
            print(f"   ✅ Successful Phases: {workflow_summary['successful_phases']}")
            print(f"   🔢 Total Errors So Far: {workflow_summary['total_errors']}")

        logging.info(f"--- Script Part 3b Execution Finished ---")

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

        # ENHANCED: Final workflow guidance
        if workflow_manager and not script_aborted:
            print("\n🚀 NEXT STEPS:")
            print("   1. Verify system stability after Phase 2")
            print("   2. Check that show tech completed (if it was running)")
            print("   3. Execute Part 3c (Phase 3) for final validation")
            print(f"   💾 Workflow state saved to: {workflow_manager.state.state_file}")