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

# Combined IOS-XR 7.3.5 Post-Check Framework (Parts 3a, 3b, 3c)
# This script provides an interactive menu system for executing all phases of the 7.3.5 post-check process:
# - Phase 1 (Steps a-e): Initial validation and manual reload preparation
# - Phase 2 (Steps f-j): Post-reload validation and diagnostics collection
# - Phase 3 (Steps k-q): Final dual validation for production readiness

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
import json
from typing import Dict, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass

# Import utilities with consistent alias
import utils_7_3_5_common as utils
from utils_7_3_5_common import (
    SSHConnectionError, RouterCommandError, ScriptExecutionError, DataplaneError,
    ShowTechError, AsicErrorShowError, colorful_countdown_timer,
    connect_with_retry, get_hostname_from_router, run_dataplane_monitor_phase,
    execute_script_phase, run_show_tech_phase, run_clear_asic_counters,
    print_final_summary, format_execution_time, CompactFormatter, Tee,
    SSH_TIMEOUT_SECONDS, DATAPLANE_MONITOR_TIMEOUT_SECONDS, WAIT_TIME_MINUTES,
    HostnameRetrievalError, suggest_dataplane_recovery_actions,
    WorkflowState, LiveWorkflowDashboard, pre_flight_check,
    suggest_recovery_actions, smart_retry_with_context,
    create_enhanced_workflow_manager
)

# Global error tracking for Phase 3 dual validation
PHASE3_DUMMY_NO_1_ERRORS_DETECTED = False  # Step n errors
PHASE3_DUMMY_NO_2_ERRORS_DETECTED = False  # Step q errors


class ExecutionMode(Enum):
    """Execution mode enumeration"""
    PHASE_1_ONLY = "phase_1"
    PHASE_2_ONLY = "phase_2"
    PHASE_3_ONLY = "phase_3"
    ALL_PHASES = "all_phases"
    RESUME_FROM = "resume_from"
    CUSTOM_STEPS = "custom_steps"


@dataclass
class PhaseConfig:
    """Configuration for each phase execution"""
    phase_name: str
    steps: List[str]
    estimated_duration_minutes: int
    critical_steps: List[str]
    description: str
    can_resume: bool = True


class InteractiveFrameworkManager:
    """Combined interactive framework manager for 7.3.5 post-checks"""

    def __init__(self):
        self.router_ip = None
        self.username = None
        self.password = None
        self.hostname = "unknown_host"
        self.workflow_manager = None
        self.session_start_time = time.time()
        self.true_original_stdout = sys.stdout
        self.session_log_file_handler = None
        self.raw_output_file = None

        # Phase configurations
        self.phases = {
            "phase_1": PhaseConfig(
                phase_name="Phase 1 (Steps a-e)",
                steps=["a", "b", "c", "d", "e"],
                estimated_duration_minutes=60,
                critical_steps=["b", "d"],
                description="Initial validation with manual reload preparation"
            ),
            "phase_2": PhaseConfig(
                phase_name="Phase 2 (Steps f-j)",
                steps=["f", "g", "h", "i", "j"],
                estimated_duration_minutes=90,
                critical_steps=["f", "h"],
                description="Post-reload validation and diagnostics collection"
            ),
            "phase_3": PhaseConfig(
                phase_name="Phase 3 (Steps k-q)",
                steps=["k", "l", "m", "n", "o", "p", "q"],
                estimated_duration_minutes=120,
                critical_steps=["n", "q"],
                description="Final dual validation for production readiness"
            )
        }

        self.scripts_to_run = [
            "monitor_8800_system_v2_3_msft_bash_group0.py",
            "monitor_8800_system_v2_3_msft_bash_group1.py",
            "monitor_8800_system_v2_3_msft_bash_group2.py",
            "monitor_8800_system_v2_3_msft_bash_group3.py"
        ]

    def initialize(self):
        """Initialize framework with banner, credentials, and logging, matching the 7.3.5 UI."""
        # --- FIX: Standardized banner from 7.3.5 script ---
        print(f"\n{'=' * 80}")
        print(f"{'IOS-XR 7.3.6+ Post-Check Interactive Framework v3.0':^80}")
        print(f"{'=' * 80}")

        # --- FIX: Standardized initialization header from 7.3.5 script ---
        print(f"\n🔧 FRAMEWORK INITIALIZATION")
        print(f"{'─' * 50}")

        self.router_ip = input("Enter Router IP address or Hostname: ")
        self.username = input("Enter SSH Username: ")
        self.password = getpass.getpass(f"Enter SSH Password for {self.username}@{self.router_ip}: ")

        try:
            self.hostname = get_hostname_from_router(self.router_ip, self.username, self.password)
            # --- FIX: Changed from logging.info() to print() to match 7.3.5 ---
            print(f"✅ Connected to router: {self.hostname}")
        except HostnameRetrievalError as e:
            logging.error(f"Could not retrieve hostname: {e}. Using IP for logs.")
            self.hostname = self.router_ip.replace('.', '-')

        self.workflow_manager = create_enhanced_workflow_manager(self.hostname)
        self._setup_logging()

        # --- FIX: Changed from logging.info() to print() to match 7.3.5 ---
        print(f"✅ Framework initialization completed")


    def _setup_logging(self):
        """Setup comprehensive logging system"""
        hostname_dir = os.path.join(os.getcwd(), self.hostname)
        os.makedirs(hostname_dir, exist_ok=True)

        timestamp_for_logs = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        session_log_path = os.path.join(hostname_dir,
                                        f"{self.hostname}_7_3_5_combined_post_checks_session_{timestamp_for_logs}.txt")
        raw_output_log_path = os.path.join(hostname_dir,
                                           f"{self.hostname}_7_3_5_combined_post_checks_output_{timestamp_for_logs}.txt")

        # Clear existing handlers
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)

        # Setup file logging
        try:
            self.session_log_file_handler = logging.FileHandler(session_log_path)
            self.session_log_file_handler.setFormatter(
                logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
            logging.root.addHandler(self.session_log_file_handler)
        except IOError as e:
            logging.error(f"Could not open session log file: {e}")

        # Setup raw output logging
        try:
            self.raw_output_file = open(raw_output_log_path, 'w', encoding='utf-8')
            sys.stdout = Tee(self.true_original_stdout, self.raw_output_file)
        except IOError as e:
            logging.error(f"Could not open raw output log file: {e}")
            sys.stdout = self.true_original_stdout

        # Setup console handler
        console_formatter = CompactFormatter()
        console_handler = logging.StreamHandler(self.true_original_stdout)
        console_handler.setFormatter(console_formatter)
        logging.root.addHandler(console_handler)
        logging.root.setLevel(logging.INFO)

        # Setup global file logging for utils
        try:
            utils.session_log_file_console_mirror = open(
                session_log_path.replace('session', 'console_mirror'), 'w', encoding='utf-8')
            utils.session_log_file_raw_output = open(
                raw_output_log_path.replace('output', 'raw_output'), 'w', encoding='utf-8')
        except IOError as e:
            logging.error(f"Could not open global session log files: {e}")

    def display_main_menu(self):
        """Display main menu with SecureCRT compatible formatting"""
        print(f"\n{'=' * 80}")
        print(f"{'IOS-XR 7.3.5 Post-Check Interactive Framework v2.0':^80}")
        print(f"{'=' * 80}")

        print(f"\nRouter: {self.hostname} ({self.router_ip})")
        print(f"Session Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        print(f"\nPHASE EXECUTION OPTIONS:")
        print(f"   [1] Execute Phase 1 Only (Steps a-e) - ~60 min")
        print(f"   [2] Execute Phase 2 Only (Steps f-j) - ~90 min")
        print(f"   [3] Execute Phase 3 Only (Steps k-q) - ~120 min")
        print(f"   [4] Execute All Phases Sequentially - ~270 min")

        print(f"\nINDIVIDUAL OPERATIONS:")
        print(f"   [5] Run Dataplane Monitor Only")
        print(f"   [6] Run Dummy Scripts Only")
        print(f"   [7] Show Tech Collection Only")
        print(f"   [8] Clear ASIC Counters Only")

        print(f"\nUTILITIES:")
        print(f"   [status] View Previous Results")
        print(f"   [help]   Help & Documentation")
        print(f"   [exit]   Exit")

        print(f"\n{'=' * 80}")


    def get_user_choice(self):
        """Get and validate user menu choice"""
        while True:
            choice = input(f"Select option: ").strip().lower()

            valid_choices = ["1", "2", "3", "4", "5", "6", "7", "8", "status", "help", "exit", "quit", "q"]

            if choice in valid_choices:
                return choice
            else:
                print(f"Invalid choice '{choice}'. Please try again.")


    def confirm_action(self, message: str, default_yes: bool = False) -> bool:
        """Interactive confirmation with clear defaults"""
        default_choice = "Y/n" if default_yes else "y/N"
        response = input(f"{message} ({default_choice}): ").lower().strip()

        if not response:
            return default_yes

        return response.startswith('y')

    def run_interactive_framework(self):
        """Main interactive framework execution loop"""

        while True:
            try:
                self.display_main_menu()
                choice = self.get_user_choice()

                if choice == "1":
                    self.execute_phase_1()
                elif choice == "2":
                    self.execute_phase_2()
                elif choice == "3":
                    self.execute_phase_3()
                elif choice == "4":
                    self.execute_all_phases_sequential()
                elif choice == "5":
                    self.run_dataplane_monitor_interactive()
                elif choice == "6":
                    self.run_dummy_scripts_interactive()
                elif choice == "7":
                    self.run_show_tech_interactive()
                elif choice == "8":
                    self.clear_asic_counters_interactive()
                elif choice in ["status"]:
                    self.show_execution_status()
                elif choice in ["help"]:
                    self.show_help()
                elif choice in ["exit", "quit", "q"]:
                    if self.confirm_action("Are you sure you want to exit?"):
                        break
                else:
                    print(f"❌ Invalid choice: {choice}")

            except KeyboardInterrupt:
                print(f"\n\n⚠️ Operation interrupted by user")
                if self.confirm_action("Do you want to exit the framework?"):
                    break
                else:
                    continue
            except Exception as e:
                logging.error(f"Unexpected error in interactive menu: {e}", exc_info=True)
                print(f"❌ An error occurred: {e}")
                if not self.confirm_action("Continue with framework?"):
                    break

        self.cleanup()

    # === PHASE EXECUTION METHODS ===

    def execute_phase_1(self):
        """Execute Phase 1 (Steps a-e) - Interactive version"""
        global PHASE3_DUMMY_NO_1_ERRORS_DETECTED, PHASE3_DUMMY_NO_2_ERRORS_DETECTED

        print(f"\n{'#' * 70}")
        print(f"### 🚀 PHASE 1 EXECUTION (Steps a-e) ###")
        print(f"{'#' * 70}")

        phase_config = self.phases["phase_1"]
        print(f"📋 Description: {phase_config.description}")
        print(f"⏱️  Estimated Duration: {phase_config.estimated_duration_minutes} minutes")
        print(f"🚨 Critical Steps: {', '.join(phase_config.critical_steps)}")

        if not self.confirm_action("Proceed with Phase 1 execution?"):
            return

        results_summary = {}
        script_aborted = False
        phase_start_time = time.time()

        # Start phase tracking
        self.workflow_manager.dashboard.start_phase("Phase 1 - Steps a-e")

        try:
            # Step a: Dummy scripts (--dummy yes)
            print(f"\n{'#' * 70}")
            print(f"### Step a: Running scripts with '--dummy' yes ###")
            print(f"{'#' * 70}")

            try:
                smart_retry_with_context(
                    lambda: execute_script_phase(self.router_ip, self.username, self.password,
                                                 self.scripts_to_run, "'--dummy' yes",
                                                 SSH_TIMEOUT_SECONDS, "Phase 1"),
                    max_retries=2,
                    context="Step a - Dummy Yes"
                )
                results_summary["Step a"] = "Dummy Yes: Success"
                self.workflow_manager.dashboard.update_phase_progress("Phase 1", 1, 5, "Step a Complete")
                logging.info(f"✓ Dummy yes phase completed successfully.")
            except Exception as e:
                suggest_recovery_actions(type(e), "Step a", "Dummy yes execution")
                results_summary["Step a"] = f"Dummy Yes: Failed - {e}"
                script_aborted = True

            if not script_aborted:
                # Step b: First dataplane monitor
                print(f"\n{'#' * 70}")
                print(f"### Step b: First Dataplane Monitor ###")
                print(f"{'#' * 70}")

                try:
                    smart_retry_with_context(
                        lambda: run_dataplane_monitor_phase(self.router_ip, self.username, self.password,
                                                            "FIRST", SSH_TIMEOUT_SECONDS,
                                                            DATAPLANE_MONITOR_TIMEOUT_SECONDS),
                        max_retries=2,
                        context="Step b - Dataplane Monitor"
                    )
                    results_summary["Step b"] = "First Dataplane Monitor: Success"
                    self.workflow_manager.dashboard.update_phase_progress("Phase 1", 2, 5, "Step b Complete")
                    logging.info(f"✓ First Dataplane Monitor completed successfully.")
                except DataplaneError as e:
                    utils.suggest_dataplane_recovery_actions('3a', 'step_b', 'FIRST')
                    results_summary["Step b"] = f"First Dataplane Monitor: Failed - {e}"
                    script_aborted = True
                except Exception as e:
                    suggest_recovery_actions(type(e), "Step b", "Dataplane monitoring")
                    results_summary["Step b"] = f"First Dataplane Monitor: Failed - {e}"
                    script_aborted = True

            if not script_aborted:
                # Step c: 20-minute wait
                print(f"\n{'#' * 70}")
                print(f"### Step c: 20-minute Wait Time ###")
                print(f"{'#' * 70}")

                try:
                    self.workflow_manager.dashboard.update_phase_progress("Phase 1", 3, 5, "Step c - 20min Wait")
                    colorful_countdown_timer(WAIT_TIME_MINUTES * 60)
                    results_summary["Step c"] = f"20-minute Wait: Success"
                    self.workflow_manager.dashboard.update_phase_progress("Phase 1", 3, 5, "Step c Complete")
                    logging.info(f"✓ 20-minute wait completed.")
                except Exception as e:
                    suggest_recovery_actions(type(e), "Step c", "Wait time countdown")
                    results_summary["Step c"] = f"20-minute Wait: Failed - {e}"
                    script_aborted = True

            if not script_aborted:
                # Step d: Dummy scripts (--dummy no) - CRITICAL
                print(f"\n{'#' * 70}")
                print(f"### Step d: Running scripts with '--dummy' no (CRITICAL) ###")
                print(f"{'#' * 70}")

                try:
                    smart_retry_with_context(
                        lambda: execute_script_phase(self.router_ip, self.username, self.password,
                                                     self.scripts_to_run, "'--dummy' no",
                                                     SSH_TIMEOUT_SECONDS, "Phase 1"),
                        max_retries=1,  # Don't retry on degraded links
                        context="Step d - Dummy No"
                    )
                    results_summary["Step d"] = "Dummy No: Success"
                    self.workflow_manager.dashboard.update_phase_progress("Phase 1", 4, 5, "Step d Complete")
                    logging.info(f"✓ Dummy no phase completed successfully.")
                except ScriptExecutionError as e:
                    if "Degraded links found" in str(e):
                        results_summary["Step d"] = "Dummy No: Failed - Degraded links found"
                        logging.critical(f"✗ Dummy no phase failed: Degraded links found")

                        self._handle_degraded_links_phase1()
                        script_aborted = True
                    else:
                        suggest_recovery_actions(type(e), "Step d", "Dummy no execution")
                        results_summary["Step d"] = f"Dummy No: Failed - {e}"
                        script_aborted = True
                except Exception as e:
                    results_summary["Step d"] = f"Dummy No: Failed - {e}"
                    script_aborted = True

            if not script_aborted:
                # Step e: Manual intervention
                print(f"\n{'#' * 70}")
                print(f"### Step e: MANUAL INTERVENTION REQUIRED ###")
                print(f"{'#' * 70}")

                try:
                    self.workflow_manager.dashboard.update_phase_progress("Phase 1", 5, 5, "Step e - Manual Reload")
                    logging.critical("Please perform the two reloads now.")

                    self._provide_manual_intervention_guidance()

                    results_summary["Step e"] = "Manual Reload Step: Instructed User"
                    self.workflow_manager.dashboard.update_phase_progress("Phase 1", 5, 5, "Step e Complete")
                    logging.info(f"✓ Manual reload instructions provided to user.")
                except Exception as e:
                    suggest_recovery_actions(type(e), "Step e", "Manual intervention instruction")
                    results_summary["Step e"] = f"Manual Reload Step: Failed - {e}"

        except Exception as e:
            logging.critical(f"✗ Phase 1 execution failed: {e}")
            script_aborted = True

        # Phase completion handling
        phase_duration = time.time() - phase_start_time
        errors = [v for v in results_summary.values() if "Failed" in v]

        if self.workflow_manager:
            self.workflow_manager.state.save_phase_completion("phase_1", results_summary, errors)
            self.workflow_manager.dashboard.complete_phase("Phase 1", success=not script_aborted, errors=errors)

        # Display results
        self._display_phase_results("Phase 1", results_summary, phase_duration, script_aborted)

        if not script_aborted:
            print(f"\n🚀 NEXT STEPS:")
            print(f"   1. Complete the manual reloads as instructed")
            print(f"   2. Verify all system cards are operational")
            print(f"   3. Return to menu and execute Phase 2 when ready")

    def execute_phase_2(self):
        """Execute Phase 2 (Steps f-j) - Interactive version"""

        print(f"\n{'#' * 70}")
        print(f"### 🚀 PHASE 2 EXECUTION (Steps f-j) ###")
        print(f"{'#' * 70}")

        phase_config = self.phases["phase_2"]
        print(f"📋 Description: {phase_config.description}")
        print(f"⏱️  Estimated Duration: {phase_config.estimated_duration_minutes} minutes")
        print(f"🚨 Critical Steps: {', '.join(phase_config.critical_steps)}")

        if not self.confirm_action("Proceed with Phase 2 execution?"):
            return

        results_summary = {}
        script_aborted = False
        phase_start_time = time.time()

        # Start phase tracking
        self.workflow_manager.dashboard.start_phase("Phase 2 - Steps f-j")

        try:
            # Step f: Second dataplane monitor
            print(f"\n{'#' * 70}")
            print(f"### Step f: Second Dataplane Monitor ###")
            print(f"{'#' * 70}")

            try:
                smart_retry_with_context(
                    lambda: run_dataplane_monitor_phase(self.router_ip, self.username, self.password,
                                                        "SECOND", SSH_TIMEOUT_SECONDS,
                                                        DATAPLANE_MONITOR_TIMEOUT_SECONDS),
                    max_retries=2,
                    context="Step f - Second Dataplane Monitor"
                )
                results_summary["Step f"] = "Second Dataplane Monitor: Success"
                self.workflow_manager.dashboard.update_phase_progress("Phase 2", 1, 5, "Step f Complete")
                logging.info(f"✓ Second Dataplane Monitor completed successfully.")
            except DataplaneError as e:
                utils.suggest_dataplane_recovery_actions('3b', 'step_f', 'SECOND')
                results_summary["Step f"] = f"Second Dataplane Monitor: Failed - {e}"
                script_aborted = True
            except Exception as e:
                suggest_recovery_actions(type(e), "Step f", "Second dataplane monitoring")
                results_summary["Step f"] = f"Second Dataplane Monitor: Failed - {e}"
                script_aborted = True

            if not script_aborted:
                # Step g: Second 20-minute wait
                print(f"\n{'#' * 70}")
                print(f"### Step g: Second 20-minute Wait Time ###")
                print(f"{'#' * 70}")

                try:
                    self.workflow_manager.dashboard.update_phase_progress("Phase 2", 2, 5, "Step g - 20min Wait")
                    colorful_countdown_timer(WAIT_TIME_MINUTES * 60)
                    results_summary["Step g"] = f"Second 20-minute Wait: Success"
                    self.workflow_manager.dashboard.update_phase_progress("Phase 2", 2, 5, "Step g Complete")
                    logging.info(f"✓ Second 20-minute wait completed.")
                except Exception as e:
                    suggest_recovery_actions(type(e), "Step g", "Wait time countdown")
                    results_summary["Step g"] = f"Second 20-minute Wait: Failed - {e}"
                    script_aborted = True

            if not script_aborted:
                # Step h: Third dataplane monitor
                print(f"\n{'#' * 70}")
                print(f"### Step h: Third Dataplane Monitor ###")
                print(f"{'#' * 70}")

                try:
                    smart_retry_with_context(
                        lambda: run_dataplane_monitor_phase(self.router_ip, self.username, self.password,
                                                            "THIRD", SSH_TIMEOUT_SECONDS,
                                                            DATAPLANE_MONITOR_TIMEOUT_SECONDS),
                        max_retries=2,
                        context="Step h - Third Dataplane Monitor"
                    )
                    results_summary["Step h"] = "Third Dataplane Monitor: Success"
                    self.workflow_manager.dashboard.update_phase_progress("Phase 2", 3, 5, "Step h Complete")
                    logging.info(f"✓ Third Dataplane Monitor completed successfully.")
                except DataplaneError as e:
                    utils.suggest_dataplane_recovery_actions('3b', 'step_h', 'THIRD')
                    results_summary["Step h"] = f"Third Dataplane Monitor: Failed - {e}"
                    script_aborted = True
                except Exception as e:
                    suggest_recovery_actions(type(e), "Step h", "Third dataplane monitoring")
                    results_summary["Step h"] = f"Third Dataplane Monitor: Failed - {e}"
                    script_aborted = True

            if not script_aborted:
                # Step i: Show tech collection
                print(f"\n{'#' * 70}")
                print(f"### Step i: Show Tech Collection ###")
                print(f"{'#' * 70}")

                try:
                    smart_retry_with_context(
                        lambda: run_show_tech_phase(self.router_ip, self.username, self.password,
                                                    SSH_TIMEOUT_SECONDS),
                        max_retries=2,
                        context="Step i - Show Tech Collection"
                    )
                    results_summary["Step i"] = "Show Tech Collection: Success"
                    self.workflow_manager.dashboard.update_phase_progress("Phase 2", 4, 5, "Step i Complete")
                    logging.info(f"✓ Show tech collection completed successfully.")
                except (SSHConnectionError, RouterCommandError, ShowTechError) as e:
                    results_summary["Step i"] = f"Show Tech Collection: Failed - {e}"
                    logging.warning(f"⚠️ Show tech collection failed: {e}")

                    print(f"💡 SHOW TECH FAILURE GUIDANCE:")
                    print(f"   💾 Check available disk space: 'show filesystem harddisk:'")
                    print(f"   🕒 Wait for any ongoing show tech to complete")
                    print(f"   📁 Clean up old files if needed")
                    print(f"   ✅ Phase 2 can continue - show tech is non-critical")

                    # Don't abort - show tech is non-critical

            # Step j: Clear ASIC counters
            print(f"\n{'#' * 70}")
            print(f"### Step j: Clear ASIC Counters ###")
            print(f"{'#' * 70}")

            try:
                smart_retry_with_context(
                    lambda: run_clear_asic_counters(self.router_ip, self.username, self.password,
                                                    SSH_TIMEOUT_SECONDS),
                    max_retries=2,
                    context="Step j - Clear ASIC Counters"
                )
                results_summary["Step j"] = "Clear ASIC Counters: Success"
                self.workflow_manager.dashboard.update_phase_progress("Phase 2", 5, 5, "Step j Complete")
                logging.info(f"✓ Clear ASIC counters completed successfully.")
            except Exception as e:
                results_summary["Step j"] = f"Clear ASIC Counters: Failed - {e}"
                logging.warning(f"⚠️ Clear ASIC counters failed: {e}")

                print(f"💡 ASIC CLEARING GUIDANCE:")
                print(f"   ⏰ Wait for router to stabilize (5-10 minutes)")
                print(f"   📋 ASIC clearing failure is non-critical")
                print(f"   ✅ Phase 3 can proceed normally")

                # Don't abort - ASIC clearing is non-critical

        except Exception as e:
            logging.critical(f"✗ Phase 2 execution failed: {e}")
            script_aborted = True

        # Phase completion handling
        phase_duration = time.time() - phase_start_time
        errors = [v for v in results_summary.values() if "Failed" in v]

        if self.workflow_manager:
            self.workflow_manager.state.save_phase_completion("phase_2", results_summary, errors)
            self.workflow_manager.dashboard.complete_phase("Phase 2", success=not script_aborted, errors=errors)

        # Display results
        self._display_phase_results("Phase 2", results_summary, phase_duration, script_aborted)

        if not script_aborted:
            print(f"\n🚀 NEXT STEPS:")
            print(f"   1. Review Phase 2 execution results above")
            print(f"   2. Verify system stability")
            print(f"   3. Execute Phase 3 for final validation when ready")

    def execute_phase_3(self):
        """Execute Phase 3 (Steps k-q) - Interactive version with dual validation"""
        global PHASE3_DUMMY_NO_1_ERRORS_DETECTED, PHASE3_DUMMY_NO_2_ERRORS_DETECTED

        # Reset global flags for this execution
        PHASE3_DUMMY_NO_1_ERRORS_DETECTED = False
        PHASE3_DUMMY_NO_2_ERRORS_DETECTED = False

        print(f"\n{'#' * 70}")
        print(f"### 🚀 PHASE 3 EXECUTION (Steps k-q) - FINAL VALIDATION ###")
        print(f"{'#' * 70}")

        phase_config = self.phases["phase_3"]
        print(f"📋 Description: {phase_config.description}")
        print(f"⏱️  Estimated Duration: {phase_config.estimated_duration_minutes} minutes")
        print(f"🚨 Critical Steps: {', '.join(phase_config.critical_steps)} (DUAL VALIDATION)")

        print(f"\n⚠️  IMPORTANT: This phase contains dual validation for production readiness")
        print(f"   🎯 Step n: First critical validation")
        print(f"   🎯 Step q: Second critical validation")
        print(f"   🏆 Both must pass for production approval")

        if not self.confirm_action("Proceed with Phase 3 execution?"):
            return

        results_summary = {}
        script_aborted = False
        phase_start_time = time.time()

        # Start phase tracking
        self.workflow_manager.dashboard.start_phase("Phase 3 - Steps k-q")

        try:
            # Step k: Dummy scripts (--dummy yes) Part 3
            print(f"\n{'#' * 70}")
            print(f"### Step k: Running scripts with '--dummy' yes (Part 3) ###")
            print(f"{'#' * 70}")

            try:
                smart_retry_with_context(
                    lambda: execute_script_phase(self.router_ip, self.username, self.password,
                                                 self.scripts_to_run, "'--dummy' yes",
                                                 SSH_TIMEOUT_SECONDS, "Phase 3"),
                    max_retries=2,
                    context="Step k - Dummy Yes (Part 3)"
                )
                results_summary["Step k"] = "Dummy Yes (Part 3): Success"
                self.workflow_manager.dashboard.update_phase_progress("Phase 3", 1, 7, "Step k Complete")
                logging.info(f"✓ Dummy yes phase (Part 3) completed successfully.")
            except Exception as e:
                suggest_recovery_actions(type(e), "Step k", "Dummy yes execution (Part 3)")
                results_summary["Step k"] = f"Dummy Yes (Part 3): Failed - {e}"
                script_aborted = True

            if not script_aborted:
                # Step l: Fourth dataplane monitor
                print(f"\n{'#' * 70}")
                print(f"### Step l: Fourth Dataplane Monitor ###")
                print(f"{'#' * 70}")

                try:
                    smart_retry_with_context(
                        lambda: run_dataplane_monitor_phase(self.router_ip, self.username, self.password,
                                                            "FOURTH", SSH_TIMEOUT_SECONDS,
                                                            DATAPLANE_MONITOR_TIMEOUT_SECONDS),
                        max_retries=2,
                        context="Step l - Fourth Dataplane Monitor"
                    )
                    results_summary["Step l"] = "Fourth Dataplane Monitor: Success"
                    self.workflow_manager.dashboard.update_phase_progress("Phase 3", 2, 7, "Step l Complete")
                    logging.info(f"✓ Fourth Dataplane Monitor completed successfully.")
                except DataplaneError as e:
                    utils.suggest_dataplane_recovery_actions('3c', 'step_l', 'FOURTH')
                    results_summary["Step l"] = f"Fourth Dataplane Monitor: Failed - {e}"
                    script_aborted = True
                except Exception as e:
                    suggest_recovery_actions(type(e), "Step l", "Fourth dataplane monitoring")
                    results_summary["Step l"] = f"Fourth Dataplane Monitor: Failed - {e}"
                    script_aborted = True

            if not script_aborted:
                # Step m: Third 20-minute wait
                print(f"\n{'#' * 70}")
                print(f"### Step m: Third 20-minute Wait Time ###")
                print(f"{'#' * 70}")

                try:
                    self.workflow_manager.dashboard.update_phase_progress("Phase 3", 3, 7, "Step m - 20min Wait")
                    colorful_countdown_timer(WAIT_TIME_MINUTES * 60)
                    results_summary["Step m"] = f"Third 20-minute Wait: Success"
                    self.workflow_manager.dashboard.update_phase_progress("Phase 3", 3, 7, "Step m Complete")
                    logging.info(f"✓ Third 20-minute wait completed.")
                except Exception as e:
                    suggest_recovery_actions(type(e), "Step m", "Wait time countdown")
                    results_summary["Step m"] = f"Third 20-minute Wait: Failed - {e}"
                    script_aborted = True

            if not script_aborted:
                # Step n: First dummy no (CRITICAL VALIDATION #1)
                print(f"\n{'#' * 70}")
                print(f"### Step n: First Critical Validation (--dummy no) ###")
                print(f"{'#' * 70}")

                try:
                    smart_retry_with_context(
                        lambda: execute_script_phase(self.router_ip, self.username, self.password,
                                                     self.scripts_to_run, "'--dummy' no",
                                                     SSH_TIMEOUT_SECONDS, "Phase 3 - First Dummy No"),
                        max_retries=1,  # Don't retry on degraded links
                        context="Step n - First Dummy No (Critical)"
                    )
                    results_summary["Step n"] = "Dummy No (First in Part 3): Success"
                    self.workflow_manager.dashboard.update_phase_progress("Phase 3", 4, 7, "Step n Complete")
                    logging.info(f"✓ Dummy no phase (First in Part 3) completed successfully.")
                except ScriptExecutionError as e:
                    if "Degraded links found" in str(e):
                        PHASE3_DUMMY_NO_1_ERRORS_DETECTED = True
                        results_summary["Step n"] = "Dummy No (First in Part 3): Failed - Degraded links found"
                        logging.critical(f"✗ Dummy no phase (First in Part 3) failed: Degraded links found")

                        self._handle_degraded_links_phase3("n")
                        script_aborted = True
                    else:
                        results_summary["Step n"] = f"Dummy No (First in Part 3): Failed - {e}"
                        suggest_recovery_actions(type(e), "Step n", "First dummy no execution")
                        script_aborted = True
                except Exception as e:
                    results_summary["Step n"] = f"Dummy No (First in Part 3): Failed - {e}"
                    script_aborted = True

            if not script_aborted:
                # Step o: Fifth dataplane monitor
                print(f"\n{'#' * 70}")
                print(f"### Step o: Fifth Dataplane Monitor ###")
                print(f"{'#' * 70}")

                try:
                    smart_retry_with_context(
                        lambda: run_dataplane_monitor_phase(self.router_ip, self.username, self.password,
                                                            "FIFTH", SSH_TIMEOUT_SECONDS,
                                                            DATAPLANE_MONITOR_TIMEOUT_SECONDS),
                        max_retries=2,
                        context="Step o - Fifth Dataplane Monitor"
                    )
                    results_summary["Step o"] = "Fifth Dataplane Monitor: Success"
                    self.workflow_manager.dashboard.update_phase_progress("Phase 3", 5, 7, "Step o Complete")
                    logging.info(f"✓ Fifth Dataplane Monitor completed successfully.")
                except DataplaneError as e:
                    utils.suggest_dataplane_recovery_actions('3c', 'step_o', 'FIFTH')
                    results_summary["Step o"] = f"Fifth Dataplane Monitor: Failed - {e}"
                    script_aborted = True
                except Exception as e:
                    suggest_recovery_actions(type(e), "Step o", "Fifth dataplane monitoring")
                    results_summary["Step o"] = f"Fifth Dataplane Monitor: Failed - {e}"
                    script_aborted = True

            if not script_aborted:
                # Step p: Fourth 20-minute wait
                print(f"\n{'#' * 70}")
                print(f"### Step p: Fourth 20-minute Wait Time ###")
                print(f"{'#' * 70}")

                try:
                    self.workflow_manager.dashboard.update_phase_progress("Phase 3", 6, 7, "Step p - 20min Wait")
                    colorful_countdown_timer(WAIT_TIME_MINUTES * 60)
                    results_summary["Step p"] = f"Fourth 20-minute Wait: Success"
                    self.workflow_manager.dashboard.update_phase_progress("Phase 3", 6, 7, "Step p Complete")
                    logging.info(f"✓ Fourth 20-minute wait completed.")
                except Exception as e:
                    suggest_recovery_actions(type(e), "Step p", "Wait time countdown")
                    results_summary["Step p"] = f"Fourth 20-minute Wait: Failed - {e}"
                    script_aborted = True

            if not script_aborted:
                # Step q: Second dummy no (CRITICAL VALIDATION #2)
                print(f"\n{'#' * 70}")
                print(f"### Step q: Second Critical Validation (--dummy no) ###")
                print(f"{'#' * 70}")

                try:
                    smart_retry_with_context(
                        lambda: execute_script_phase(self.router_ip, self.username, self.password,
                                                     self.scripts_to_run, "'--dummy' no",
                                                     SSH_TIMEOUT_SECONDS, "Phase 3 - Second Dummy No"),
                        max_retries=1,  # Don't retry on degraded links
                        context="Step q - Second Dummy No (Final Critical)"
                    )
                    results_summary["Step q"] = "Dummy No (Second in Part 3): Success"
                    self.workflow_manager.dashboard.update_phase_progress("Phase 3", 7, 7,
                                                                          "Step q Complete - FINAL STEP")
                    logging.info(f"✓ Dummy no phase (Second in Part 3) completed successfully.")
                except ScriptExecutionError as e:
                    if "Degraded links found" in str(e):
                        PHASE3_DUMMY_NO_2_ERRORS_DETECTED = True
                        results_summary["Step q"] = "Dummy No (Second in Part 3): Failed - Degraded links found"
                        logging.critical(f"✗ Dummy no phase (Second in Part 3) failed: Degraded links found")

                        self._handle_degraded_links_phase3("q")
                        script_aborted = True
                    else:
                        results_summary["Step q"] = f"Dummy No (Second in Part 3): Failed - {e}"
                        suggest_recovery_actions(type(e), "Step q", "Second dummy no execution")
                        script_aborted = True
                except Exception as e:
                    results_summary["Step q"] = f"Dummy No (Second in Part 3): Failed - {e}"
                    script_aborted = True

        except Exception as e:
            logging.critical(f"✗ Phase 3 execution failed: {e}")
            script_aborted = True

        # Phase completion handling with dual validation assessment
        phase_duration = time.time() - phase_start_time
        errors = [v for v in results_summary.values() if "Failed" in v]

        if self.workflow_manager:
            self.workflow_manager.state.save_phase_completion("phase_3", results_summary, errors)
            self.workflow_manager.dashboard.complete_phase("Phase 3", success=not script_aborted, errors=errors)

        # Update results summary with dual error detection status
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

        # Display results with dual validation assessment
        self._display_phase_results("Phase 3", results_summary, phase_duration, script_aborted)

        # Final dual validation assessment
        step_n_success = not PHASE3_DUMMY_NO_1_ERRORS_DETECTED
        # Step q is only successful if it ran (is in results_summary) AND it had no errors.
        step_q_success = "Step q" in results_summary and not PHASE3_DUMMY_NO_2_ERRORS_DETECTED

        print(f"\n🔗 DUAL VALIDATION RESULTS:")
        print(f"   Step n (First): {'✅ PASSED' if step_n_success else '❌ FAILED'}")

        # Display a more accurate status for Step q
        if "Step q" not in results_summary:
            print(f"   Step q (Second): {'⚪ NOT RUN'}")
        else:
            print(f"   Step q (Second): {'✅ PASSED' if step_q_success else '❌ FAILED'}")

        dual_validation_success = step_n_success and step_q_success

        print(f"\n🏆 FINAL VALIDATION: {'✅ PASSED' if dual_validation_success else '❌ FAILED'}")
        if dual_validation_success:
            print(f"   🚀 System approved for production deployment")
        else:
            print(f"   🔧 Address validation failures before production")

    def execute_all_phases_sequential(self):
        """Execute all phases sequentially with checkpoints"""

        print(f"\n{'#' * 70}")
        print(f"### 🚀 COMPLETE WORKFLOW EXECUTION ###")
        print(f"{'#' * 70}")

        total_estimated = sum(phase.estimated_duration_minutes for phase in self.phases.values())
        print(
            f"⏱️  Total Estimated Duration: {total_estimated} minutes ({total_estimated // 60}h {total_estimated % 60}m)")
        print(f"📋 All Phases: Phase 1 → Phase 2 → Phase 3")

        print(f"\n⚠️  IMPORTANT NOTES:")
        print(f"   🔄 Phase 1 includes manual reload steps")
        print(f"   ⏸️  You can pause between phases if needed")
        print(f"   🛑 Critical failures will stop the workflow")

        if not self.confirm_action("Proceed with complete workflow execution?"):
            return

        workflow_start_time = time.time()
        overall_success = True

        # Execute Phase 1
        print(f"\n{'🎯 Starting Phase 1':=^80}")
        try:
            self.execute_phase_1()
            # Check if Phase 1 completed successfully
            if not self._check_phase_success("phase_1"):
                print(f"❌ Phase 1 failed - workflow stopped")
                return
        except Exception as e:
            logging.error(f"Phase 1 failed: {e}")
            overall_success = False
            return

        # Checkpoint between Phase 1 and 2
        print(f"\n{'⏸️  CHECKPOINT: Phase 1 → Phase 2':=^80}")
        print(f"📋 REQUIRED: Complete manual reloads before continuing")
        print(f"   1. First reload: Wait 30+ minutes")
        print(f"   2. Second reload: Wait 30+ minutes")
        print(f"   3. Verify all cards operational")

        if not self.confirm_action("Have manual reloads been completed successfully?"):
            print(f"⏸️  Workflow paused. Run Phase 2 manually when ready.")
            return

        # Execute Phase 2
        print(f"\n{'🎯 Starting Phase 2':=^80}")
        try:
            self.execute_phase_2()
            if not self._check_phase_success("phase_2"):
                print(f"❌ Phase 2 had issues - review before Phase 3")
                if not self.confirm_action("Continue to Phase 3 despite Phase 2 issues?"):
                    return
        except Exception as e:
            logging.error(f"Phase 2 failed: {e}")
            if not self.confirm_action("Continue to Phase 3 despite Phase 2 failure?"):
                return

        # Checkpoint between Phase 2 and 3
        print(f"\n{'⏸️  CHECKPOINT: Phase 2 → Phase 3':=^80}")
        print(f"📋 CRITICAL: Phase 3 contains final production validation")
        print(f"   🎯 Dual validation tests (Steps n and q)")
        print(f"   🏆 Both must pass for production approval")

        if not self.confirm_action("System stable and ready for final validation?"):
            print(f"⏸️  Workflow paused. Execute Phase 3 when system is stable.")
            return

        # Execute Phase 3
        print(f"\n{'🎯 Starting Phase 3 - FINAL VALIDATION':=^80}")
        try:
            self.execute_phase_3()
        except Exception as e:
            logging.error(f"Phase 3 failed: {e}")
            overall_success = False

        # Final workflow assessment
        workflow_duration = time.time() - workflow_start_time
        self._display_complete_workflow_results(workflow_duration, overall_success)

    # === INDIVIDUAL OPERATIONS ===

    def run_dataplane_monitor_interactive(self):
        """Interactive dataplane monitor execution"""

        print(f"\n🔍 DATAPLANE MONITOR")
        print(f"{'─' * 40}")

        monitor_types = [
            ("Single Monitor", "Quick dataplane health check", "~12 min"),
            ("Multiple Monitors", "Run 2-3 consecutive monitors", "~30-40 min")
        ]

        print(f"📋 Available Options:")
        for i, (name, desc, duration) in enumerate(monitor_types, 1):
            print(f"   {i}. {name} - {desc} ({duration})")

        choice = input(f"Select option (1-{len(monitor_types)}): ")

        try:
            if choice == "1":
                self._single_dataplane_monitor()
            elif choice == "2":
                self._multiple_dataplane_monitors()
            else:
                print(f"❌ Invalid selection")
        except Exception as e:
            print(f"❌ Dataplane monitor operation failed: {e}")

    def run_dummy_scripts_interactive(self):
        """Interactive dummy script execution"""

        print(f"\n🐍 DUMMY SCRIPT EXECUTION")
        print(f"{'─' * 40}")

        script_options = [
            ("Baseline Check", "--dummy yes", "Safe baseline validation", "~5 min"),
            ("Critical Validation", "--dummy no", "⚠️ May detect degraded links", "~5 min")
        ]

        print(f"📋 Available Options:")
        for i, (name, option, desc, duration) in enumerate(script_options, 1):
            print(f"   {i}. {name} ({option}) - {desc} ({duration})")

        choice = input(f"Select option (1-{len(script_options)}): ")

        try:
            if choice == "1":
                self._execute_dummy_scripts_interactive("'--dummy' yes", "Interactive Baseline")
            elif choice == "2":
                print(f"⚠️  WARNING: This may detect degraded links and impact workflow")
                if self.confirm_action("Proceed with critical validation?"):
                    self._execute_dummy_scripts_interactive("'--dummy' no", "Interactive Critical")
            else:
                print(f"❌ Invalid selection")
        except Exception as e:
            print(f"❌ Dummy script operation failed: {e}")

    def run_show_tech_interactive(self):
        """Interactive show tech collection"""

        print(f"\n📊 SHOW TECH COLLECTION")
        print(f"{'─' * 40}")

        print(f"📋 Show Tech Information:")
        print(f"   🎯 Purpose: Comprehensive diagnostic data collection")
        print(f"   ⏱️  Duration: ~15-30 minutes")
        print(f"   💾 Output: Compressed .tgz file on harddisk:")
        print(f"   📊 Content: Fabric, link, and system information")

        if not self.confirm_action("Proceed with show tech collection?"):
            return

        try:
            success = smart_retry_with_context(
                lambda: run_show_tech_phase(self.router_ip, self.username, self.password, SSH_TIMEOUT_SECONDS),
                max_retries=2,
                context="Interactive Show Tech"
            )

            if success:
                print(f"✅ Show tech collection completed successfully")
            else:
                print(f"❌ Show tech collection failed")

        except Exception as e:
            print(f"❌ Show tech collection failed: {e}")
            print(f"💡 This is typically non-critical for workflow continuation")

    def clear_asic_counters_interactive(self):
        """Interactive ASIC counter clearing"""

        print(f"\n🧹 CLEAR ASIC COUNTERS")
        print(f"{'─' * 40}")

        print(f"📋 ASIC Counter Clearing Information:")
        print(f"   🎯 Purpose: Reset ASIC error counters for clean monitoring")
        print(f"   ⏱️  Duration: ~30 seconds")
        print(f"   📊 Impact: Clears historical error data")
        print(f"   ✅ Safety: Non-disruptive operation")

        if not self.confirm_action("Proceed with ASIC counter clearing?"):
            return

        try:
            success = smart_retry_with_context(
                lambda: run_clear_asic_counters(self.router_ip, self.username, self.password, SSH_TIMEOUT_SECONDS),
                max_retries=2,
                context="Interactive ASIC Clear"
            )

            if success:
                print(f"✅ ASIC counters cleared successfully")
            else:
                print(f"❌ ASIC counter clearing failed")

        except Exception as e:
            print(f"❌ ASIC counter clearing failed: {e}")
            print(f"💡 This is typically non-critical for workflow continuation")

    # === HELPER METHODS ===

    def _single_dataplane_monitor(self):
        """Execute single dataplane monitor"""
        try:
            print(f"\n🔍 Running single dataplane monitor...")
            result = run_dataplane_monitor_phase(
                self.router_ip, self.username, self.password,
                "INTERACTIVE", SSH_TIMEOUT_SECONDS, DATAPLANE_MONITOR_TIMEOUT_SECONDS
            )

            if result:
                print(f"✅ Dataplane monitor completed successfully")
                print(f"🎯 System Status: HEALTHY")
            else:
                print(f"❌ Dataplane issues detected")

        except Exception as e:
            print(f"❌ Dataplane monitor failed: {e}")

    def _multiple_dataplane_monitors(self):
        """Execute multiple consecutive dataplane monitors"""
        monitor_count = 3
        print(f"\n🔍 Running {monitor_count} consecutive dataplane monitors...")

        results = []
        for i in range(monitor_count):
            try:
                print(f"\n--- Monitor {i + 1} of {monitor_count} ---")
                result = run_dataplane_monitor_phase(
                    self.router_ip, self.username, self.password,
                    f"BATCH_{i + 1}", SSH_TIMEOUT_SECONDS, DATAPLANE_MONITOR_TIMEOUT_SECONDS
                )
                results.append(result)

                if result:
                    print(f"✅ Monitor {i + 1}: CLEAN")
                else:
                    print(f"❌ Monitor {i + 1}: ISSUES DETECTED")

                # Brief pause between monitors
                if i < monitor_count - 1:
                    print(f"⏱️ Brief pause before next monitor...")
                    time.sleep(30)

            except Exception as e:
                print(f"❌ Monitor {i + 1} failed: {e}")
                results.append(False)

        # Summary
        successful_monitors = sum(1 for r in results if r)
        print(f"\n📊 MULTIPLE MONITOR SUMMARY:")
        print(f"   ✅ Successful: {successful_monitors}/{monitor_count}")
        print(f"   {'🎯 Overall Status: HEALTHY' if successful_monitors == monitor_count else '⚠️ Issues detected'}")

    def _execute_dummy_scripts_interactive(self, dummy_option: str, context: str):
        """Execute dummy scripts with interactive error handling"""

        print(f"\n🐍 Executing dummy scripts with option: {dummy_option}")
        print(f"📝 Context: {context}")

        try:
            success = execute_script_phase(
                self.router_ip, self.username, self.password,
                self.scripts_to_run, dummy_option, SSH_TIMEOUT_SECONDS, context
            )

            if success:
                print(f"✅ Dummy script execution completed successfully")
                if dummy_option == "'--dummy' no":
                    print(f"🎯 Critical Validation: PASSED")

            return success

        except ScriptExecutionError as e:
            if "Degraded links found" in str(e):
                print(f"❌ Degraded links detected in {context}")
                self._handle_degraded_links_interactive(context)
                return False
            else:
                print(f"❌ Script execution failed: {e}")
                return False
        except Exception as e:
            print(f"❌ Unexpected error during script execution: {e}")
            return False

    def _handle_degraded_links_phase1(self):
        """Handle degraded links detected in Phase 1"""
        print(f"🚨 CRITICAL: Degraded Links Detected in Phase 1")
        print(f"📋 Required Actions Before Proceeding:")
        print(f"   🔍 1. Review link degradation analysis above")
        print(f"   🔧 2. Investigate and fix physical layer issues")
        print(f"   🔄 3. Consider LC/FC reseating or replacement")
        print(f"   ⚠️  4. Do NOT proceed to Phase 2 until resolved")

    def _handle_degraded_links_phase3(self, step: str):
        """Handle degraded links detected in Phase 3"""
        if step == "n":
            print(f"🚨 CRITICAL PHASE 3 FAILURE - DEGRADED LINKS DETECTED")
            print(f"📋 IMMEDIATE ACTIONS REQUIRED:")
            print(f"   🔴 1. STOP - Do not proceed to Step o")
            print(f"   🔍 2. Analyze link degradation data above immediately")
            print(f"   🔧 3. Physical layer intervention required:")
            print(f"      • Check LC-FC physical connections")
            print(f"      • Consider LC/FC reseating")
            print(f"      • Verify optics are properly seated")
            print(f"   🔄 4. After fixes, restart entire Phase 3")
            print(f"   ❌ 5. Do NOT continue to Step o with degraded links")
        elif step == "q":
            print(f"🚨 CRITICAL FINAL PHASE FAILURE - DEGRADED LINKS DETECTED")
            print(f"📋 COMPREHENSIVE FAILURE ANALYSIS:")
            print(f"   ❌ FINAL VALIDATION FAILED")
            print(f"   🔍 Root Cause Analysis Required:")
            print(f"      • Compare Step n vs Step q degradation patterns")
            print(f"      • Identify if issues are worsening or consistent")
            print(f"      • Check for intermittent connection problems")
            print(f"   🔧 REQUIRED ACTIONS:")
            print(f"      • Full LC/FC physical inspection")
            print(f"      • Consider hardware replacement")
            print(f"      • Validate optics integrity")
            print(f"   🚫 SYSTEM NOT READY FOR PRODUCTION")

    def _handle_degraded_links_interactive(self, context: str):
        """Interactive handling of degraded links"""
        print(f"\n🚨 DEGRADED LINKS DETECTED - {context}")
        print(f"{'=' * 60}")

        recovery_options = [
            "🔍 View detailed error analysis",
            "📋 Get recovery procedure checklist",
            "💡 Get hardware-specific guidance",
            "🔄 Continue anyway (NOT RECOMMENDED)",
            "⏹️  Stop and address issues (RECOMMENDED)"
        ]

        print(f"\n💡 AVAILABLE ACTIONS:")
        for i, option in enumerate(recovery_options, 1):
            print(f"   {i}. {option}")

        choice = input(f"\nSelect action (1-{len(recovery_options)}): ")

        if choice == "1":
            self._display_detailed_error_analysis()
        elif choice == "2":
            self._generate_recovery_checklist()
        elif choice == "3":
            self._provide_hardware_guidance()
        elif choice == "4":
            print(f"⚠️  Continuing with degraded links - HIGH RISK")
            return True
        elif choice == "5":
            print(f"✅ Recommended action - stopping for issue resolution")
            return False
        else:
            print(f"❌ Invalid selection - defaulting to stop")
            return False

    def _provide_manual_intervention_guidance(self):
        """Provide detailed manual intervention guidance"""
        print(f"🔄 RELOAD PROCEDURE GUIDANCE:")
        print(f"   1. Perform first reload: 'reload location all' or equivalent")
        print(f"   2. Wait for complete system startup (30+ minutes)")
        print(f"   3. Verify all cards show OPERATIONAL in 'show platform'")
        print(f"   4. Perform second reload: 'reload location all' or equivalent")
        print(f"   5. Wait for complete system startup (30+ minutes)")
        print(f"   6. Verify system stability before continuing")

        print(f"\n📋 VERIFICATION CHECKLIST:")
        print(f"   ✅ All cards OPERATIONAL")
        print(f"   ✅ No active critical alarms")
        print(f"   ✅ Fabric connectivity stable")
        print(f"   ✅ System responsive to commands")

    def show_execution_status(self):
        """Display comprehensive execution status"""

        print(f"\n📊 EXECUTION STATUS DASHBOARD")
        print(f"{'=' * 80}")

        # Session information
        session_duration = time.time() - self.session_start_time
        print(f"🏷️  Router: {self.hostname} ({self.router_ip})")
        print(f"📅 Session Duration: {format_execution_time(session_duration)}")
        print(f"👤 User: {self.username}")

        # Workflow state analysis
        if self.workflow_manager:
            state = self.workflow_manager.state.state
            completed_phases = state.get('completed_phases', {})

            print(f"\n🎯 WORKFLOW STATE:")
            for phase_key, phase_config in self.phases.items():
                if phase_key in completed_phases:
                    phase_data = completed_phases[phase_key]
                    status_icon = "✅" if phase_data.get('success') else "❌"
                    timestamp = phase_data.get('timestamp', 'N/A')
                    error_count = len(phase_data.get('errors', []))

                    print(f"   {status_icon} {phase_config.phase_name}")
                    print(f"      📅 Completed: {timestamp}")
                    if error_count > 0:
                        print(f"      ⚠️  Errors: {error_count}")
                else:
                    print(f"   ⏳ {phase_config.phase_name}: Not Started")

            # Overall summary
            total_errors = state.get('total_errors', 0)
            print(f"\n📈 OVERALL SUMMARY:")
            print(f"   📊 Total Phases: {len(self.phases)}")
            print(f"   ✅ Completed: {len(completed_phases)}")
            print(f"   ❌ Total Errors: {total_errors}")

        else:
            print(f"⚠️  No workflow state available")

        input(f"\nPress Enter to continue...")

    def show_help(self):
        """Display comprehensive help information"""

        print(f"\n❓ FRAMEWORK HELP & DOCUMENTATION")
        print(f"{'=' * 80}")

        print(f"\n📋 PHASE DESCRIPTIONS:")
        for phase_key, phase_config in self.phases.items():
            print(f"\n🎯 {phase_config.phase_name}:")
            print(f"   📝 {phase_config.description}")
            print(f"   ⏱️  Duration: ~{phase_config.estimated_duration_minutes} minutes")
            print(f"   📋 Steps: {', '.join(phase_config.steps)}")
            print(f"   🚨 Critical: {', '.join(phase_config.critical_steps)}")

        print(f"\n🔍 OPERATION DESCRIPTIONS:")
        operations = [
            ("Dataplane Monitor", "Validates dataplane health and stability"),
            ("Dummy Scripts", "Checks for degraded links using monitor scripts"),
            ("Show Tech", "Collects comprehensive diagnostic information"),
            ("ASIC Clear", "Resets ASIC error counters")
        ]

        for name, description in operations:
            print(f"   🔧 {name}: {description}")

        print(f"\n🚨 IMPORTANT SAFETY NOTES:")
        print(f"   ⚠️  Always complete manual reloads between Phase 1 and 2")
        print(f"   ❌ Never proceed with degraded links in critical validations")
        print(f"   ✅ Non-critical failures (show tech, ASIC clear) can continue")
        print(f"   🏆 Phase 3 dual validation must both pass for production")

        print(f"\n📞 SUPPORT:")
        print(f"   👤 Author: {__author__}")
        print(f"   📧 Email: {__email__}")
        print(f"   📦 Version: {__version__}")

        input(f"\nPress Enter to return to menu...")

    def _check_phase_success(self, phase_key: str) -> bool:
        """Check if a phase completed successfully"""
        if not self.workflow_manager:
            return False

        completed_phases = self.workflow_manager.state.state.get('completed_phases', {})
        if phase_key in completed_phases:
            return completed_phases[phase_key].get('success', False)

        return False

    def _display_phase_results(self, phase_name: str, results: Dict[str, str], duration: float, aborted: bool):
        """Display comprehensive phase results"""

        print(f"\n{'#' * 70}")
        print(f"### Final Summary for {phase_name} ###")
        print(f"{'#' * 70}")

        # Status overview
        if aborted:
            print(f"❌ {phase_name} - EXECUTION ABORTED")
        else:
            print(f"✅ {phase_name} - EXECUTION COMPLETED")

        # Detailed results
        print_final_summary(results, duration)

        # Error analysis
        errors = [k for k, v in results.items() if "Failed" in v]
        if errors:
            print(f"\n⚠️  ERRORS DETECTED:")
            for error_step in errors:
                print(f"   ❌ {error_step}: {results[error_step]}")
        else:
            print(f"\n✅ NO ERRORS DETECTED")

    def _display_complete_workflow_results(self, duration: float, success: bool):
        """Display complete workflow execution results"""

        print(f"\n{'#' * 80}")
        print(f"### 🏆 COMPLETE WORKFLOW RESULTS ###")
        print(f"{'#' * 80}")

        print(f"⏱️  Total Execution Time: {format_execution_time(duration)}")
        print(f"📊 Overall Status: {'✅ SUCCESS' if success else '❌ ISSUES DETECTED'}")

        # Phase-by-phase summary
        if self.workflow_manager:
            completed_phases = self.workflow_manager.state.state.get('completed_phases', {})

            print(f"\n📋 PHASE-BY-PHASE SUMMARY:")
            for phase_key, phase_config in self.phases.items():
                if phase_key in completed_phases:
                    phase_data = completed_phases[phase_key]
                    status_icon = "✅" if phase_data.get('success') else "❌"
                    error_count = len(phase_data.get('errors', []))

                    print(f"   {status_icon} {phase_config.phase_name}")
                    if error_count > 0:
                        print(f"      ⚠️  {error_count} errors detected")

            # Final production readiness assessment
            if success and not PHASE3_DUMMY_NO_1_ERRORS_DETECTED and not PHASE3_DUMMY_NO_2_ERRORS_DETECTED:
                print(f"\n🏆 PRODUCTION READINESS: ✅ APPROVED")
                print(f"   🚀 System certified for production deployment")
            else:
                print(f"\n🚫 PRODUCTION READINESS: ❌ NOT APPROVED")
                print(f"   🔧 Address identified issues before production")

    def cleanup(self):
        """Cleanup framework resources"""
        print(f"\n🧹 Framework Cleanup...")

        # Restore stdout
        sys.stdout = self.true_original_stdout

        # Close file handlers
        if self.session_log_file_handler:
            logging.root.removeHandler(self.session_log_file_handler)
            self.session_log_file_handler.close()

        if self.raw_output_file:
            self.raw_output_file.close()

        # Close global session files
        if utils.session_log_file_console_mirror:
            utils.session_log_file_console_mirror.close()
        if utils.session_log_file_raw_output:
            utils.session_log_file_raw_output.close()

        # Clean up logging handlers
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)

        total_session_time = time.time() - self.session_start_time
        print(f"📊 Total Session Time: {format_execution_time(total_session_time)}")
        print(f"✅ Framework cleanup completed")


def main():
    """Enhanced main function with interactive framework"""

    print(f"{'=' * 80}")
    print(f"{'🚀 IOS-XR 7.3.5 Fabric Card Remediation Framework':^80}")
    print(f"{'Combined Interactive Post-Check Automation v3.0':^80}")
    print(f"{'=' * 80}")

    framework = InteractiveFrameworkManager()

    try:
        # Initialize framework
        framework.initialize()

        # Run interactive loop
        framework.run_interactive_framework()

    except KeyboardInterrupt:
        print(f"\n\n⚠️ Framework interrupted by user")
    except Exception as e:
        logging.critical(f"Framework execution failed: {e}", exc_info=True)
        print(f"❌ Critical framework error: {e}")
    finally:
        framework.cleanup()
        print(f"\n👋 Framework session ended")


if __name__ == "__main__":
    main()