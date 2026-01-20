# This script is a comprehensive audit tool for Cisco IOS-XR and NX-OS devices,
# optimized for large-scale execution (e.g., 3000+ devices).
#
# Key Capabilities:
#
# 1.  **Multi-Platform Support:**
#     - **IOS-XR:** Automatically detects IOS-XR devices. Specifically targets 8800 series line cards
#       (8800-LC-48H, 88-LC0-36FH, 88-LC0-36FH-M) to count installed optics.
#     - **NX-OS:** Automatically detects Nexus devices. Audits all installed modules and transceivers.
#
# 2.  **Scale & Performance:**
#     - **High Concurrency:** Defaults to 50 concurrent threads to process large lists quickly.
#     - **Retry Logic:** Includes a robust retry mechanism (3 attempts) for SSH connections.
#     - **CSV Export:** Automatically exports a consolidated CSV report of SUCCESSFUL devices only.
#
# 3.  **Intelligent Device Interrogation:**
#     - **OS & Chassis Detection:** Dynamically determines OS and Chassis model via 'show version'.
#     - **Interactive Shell:** Uses `invoke_shell()` to bypass common non-interactive authorization issues.
#
# 4.  **Reporting:**
#     - **Console:** Prints progress, OS-specific summaries, AND a dedicated failure report for unreachable devices.
#     - **Files:** Saves a master CSV report (Raw text files are no longer generated to reduce clutter).
#
# Usage:
# Run the script, enter your SSH username and password when prompted, then paste your list of
# device hostnames or IP addresses (one per line), pressing Enter twice when finished.
#
# Requirements:
# - Python 3.x
# - paramiko (`pip install paramiko`)
# - prettytable (`pip install prettytable`)


__author__ = "Pronoy Dasgupta"
__copyright__ = "Copyright 2024 (C) Cisco Systems, Inc."
__credits__ = "Pronoy Dasgupta"
__version__ = "2.4.0"
__maintainer__ = "Pronoy Dasgupta"
__email__ = "prongupt@cisco.com"
__status__ = "production"

import getpass
import paramiko
import time
from prettytable import PrettyTable, FRAME
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import datetime
import os
import csv
import sys

# --- Configuration Constants ---
MAX_WORKERS = 50  # Number of concurrent threads
MAX_RETRIES = 3  # Number of SSH connection attempts per device
RETRY_DELAY = 5  # Seconds to wait between retries
SSH_TIMEOUT = 20  # Seconds to wait for SSH connection

# ANSI escape codes for text formatting
COLOR_BOLD_GREEN = "\033[1;92m"
COLOR_BOLD_RED = "\033[1;91m"
COLOR_BOLD_YELLOW = "\033[1;93m"
COLOR_RESET = "\033[0m"


def get_timestamp_log():
    """Returns a formatted timestamp string for logging."""
    return datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")


def get_device_info_list():
    """
    Prompts the user for a list of router hostnames/IPs (allowing paste),
    then a single username and password.
    """
    hostnames = []

    print("\nPaste your list of hostnames or IP addresses below, one per line.")
    print("Press Enter twice when you are finished (i.e., an empty line):")

    while True:
        line = input()
        if not line:
            if not hostnames or hostnames[-1] == "":
                break
            hostnames.append("")
        else:
            hostnames.append(line.strip())

    hostnames = [h for h in hostnames if h]

    if not hostnames:
        print(f"{COLOR_BOLD_RED}No hostnames entered. Exiting.{COLOR_RESET}")
        return []

    print("\n--- Authentication Details (for all devices) ---")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    device_list = []
    for host in hostnames:
        device_list.append({
            "host": host,
            "username": username,
            "password": password,
        })
    return device_list


def parse_show_platform(output):
    """
    Parses 'show platform' (IOS-XR) to find specific 8800 line cards.
    """
    lc_info_list = []
    lines = output.splitlines()
    target_models_regex = r"(0/\d+/CPU0)\s+.*?(8800-LC-48H|88-LC0-36FH-M|88-LC0-36FH).*?IOS XR RUN"

    for line in lines:
        clean_line = line.strip()
        match = re.search(target_models_regex, clean_line)
        if match:
            slot = match.group(1)
            model = match.group(2)
            lc_info_list.append({'slot': slot, 'model': model})
    return lc_info_list


def parse_show_inventory_location(output):
    """
    Parses 'show inventory location' (IOS-XR) for optics PIDs.
    """
    optics_category_counts = {}
    lines = output.splitlines()

    for i, line in enumerate(lines):
        if "DESCR:" in line and "Pluggable Optics Module" in line:
            for j in range(i + 1, len(lines)):
                next_line = lines[j]
                if "PID:" in next_line:
                    pid_start_index = next_line.find("PID:")
                    if pid_start_index != -1:
                        pid_substring = next_line[pid_start_index + len("PID:"):].strip()
                        pid_end_index = pid_substring.find(",")
                        if pid_end_index != -1:
                            pid = pid_substring[:pid_end_index].strip()
                        else:
                            pid = pid_substring.strip()

                        optics_category_counts[pid] = optics_category_counts.get(pid, 0) + 1
                    break
                if "NAME:" in next_line or "DESCR:" in next_line:
                    break
    return optics_category_counts


def parse_nxos_show_module(output):
    """
    Parses 'show module' (NX-OS) to map Slots to Models.
    """
    slot_models = {}
    lines = output.splitlines()
    regex = r"^(\d+)\s+\d+\s+.*?\s+([A-Z0-9][A-Z0-9-]+)\s+(?:ok|active|standby|ha-standby)"

    for line in lines:
        line = line.strip()
        match = re.search(regex, line, re.IGNORECASE)
        if match:
            slot = match.group(1)
            model = match.group(2)
            slot_models[slot] = model
    return slot_models


def parse_nxos_transceiver_output(output):
    """
    Parses 'show interface transceiver' (NX-OS). Returns nested dict by slot.
    """
    slot_optics = {}
    lines = output.splitlines()
    transceiver_present = False
    current_slot = None

    for line in lines:
        line = line.strip()
        if line.startswith("Ethernet"):
            transceiver_present = False
            match = re.match(r"Ethernet(\d+)/", line)
            if match:
                current_slot = match.group(1)
            else:
                current_slot = None
            continue

        if "transceiver is present" in line:
            transceiver_present = True
            continue

        if transceiver_present and line.startswith("type is") and current_slot:
            parts = line.split("type is")
            if len(parts) > 1:
                pid = parts[1].strip()
                if current_slot not in slot_optics:
                    slot_optics[current_slot] = {}
                slot_optics[current_slot][pid] = slot_optics[current_slot].get(pid, 0) + 1
            transceiver_present = False
    return slot_optics


def send_command_interactive(shell, command, wait_time=2, max_loops=15):
    """
    Sends a command to an interactive shell and waits for the output.
    """
    shell.send(command + '\n')
    output = ""
    for _ in range(max_loops):
        if shell.recv_ready():
            chunk = shell.recv(65535).decode('utf-8', errors='ignore')
            output += chunk
            if output.strip().endswith('#'):
                break
        time.sleep(wait_time)
    return output


def connect_with_retry(hostname, username, password):
    """
    Attempts to connect to the device with retries.
    Returns (client, shell) if successful, or raises Exception if all retries fail.
    """
    last_exception = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            client.connect(
                hostname=hostname,
                username=username,
                password=password,
                timeout=SSH_TIMEOUT,
                look_for_keys=False,
                allow_agent=False,
                banner_timeout=20
            )

            shell = client.invoke_shell()
            time.sleep(1)
            if shell.recv_ready():
                shell.recv(65535)  # Clear banner

            shell.send("terminal length 0\n")
            time.sleep(1)
            if shell.recv_ready():
                shell.recv(65535)  # Clear output

            return client, shell

        except Exception as e:
            last_exception = e
            if client:
                client.close()
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
            else:
                raise last_exception


def process_device_optics(device_config):
    """
    Connects to a single device, identifies OS/Chassis, and counts optics.
    """
    hostname = device_config["host"]
    username = device_config["username"]
    password = device_config["password"]

    device_results = {
        "hostname": hostname,
        "status": "Success",
        "error_message": None,
        "line_cards": [],
        "os_type": "Unknown",
        "os_version": "Unknown",
        "chassis_type": "Unknown"
    }

    client = None
    shell = None

    try:
        # Use the retry wrapper
        client, shell = connect_with_retry(hostname, username, password)

        # --- OS Detection ---
        xr_check_output = send_command_interactive(shell, 'show version | i "Cisco IOS XR Software"')

        # FIX: Check for "Version" as well to avoid matching the command echo on NX-OS
        if "Cisco IOS XR Software" in xr_check_output and "Version" in xr_check_output:
            # Step B: It is IOS-XR
            device_results["os_type"] = "IOS-XR"

            # Get Version & Chassis
            full_ver_output = send_command_interactive(shell, 'show version', wait_time=2)

            # Parse Version
            xr_version_found = False
            for line in full_ver_output.splitlines():
                if "Label" in line and ":" in line:
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        device_results["os_version"] = parts[1].strip()
                        xr_version_found = True
                        break
            if not xr_version_found:
                # Fallback parse
                for line in xr_check_output.splitlines():
                    if "Version" in line:
                        parts = line.split("Version", 1)
                        if len(parts) > 1:
                            device_results["os_version"] = parts[1].strip().split(" ")[0]
                            xr_version_found = True
                            break
            if not xr_version_found:
                device_results["os_version"] = "Parse Error"

            # Parse Chassis
            for line in full_ver_output.splitlines():
                if "Chassis" in line and "Cisco" in line:
                    match = re.search(r"(Cisco\s+88\d+)", line)
                    if match:
                        device_results["chassis_type"] = match.group(1)
                        break
                    if line.strip().startswith("Cisco") and "Chassis" in line:
                        device_results["chassis_type"] = line.strip()
                        break

            # Get Platform & Optics
            platform_output = send_command_interactive(shell, "show platform", wait_time=2)
            if "authorization failed" in platform_output.lower():
                device_results["status"] = "Authorization Failed"
                device_results["error_message"] = "User does not have permission to run 'show platform'."
                return device_results

            lc_info_list = parse_show_platform(platform_output)
            if not lc_info_list:
                device_results["status"] = "No target 8800 LC found"
                device_results["error_message"] = "No target 8800 line cards (48H/36FH) found."
                return device_results

            for lc_info in lc_info_list:
                slot = lc_info['slot']
                model = lc_info['model']
                lc_data = {"slot": slot, "model": model, "optics_counts": {}, "total_optics": 0, "lc_error": None}

                command = f"show inventory location {slot}"
                inventory_output = send_command_interactive(shell, command, wait_time=2)

                if "Invalid input" in inventory_output or "Error" in inventory_output:
                    lc_data["lc_error"] = f"Error executing '{command}'"
                else:
                    optics_counts = parse_show_inventory_location(inventory_output)
                    lc_data["optics_counts"] = optics_counts
                    lc_data["total_optics"] = sum(optics_counts.values())
                device_results["line_cards"].append(lc_data)

        else:
            # --- NX-OS Check ---
            nx_check_output = send_command_interactive(shell, 'show version', wait_time=2)

            if "NX-OS" in nx_check_output or "Nexus" in nx_check_output:
                device_results["os_type"] = "NX-OS"

                # Parse Version
                for line in nx_check_output.splitlines():
                    if "version" in line and ("system" in line or "NX-OS" in line or "NXOS" in line):
                        parts = line.split("version")
                        if len(parts) > 1:
                            device_results["os_version"] = parts[1].strip()
                            break
                if device_results["os_version"] == "Unknown":
                    device_results["os_version"] = "Detected (Parse Error)"

                # Parse Chassis
                lines = nx_check_output.splitlines()
                for i, line in enumerate(lines):
                    if line.strip() == "Hardware":
                        for j in range(1, 5):
                            if i + j < len(lines):
                                hw_line = lines[i + j].strip()
                                if "cisco" in hw_line.lower() and "Nexus" in hw_line:
                                    match = re.search(r"cisco\s+Nexus\d+\s+([A-Z0-9-]+)", hw_line, re.IGNORECASE)
                                    if match:
                                        device_results["chassis_type"] = match.group(1)
                                    else:
                                        device_results["chassis_type"] = hw_line
                                    break

                module_output = send_command_interactive(shell, "show module", wait_time=2)
                slot_model_map = parse_nxos_show_module(module_output)
                transceiver_output = send_command_interactive(shell, "show interface transceiver", wait_time=3)

                slot_optics_data = parse_nxos_transceiver_output(transceiver_output)

                for slot, optics_counts in slot_optics_data.items():
                    model_pid = slot_model_map.get(slot, "Unknown Module")
                    lc_data = {
                        "slot": f"Slot {slot}",
                        "model": model_pid,
                        "optics_counts": optics_counts,
                        "total_optics": sum(optics_counts.values()),
                        "lc_error": None
                    }
                    device_results["line_cards"].append(lc_data)

                if not slot_optics_data:
                    # Dummy entry for summary
                    first_slot = next(iter(slot_model_map), "Chassis")
                    first_model = slot_model_map.get(first_slot, "NX-OS")
                    lc_data = {"slot": f"Slot {first_slot}", "model": first_model, "optics_counts": {},
                               "total_optics": 0, "lc_error": None}
                    device_results["line_cards"].append(lc_data)
            else:
                device_results["status"] = "Unknown OS"
                device_results["error_message"] = "Could not identify device as IOS-XR or NX-OS."

    except Exception as e:
        device_results["status"] = "Connection Error"
        device_results["error_message"] = str(e)
    finally:
        if client:
            client.close()

    return device_results


def export_to_csv(results, filename):
    """
    Exports the consolidated results to a CSV file.
    Only exports devices with Status = "Success".
    """
    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        # Header
        writer.writerow([
            "Hostname", "OS Type", "OS Version", "Chassis Model",
            "Status", "Error Message",
            "Slot", "Module Model", "Optic PID", "Count", "Total Optics on Module"
        ])

        for res in results:
            # Skip failed devices
            if res["status"] != "Success":
                continue

            base_row = [
                res["hostname"], res["os_type"], res["os_version"], res["chassis_type"],
                res["status"], res["error_message"]
            ]

            if not res["line_cards"]:
                # Write a row even if no line cards found, to record the device status
                writer.writerow(base_row + ["N/A", "N/A", "N/A", 0, 0])
            else:
                for lc in res["line_cards"]:
                    if lc["optics_counts"]:
                        for pid, count in lc["optics_counts"].items():
                            writer.writerow(base_row + [
                                lc["slot"], lc["model"], pid, count, lc["total_optics"]
                            ])
                    else:
                        # Write a row for the module even if 0 optics
                        writer.writerow(base_row + [
                            lc["slot"], lc["model"], "None", 0, 0
                        ])


def print_summary_for_os(results, os_type_filter):
    """
    Helper function to print summary tables (Device/Slot and Grand Total).
    """
    filtered_results = [r for r in results if r.get("os_type") == os_type_filter]

    if not filtered_results:
        return

    print(f"\n{'=' * 10} Summary: Total Optics per Device and Slot ({os_type_filter}) {'=' * 10}")

    summary_table = PrettyTable()
    summary_table.field_names = ["Device", "Chassis", "Slot", "Module PID", "Total Optics Installed"]
    summary_table.align = "l"
    summary_table.align["Total Optics Installed"] = "r"
    summary_table.hrules = FRAME

    last_hostname = None
    grand_total_counts = {}

    for device_result in filtered_results:
        hostname = device_result["hostname"]
        chassis = device_result.get("chassis_type", "Unknown")

        if last_hostname is not None and last_hostname != hostname:
            summary_table.add_row([''] * len(summary_table.field_names))

        if device_result["status"] == "Success" and device_result["line_cards"]:
            for lc_data in device_result["line_cards"]:
                if lc_data["optics_counts"]:
                    for pid, count in lc_data["optics_counts"].items():
                        grand_total_counts[pid] = grand_total_counts.get(pid, 0) + count

                if not lc_data["lc_error"]:
                    summary_table.add_row(
                        [hostname, chassis, lc_data["slot"], lc_data["model"], lc_data["total_optics"]])
                else:
                    summary_table.add_row(
                        [hostname, chassis, lc_data["slot"], lc_data["model"], f"{COLOR_BOLD_RED}Error{COLOR_RESET}"])
        elif device_result["status"] != "Success":
            summary_table.add_row([hostname, chassis, f"{COLOR_BOLD_RED}N/A (Error){COLOR_RESET}", "N/A", "N/A"])
        elif os_type_filter == "IOS-XR":
            summary_table.add_row([hostname, chassis, "No Target 8800 LC", "N/A", 0])

        last_hostname = hostname

    if summary_table._rows:
        print(summary_table)
    else:
        print(f"{COLOR_BOLD_YELLOW}No relevant optics data found for {os_type_filter}.{COLOR_RESET}")

    print(f"\n{'=' * 10} Grand Total: Optics Across All {os_type_filter} Devices {'=' * 10}")
    if grand_total_counts:
        grand_total_table = PrettyTable()
        grand_total_table.field_names = ["Optics PID", "Total Count"]
        grand_total_table.align = "l"
        grand_total_table.align["Total Count"] = "r"

        for pid in sorted(grand_total_counts.keys()):
            grand_total_table.add_row([pid, grand_total_counts[pid]])
        print(grand_total_table)
    else:
        print(f"No optics found across any {os_type_filter} devices.")
    print(f"{'=' * 50}\n")


def print_failures(results):
    """
    Prints a table of devices that failed connection or authentication.
    """
    failed_devices = [r for r in results if r.get("os_type") == "Unknown" or r.get("status") != "Success"]

    if not failed_devices:
        return

    print(f"\n{'=' * 10} Connection / Audit Failures {'=' * 10}")
    fail_table = PrettyTable()
    fail_table.field_names = ["Device", "Status", "Error Details"]
    fail_table.align = "l"
    fail_table.max_width["Error Details"] = 60
    fail_table.hrules = FRAME

    for dev in failed_devices:
        fail_table.add_row([
            dev["hostname"],
            f"{COLOR_BOLD_RED}{dev['status']}{COLOR_RESET}",
            dev["error_message"]
        ])

    print(fail_table)
    print(f"{'=' * 50}\n")


def main():
    all_devices_config = get_device_info_list()

    if not all_devices_config:
        return

    print(f"\n{COLOR_BOLD_YELLOW}Starting concurrent processing for {len(all_devices_config)} devices...")
    print(f"Max Workers: {MAX_WORKERS} | Max Retries: {MAX_RETRIES}{COLOR_RESET}")
    start_time = time.time()

    results = []
    completed_count = 0
    total_devices = len(all_devices_config)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_device = {executor.submit(process_device_optics, dev_conf): dev_conf for dev_conf in
                            all_devices_config}

        for future in as_completed(future_to_device):
            device_config = future_to_device[future]
            completed_count += 1

            # Simple Progress Bar
            sys.stdout.write(f"\r[Progress] Processed {completed_count}/{total_devices} devices...")
            sys.stdout.flush()

            try:
                result = future.result()
                results.append(result)
            except Exception as exc:
                results.append({
                    "hostname": device_config["host"],
                    "status": "Thread Error",
                    "error_message": f"Exception: {exc}",
                    "line_cards": [],
                    "os_type": "Unknown",
                    "os_version": "Unknown",
                    "chassis_type": "Unknown"
                })

    end_time = time.time()
    print(
        f"\n\n{COLOR_BOLD_YELLOW}Finished processing all devices in {end_time - start_time:.2f} seconds.{COLOR_RESET}\n")

    # Sort: OS Type first, then Hostname
    results.sort(key=lambda x: (x['os_type'], x['hostname']))

    # 1. Print Summaries to Console
    print_summary_for_os(results, "IOS-XR")
    print_summary_for_os(results, "NX-OS")

    # 2. Print Failures
    print_failures(results)

    # 3. Export to CSV
    csv_filename = f"optics_audit_report_{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    try:
        export_to_csv(results, csv_filename)
        print(f"{COLOR_BOLD_GREEN}Full detailed report exported to: {csv_filename}{COLOR_RESET}")
    except Exception as e:
        print(f"{COLOR_BOLD_RED}Failed to export CSV: {e}{COLOR_RESET}")


if __name__ == "__main__":
    main()