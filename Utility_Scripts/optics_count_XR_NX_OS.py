# This script is a comprehensive audit tool for Cisco IOS-XR and NX-OS devices.
# It automates the process of connecting to multiple devices, identifying the operating system,
# detecting chassis types, and auditing specific hardware modules and their installed optics.
#
# Key Capabilities:
#
# 1.  **Multi-Platform Support:**
#     - **IOS-XR:** Automatically detects IOS-XR devices. Specifically targets 8800 series line cards
#       (8800-LC-48H, 88-LC0-36FH, 88-LC0-36FH-M) to count installed optics.
#     - **NX-OS:** Automatically detects Nexus devices. Audits all installed modules and transceivers
#       using 'show module' and 'show interface transceiver'.
#
# 2.  **Intelligent Device Interrogation:**
#     - **OS Detection:** Dynamically determines if a device is IOS-XR or NX-OS based on command output,
#       handling command echoes and prompt variations robustly.
#     - **Chassis Detection:** Parses 'show version' output to identify and report the specific chassis model
#       (e.g., Cisco 8818, Nexus 9508) for both platforms.
#     - **Version Capture:** Reports the running software version for all devices.
#
# 3.  **Robust Connectivity (Interactive Shell):**
#     - Uses Paramiko's `invoke_shell()` to simulate a real interactive user session.
#     - This bypasses common authorization issues found with non-interactive `exec_command` on
#       TACACS+ secured devices.
#
# 4.  **Reporting & Data Capture:**
#     - **Raw Data Backup:** Automatically saves the raw output of inventory commands to timestamped text files.
#     - **Detailed Console Output:** Prints real-time status, OS detection logs, and per-slot optics counts.
#     - **Segregated Summaries:** Generates separate, clean summary tables for IOS-XR and NX-OS devices.
#     - **Grand Totals:** Provides a final aggregate count of every specific Optic PID found across the entire fleet.
#
# 5.  **Performance:**
#     - Multi-threaded execution allows simultaneous processing of multiple devices, significantly reducing
#       wait times for large batches.
#
# Usage:
# Run the script, enter your SSH username and password when prompted, then paste your list of
# device hostnames or IP addresses (one per line), pressing Enter twice when finished.
#
# Requirements:
# - Python 3.x
# - paramiko library (`pip install paramiko`)
# - prettytable library (`pip install prettytable`)


__author__ = "Pronoy Dasgupta"
__copyright__ = "Copyright 2024 (C) Cisco Systems, Inc."
__credits__ = "Pronoy Dasgupta"
__version__ = "2.1.0"
__maintainer__ = "Pronoy Dasgupta"
__email__ = "prongupt@cisco.com"
__status__ = "production"

import getpass
import paramiko
import time
from prettytable import PrettyTable, FRAME  # FRAME is imported, but add_hline removed
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import datetime
import os

# ANSI escape codes for text formatting
COLOR_BOLD_GREEN = "\033[1;92m"  # Bold and Green
COLOR_BOLD_RED = "\033[1;91m"  # Bold and Red for errors/warnings
COLOR_BOLD_YELLOW = "\033[1;93m"  # Bold and Yellow for warnings
COLOR_RESET = "\033[0m"  # Reset to default terminal color and style


def get_timestamp_log():
    """Returns a formatted timestamp string for logging."""
    return datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")


def get_device_info_list():
    """
    Prompts the user for a list of router hostnames/IPs (allowing paste),
    then a single username and password.
    Returns a list of dictionaries, each containing connection details for a device.
    """
    hostnames = []

    print("\nPaste your list of hostnames or IP addresses below, one per line.")
    print("Press Enter twice when you are finished (i.e., an empty line):")

    while True:
        line = input()
        if not line:  # User pressed Enter
            # If the previous line was also empty, break the loop
            if not hostnames or hostnames[-1] == "":  # Check if list is empty or last element was empty string
                break
            # Add an empty string to signify an empty line, for the double-enter logic
            hostnames.append("")
        else:
            hostnames.append(line.strip())

    # Filter out any empty strings that were added just for the double-enter logic
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
    Parses the 'show platform' output to find specific 8800 line cards and their slots.
    Returns a list of dictionaries: [{'slot': '0/0/CPU0', 'model': '8800-LC-48H'}, ...]
    Target Models: 8800-LC-48H, 88-LC0-36FH, 88-LC0-36FH-M
    """
    lc_info_list = []
    lines = output.splitlines()

    # Regex Explanation:
    # 1. (0/\d+/CPU0)  -> Capture Group 1: The Slot ID
    # 2. \s+           -> Match one or more spaces
    # 3. .*?           -> Non-greedy match of any characters (handles variable spacing/columns)
    # 4. ( ... )       -> Capture Group 2: The Model Name
    # 5. .*?           -> Non-greedy match of any characters
    # 6. IOS XR RUN    -> Literal string match for the state
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
    Parses the 'show inventory location' output to count and categorize installed optics by PID.
    Returns a dictionary where keys are PID strings and values are their counts.
    """
    optics_category_counts = {}
    lines = output.splitlines()

    for i, line in enumerate(lines):
        # Check if the current line describes an optic module
        if "DESCR:" in line and "Pluggable Optics Module" in line:
            # This line identifies an optic. Now, look for its PID in subsequent lines.
            for j in range(i + 1, len(lines)):
                next_line = lines[j]
                if "PID:" in next_line:
                    # Found the PID line for this optic
                    pid_start_index = next_line.find("PID:")
                    if pid_start_index != -1:
                        pid_substring = next_line[pid_start_index + len("PID:"):].strip()
                        pid_end_index = pid_substring.find(",")
                        if pid_end_index != -1:
                            pid = pid_substring[:pid_end_index].strip()
                        else:
                            pid = pid_substring.strip()  # If no comma, PID is till end of line

                        optics_category_counts[pid] = optics_category_counts.get(pid, 0) + 1
                    break  # Found the PID for this optic, stop looking and move to the next DESCR line

                # If we encounter another "NAME:" or "DESCR:" before a PID,
                # it means the PID wasn't immediately next or the structure is different.
                # For Cisco inventory, PID is usually right after DESCR.
                if "NAME:" in next_line or "DESCR:" in next_line:
                    break

    return optics_category_counts


def parse_nxos_show_module(output):
    """
    Parses 'show module' output for NX-OS to map Slots to Models.
    Returns a dict: {'1': 'N9K-C9336C-FX2', '27': 'N9K-C9336C-FX2'}
    """
    slot_models = {}
    lines = output.splitlines()

    # Regex to capture:
    # Group 1: Mod number (digits)
    # Group 2: Model PID (alphanumeric+hyphens), usually appearing before the Status column
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
    Parses 'show interface transceiver' output for NX-OS.
    Returns a nested dict grouped by slot:
    {
        '1': {'QSFP-100G': 4, 'SFP-10G': 2},
        '2': {'...': 1}
    }
    """
    slot_optics = {}
    lines = output.splitlines()

    transceiver_present = False
    current_slot = None

    for line in lines:
        line = line.strip()

        # 1. Check for Interface line (resets the state)
        # Example: Ethernet1/35 -> Slot 1
        if line.startswith("Ethernet"):
            transceiver_present = False
            match = re.match(r"Ethernet(\d+)/", line)
            if match:
                current_slot = match.group(1)
            else:
                current_slot = None
            continue

        # 2. Check for presence
        if "transceiver is present" in line:
            transceiver_present = True
            continue

        # 3. If present, look for type
        if transceiver_present and line.startswith("type is") and current_slot:
            # Format: type is SFP-H10GB-AOC2M
            parts = line.split("type is")
            if len(parts) > 1:
                pid = parts[1].strip()

                # Initialize slot dict if not exists
                if current_slot not in slot_optics:
                    slot_optics[current_slot] = {}

                # Increment count
                slot_optics[current_slot][pid] = slot_optics[current_slot].get(pid, 0) + 1

            # Reset state
            transceiver_present = False

    return slot_optics


def send_command_interactive(shell, command, wait_time=2, max_loops=15):
    """
    Sends a command to an interactive shell and waits for the output.
    """
    shell.send(command + '\n')
    output = ""

    # Wait for data to be available
    for _ in range(max_loops):
        if shell.recv_ready():
            chunk = shell.recv(65535).decode('utf-8', errors='ignore')
            output += chunk
            if output.strip().endswith('#'):
                break
        time.sleep(wait_time)

    return output


def process_device_optics(device_config):
    """
    Connects to a single device using an interactive shell, finds target line cards,
    and counts optics on each.
    """
    hostname = device_config["host"]
    username = device_config["username"]
    password = device_config["password"]

    device_results = {
        "hostname": hostname,
        "status": "Success",
        "error_message": None,
        "raw_show_inventory_file": None,
        "line_cards": [],
        "os_type": "Unknown",
        "os_version": "Unknown",
        "chassis_type": "Unknown"  # New field for Chassis Type
    }

    client = None
    shell = None
    try:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        client.connect(hostname=hostname, username=username, password=password, timeout=10, look_for_keys=False,
                       allow_agent=False)

        # Invoke an interactive shell
        shell = client.invoke_shell()

        # Wait for initial prompt
        time.sleep(1)
        if shell.recv_ready():
            shell.recv(65535)  # Clear initial banner/prompt

        # Disable pagination
        shell.send("terminal length 0\n")
        time.sleep(1)
        if shell.recv_ready():
            shell.recv(65535)  # Clear output

        # ---------------------------------------------------------------------
        # OS Detection Logic
        # ---------------------------------------------------------------------
        print(f"{get_timestamp_log()} Checking OS type for {hostname}...")

        # Step A: Check for IOS-XR
        xr_check_output = send_command_interactive(shell, 'show version | i "Cisco IOS XR Software"')

        # FIX: Check for "Version" as well to avoid matching the command echo on NX-OS
        if "Cisco IOS XR Software" in xr_check_output and "Version" in xr_check_output:
            # Step B: It is IOS-XR
            device_results["os_type"] = "IOS-XR"

            # Step C: Get IOS-XR Version and Chassis
            # Run full show version to get chassis info
            full_ver_output = send_command_interactive(shell, 'show version', wait_time=2)

            # 1. Parse Version
            xr_version_found = False
            for line in full_ver_output.splitlines():
                if "Label" in line and ":" in line:
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        device_results["os_version"] = parts[1].strip()
                        xr_version_found = True
                        break

            if not xr_version_found:
                # Fallback
                for line in xr_check_output.splitlines():
                    if "Version" in line:
                        parts = line.split("Version", 1)
                        if len(parts) > 1:
                            raw_ver = parts[1].strip()
                            device_results["os_version"] = raw_ver.split(" ")[0]
                            xr_version_found = True
                            break

            if not xr_version_found:
                device_results["os_version"] = "Parse Error"

            # 2. Parse Chassis (IOS-XR)
            # Look for line: "Cisco 8818 18-slot Chassis"
            # Regex: Cisco (88\d\d) .* Chassis
            for line in full_ver_output.splitlines():
                if "Chassis" in line and "Cisco" in line:
                    # Try to capture "Cisco 8818" or similar
                    match = re.search(r"(Cisco\s+88\d+)", line)
                    if match:
                        device_results["chassis_type"] = match.group(1)
                        break
                    # Fallback: just grab the whole line if it looks right
                    if line.strip().startswith("Cisco") and "Chassis" in line:
                        device_results["chassis_type"] = line.strip()
                        break

        else:
            # Step D: Check for NX-OS
            # Improved Check: Just run 'show version' and look for "NX-OS" anywhere
            nx_check_output = send_command_interactive(shell, 'show version', wait_time=2)

            if "NX-OS" in nx_check_output or "Nexus" in nx_check_output:
                device_results["os_type"] = "NX-OS"

                # 1. Parse Version
                for line in nx_check_output.splitlines():
                    if "version" in line and ("system" in line or "NX-OS" in line or "NXOS" in line):
                        parts = line.split("version")
                        if len(parts) > 1:
                            device_results["os_version"] = parts[1].strip()
                            break

                if device_results["os_version"] == "Unknown":
                    device_results["os_version"] = "Detected (Parse Error)"

                # 2. Parse Chassis (NX-OS)
                # Look for Hardware section
                # Example: cisco Nexus9000 C93180YC-EX chassis
                # Regex looks for "cisco Nexus<digits> <ModelString>"
                lines = nx_check_output.splitlines()
                for i, line in enumerate(lines):
                    if line.strip() == "Hardware":
                        # Look at the next few lines
                        for j in range(1, 5):  # Check next 4 lines
                            if i + j < len(lines):
                                hw_line = lines[i + j].strip()
                                if "cisco" in hw_line.lower() and "Nexus" in hw_line:
                                    # Updated Regex to be more flexible with what follows the model number
                                    # Captures: cisco Nexus9000 C93180YC-EX
                                    match = re.search(r"(cisco\s+Nexus\d+\s+[A-Z0-9-]+)", hw_line, re.IGNORECASE)
                                    if match:
                                        device_results["chassis_type"] = match.group(1)
                                    else:
                                        device_results["chassis_type"] = hw_line  # Fallback
                                    break
            else:
                device_results["os_type"] = "Unknown"

        # ---------------------------------------------------------------------
        # End OS Detection Logic
        # ---------------------------------------------------------------------

        # --- Capture raw 'show inventory' output and save to file ---
        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        safe_hostname = re.sub(r'[^\w.-]', '_', hostname)
        filename = f"raw_inventory_{safe_hostname}_{timestamp}.txt"

        # ---------------------------------------------------------------------
        # IOS-XR Processing
        # ---------------------------------------------------------------------
        if device_results["os_type"] == "IOS-XR":
            raw_inv_output = send_command_interactive(shell, "show inventory", wait_time=3)

            try:
                with open(filename, 'w') as f:
                    f.write(raw_inv_output)
                device_results["raw_show_inventory_file"] = filename
            except IOError as io_err:
                device_results["raw_show_inventory_file"] = f"Error saving file: {io_err}"

            # --- Get target line card count and their slots ---
            platform_output = send_command_interactive(shell, "show platform", wait_time=2)

            # Check for Authorization Failure specifically
            if "authorization failed" in platform_output.lower():
                device_results["status"] = "Authorization Failed"
                device_results["error_message"] = "User does not have permission to run 'show platform'."
                return device_results

            lc_info_list = parse_show_platform(platform_output)

            if not lc_info_list:
                device_results["status"] = "No target 8800 LC found"
                device_results[
                    "error_message"] = "No target 8800 line cards (48H/36FH) found in 'show platform' output."
                return device_results

            for lc_info in lc_info_list:
                slot = lc_info['slot']
                model = lc_info['model']

                lc_data = {
                    "slot": slot,
                    "model": model,
                    "optics_counts": {},
                    "total_optics": 0,
                    "lc_error": None
                }
                command = f"show inventory location {slot}"
                inventory_output = send_command_interactive(shell, command, wait_time=2)

                if "Invalid input" in inventory_output or "Error" in inventory_output:
                    lc_data["lc_error"] = f"Error executing '{command}'"
                else:
                    optics_category_counts = parse_show_inventory_location(inventory_output)
                    lc_data["optics_counts"] = optics_category_counts
                    lc_data["total_optics"] = sum(optics_category_counts.values())

                device_results["line_cards"].append(lc_data)

        # ---------------------------------------------------------------------
        # NX-OS Processing
        # ---------------------------------------------------------------------
        elif device_results["os_type"] == "NX-OS":
            # 1. Get Module Info (Slot -> Model PID mapping)
            module_output = send_command_interactive(shell, "show module", wait_time=2)
            slot_model_map = parse_nxos_show_module(module_output)

            # 2. Get Transceiver Info
            transceiver_output = send_command_interactive(shell, "show interface transceiver", wait_time=3)

            # Save raw transceiver output
            try:
                with open(filename, 'w') as f:
                    f.write(transceiver_output)
                device_results["raw_show_inventory_file"] = filename
            except IOError as io_err:
                device_results["raw_show_inventory_file"] = f"Error saving file: {io_err}"

            # 3. Parse Transceiver Info (grouped by slot)
            # Returns: {'1': {'PID': count}, '2': {'PID': count}}
            slot_optics_data = parse_nxos_transceiver_output(transceiver_output)

            # 4. Construct Line Card Data
            # Iterate through slots found in transceiver output
            for slot, optics_counts in slot_optics_data.items():
                # Lookup Model PID from show module map, default if not found
                model_pid = slot_model_map.get(slot, "Unknown Module")

                lc_data = {
                    "slot": f"Slot {slot}",
                    "model": model_pid,
                    "optics_counts": optics_counts,
                    "total_optics": sum(optics_counts.values()),
                    "lc_error": None
                }
                device_results["line_cards"].append(lc_data)

            # Handle case where no optics found at all
            if not slot_optics_data:
                # Create a dummy entry so the device still shows up in summary as having 0 optics
                # Try to grab at least one valid slot from show module if available
                first_slot = next(iter(slot_model_map), "Chassis")
                first_model = slot_model_map.get(first_slot, "NX-OS")
                lc_data = {
                    "slot": f"Slot {first_slot}",
                    "model": first_model,
                    "optics_counts": {},
                    "total_optics": 0,
                    "lc_error": None
                }
                device_results["line_cards"].append(lc_data)

        # ---------------------------------------------------------------------
        # Unknown OS
        # ---------------------------------------------------------------------
        else:
            device_results["status"] = "Unknown OS"
            device_results["error_message"] = "Could not identify device as IOS-XR or NX-OS."

    except paramiko.AuthenticationException:
        device_results["status"] = "Authentication Failed"
        device_results["error_message"] = "Authentication failed. Check username/password."
    except paramiko.SSHException as e:
        device_results["status"] = "SSH Error"
        device_results["error_message"] = f"SSH error: {e}"
    except Exception as e:
        device_results["status"] = "Unexpected Error"
        device_results["error_message"] = f"An unexpected error occurred: {e}"
    finally:
        if client:
            client.close()

    return device_results


def print_summary_for_os(results, os_type_filter):
    """
    Helper function to print summary tables (Device/Slot and Grand Total)
    filtered by OS Type.
    """
    filtered_results = [r for r in results if r.get("os_type") == os_type_filter]

    if not filtered_results:
        return  # Nothing to print for this OS

    print(f"\n{'=' * 10} Summary: Total Optics per Device and Slot ({os_type_filter}) {'=' * 10}")

    summary_table = PrettyTable()
    summary_table.field_names = ["Device", "Chassis", "Slot", "Module PID", "Total Optics Installed"]
    summary_table.align["Device"] = "l"
    summary_table.align["Chassis"] = "l"
    summary_table.align["Slot"] = "l"
    summary_table.align["Module PID"] = "l"
    summary_table.align["Total Optics Installed"] = "r"
    summary_table.hrules = FRAME

    last_hostname = None
    grand_total_counts = {}

    for device_result in filtered_results:
        hostname = device_result["hostname"]
        chassis = device_result.get("chassis_type", "Unknown")

        # Add empty rows for spacing if the device changes
        if last_hostname is not None and last_hostname != hostname:
            summary_table.add_row([''] * len(summary_table.field_names))
            summary_table.add_row([''] * len(summary_table.field_names))

        if device_result["status"] == "Success" and device_result["line_cards"]:
            for lc_data in device_result["line_cards"]:
                # Aggregate counts for Grand Total
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
            summary_table.add_row(
                [hostname, chassis, f"{COLOR_BOLD_RED}N/A (Device Error){COLOR_RESET}", "N/A",
                 f"{COLOR_BOLD_RED}N/A{COLOR_RESET}"])
        elif os_type_filter == "IOS-XR":  # Only print "No Target LC" for IOS-XR
            summary_table.add_row([hostname, chassis, "No Target 8800 LC", "N/A", 0])

        last_hostname = hostname

    if summary_table._rows:
        print(summary_table)
    else:
        print(f"{COLOR_BOLD_YELLOW}No relevant optics data found for {os_type_filter} summary table.{COLOR_RESET}")

    # --- Print Grand Total Table for this OS ---
    print(f"\n{'=' * 10} Grand Total: Optics Across All {os_type_filter} Devices {'=' * 10}")
    if grand_total_counts:
        grand_total_table = PrettyTable()
        grand_total_table.field_names = ["Optics PID", "Total Count"]
        grand_total_table.align["Optics PID"] = "l"
        grand_total_table.align["Total Count"] = "r"

        for pid in sorted(grand_total_counts.keys()):
            grand_total_table.add_row([pid, grand_total_counts[pid]])
        print(grand_total_table)
    else:
        print(f"No optics found across any {os_type_filter} devices.")
    print(f"{'=' * 50}\n")


def main():
    all_devices_config = get_device_info_list()

    if not all_devices_config:
        return  # Exit if no devices were entered

    print(f"\n{COLOR_BOLD_YELLOW}Starting concurrent processing for {len(all_devices_config)} devices...{COLOR_RESET}")
    start_time = time.time()

    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:  # Adjust max_workers as needed
        future_to_device = {executor.submit(process_device_optics, dev_conf): dev_conf for dev_conf in
                            all_devices_config}
        for future in as_completed(future_to_device):
            device_config = future_to_device[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as exc:
                results.append({
                    "hostname": device_config["host"],
                    "status": "Thread Error",
                    "error_message": f"Generated an exception: {exc}",
                    "raw_show_inventory_file": None,  # Indicate file not saved due to thread error
                    "line_cards": [],
                    "os_type": "Error",
                    "os_version": "Error"
                })

    end_time = time.time()
    print(
        f"\n{COLOR_BOLD_YELLOW}Finished processing all devices in {end_time - start_time:.2f} seconds.{COLOR_RESET}\n")

    # Sort results by hostname for consistent output
    results.sort(key=lambda x: (x['os_type'], x['hostname']))

    # --- Print OS Version Tables ---

    # Filter results by OS type
    ios_xr_devices = [r for r in results if r.get("os_type") == "IOS-XR"]
    nx_os_devices = [r for r in results if r.get("os_type") == "NX-OS"]

    if ios_xr_devices:
        print(f"\n{COLOR_BOLD_GREEN}--- IOS-XR Devices ---{COLOR_RESET}")
        xr_table = PrettyTable()
        xr_table.field_names = ["Hostname", "Version"]
        xr_table.align = "l"
        for dev in ios_xr_devices:
            xr_table.add_row([dev["hostname"], dev["os_version"]])
        print(xr_table)

    if nx_os_devices:
        print(f"\n{COLOR_BOLD_GREEN}--- NX-OS Devices ---{COLOR_RESET}")
        nx_table = PrettyTable()
        nx_table.field_names = ["Hostname", "Version"]
        nx_table.align = "l"
        for dev in nx_os_devices:
            nx_table.add_row([dev["hostname"], dev["os_version"]])
        print(nx_table)

    print("\n")  # Spacing before detailed results

    # --- Print detailed results for each device ---
    for device_result in results:
        hostname = device_result["hostname"]
        print(f"\n{'=' * 10} Device: {hostname} {'=' * 10}")
        print(f"Status: {device_result['status']}")

        if device_result["error_message"]:
            print(f"{COLOR_BOLD_RED}Error: {device_result['error_message']}{COLOR_RESET}")

        # Report on raw show inventory output file
        if device_result["raw_show_inventory_file"]:
            if "Error" in device_result["raw_show_inventory_file"]:
                print(
                    f"{COLOR_BOLD_RED}Raw 'show inventory' output: {device_result['raw_show_inventory_file']}{COLOR_RESET}")
            else:
                print(
                    f"{COLOR_BOLD_GREEN}Raw 'show inventory' output saved to:  {device_result['raw_show_inventory_file']}{COLOR_RESET}")
        else:
            print(
                f"{COLOR_BOLD_YELLOW}Raw 'show inventory' output not captured (possibly due to connection error).{COLOR_RESET}")

        print("\n-----------------------------------\n")

        if device_result["line_cards"]:
            print("Optics Details:")
            for lc_data in device_result["line_cards"]:
                print(f"\n  --- Slot/Module: {lc_data['slot']} ({lc_data['model']}) ---")
                if lc_data["lc_error"]:
                    print(f"    {COLOR_BOLD_RED}Error: {lc_data['lc_error']}{COLOR_RESET}")
                elif lc_data["optics_counts"]:
                    print(f"    {COLOR_BOLD_GREEN}Total optics installed: {lc_data['total_optics']}{COLOR_RESET}")
                    table = PrettyTable()
                    table.field_names = ["Optic PID", "Count"]
                    table.align["Optic PID"] = "l"
                    table.align["Count"] = "r"

                    for pid, count in lc_data["optics_counts"].items():
                        table.add_row([pid, count])
                    print(table)
                else:
                    print("    No optics found on this line card/device.")
        elif device_result["status"] == "Success":  # Only if no specific error, but no LCs found
            print("No target 8800 line cards found on this device.")

        print(f"{'=' * 30}\n")  # Separator for devices

    # --- Print Summary and Grand Total Tables Separated by OS ---
    print_summary_for_os(results, "IOS-XR")
    print_summary_for_os(results, "NX-OS")


if __name__ == "__main__":
    main()