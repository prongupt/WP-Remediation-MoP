import getpass
import paramiko
import time
from prettytable import PrettyTable, FRAME
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import datetime
import os
import csv
import threading  # Import threading for locks

# ANSI escape codes for text formatting
COLOR_BOLD_GREEN = "\033[1;92m"  # Bold and Green
COLOR_BOLD_RED = "\033[1;91m"  # Bold and Red for errors/warnings
COLOR_BOLD_YELLOW = "\033[1;93m"  # Bold and Yellow for warnings
COLOR_RESET = "\033[0m"  # Reset to default terminal color and style

# --- Configuration for large scale processing ---
MAX_WORKERS = 50  # Number of concurrent SSH connections. Adjust based on your system and network.
MAX_RETRIES = 3  # Number of times to retry a failed SSH connection
RETRY_DELAY_SECONDS = 5  # Delay between retries

# Global lock for writing to the consolidated raw inventory file
raw_inventory_file_lock = threading.Lock()


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
    Parses the 'show platform' output to find 8800-LC-48H line cards and their slots.
    """
    lc_slots = []
    lines = output.splitlines()
    for line in lines:
        match = re.match(r"^(0/\d+/CPU0)\s+8800-LC-48H\s+IOS XR RUN\s+.*", line)
        if match:
            slot = match.group(1)
            lc_slots.append(slot)
    return lc_slots


def parse_show_inventory_location(output):
    """
    Parses the 'show inventory location' output to count and categorize installed optics by PID.
    Returns a dictionary where keys are PID strings and values are their counts.
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


def process_device_optics(device_config, raw_inventory_file_handle, raw_inventory_lock):
    """
    Connects to a single device, finds 8800-LC-48H line cards,
    and counts optics on each. Directly writes raw 'show inventory' output to a shared file.
    Returns a dictionary with device hostname, status, error, and line card details.
    """
    hostname = device_config["host"]
    username = device_config["username"]
    password = device_config["password"]

    device_results = {
        "hostname": hostname,
        "status": "Success",
        "error_message": None,
        "raw_inventory_save_status": "Not Captured",  # Status of raw inventory saving
        "line_cards": []
    }

    client = None
    try:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # --- SSH Connection with Retries ---
        connected = False
        for attempt in range(MAX_RETRIES):
            try:
                print(f"[{hostname}] Attempt {attempt + 1}/{MAX_RETRIES} to connect...")
                client.connect(hostname=hostname, username=username, password=password, timeout=10, look_for_keys=False,
                               allow_agent=False)
                connected = True
                print(f"[{hostname}] Connected successfully.")
                break
            except paramiko.AuthenticationException:
                device_results["status"] = "Authentication Failed"
                device_results["error_message"] = "Authentication failed. Check username/password."
                print(f"[{hostname}] {COLOR_BOLD_RED}Authentication Failed.{COLOR_RESET}")
                return device_results  # No point retrying auth
            except paramiko.SSHException as e:
                device_results["error_message"] = f"SSH error: {e}"
                print(f"[{hostname}] {COLOR_BOLD_YELLOW}SSH Error: {e}{COLOR_RESET}")
            except Exception as e:
                device_results["error_message"] = f"Connection error: {e}"
                print(f"[{hostname}] {COLOR_BOLD_YELLOW}Connection Error: {e}{COLOR_RESET}")

            if attempt < MAX_RETRIES - 1:
                print(f"[{hostname}] Retrying in {RETRY_DELAY_SECONDS} seconds...")
                time.sleep(RETRY_DELAY_SECONDS)

        if not connected:
            device_results["status"] = "Connection Failed"
            device_results["error_message"] = device_results.get("error_message",
                                                                 "Failed to connect after multiple retries.")
            return device_results

        # --- Capture raw 'show inventory' output and write to consolidated file ---
        raw_inv_output = ""
        try:
            stdin_inv, stdout_inv, stderr_inv = client.exec_command("show inventory",
                                                                    timeout=30)  # Add timeout for command
            raw_inv_output = stdout_inv.read().decode('utf-8')
            raw_inv_error = stderr_inv.read().decode('utf-8')

            with raw_inventory_lock:  # Acquire lock before writing to shared file
                raw_inventory_file_handle.write(f"\n{'=' * 10} RAW INVENTORY FOR DEVICE: {hostname} {'=' * 10}\n\n")
                if raw_inv_error:
                    raw_inventory_file_handle.write(f"Error capturing raw 'show inventory': {raw_inv_error}\n")
                    device_results["raw_inventory_save_status"] = f"Error: {raw_inv_error}"
                else:
                    raw_inventory_file_handle.write(raw_inv_output)
                    device_results["raw_inventory_save_status"] = "Saved"
                raw_inventory_file_handle.write(f"\n{'=' * 50}\n\n")  # Separator
            print(f"[{hostname}] Raw inventory saved to consolidated file.")
        except Exception as e:
            with raw_inventory_lock:
                raw_inventory_file_handle.write(f"\n{'=' * 10} RAW INVENTORY FOR DEVICE: {hostname} {'=' * 10}\n\n")
                raw_inventory_file_handle.write(f"Error capturing raw 'show inventory' (Exception): {e}\n")
                raw_inventory_file_handle.write(f"\n{'=' * 50}\n\n")
            device_results["raw_inventory_save_status"] = f"Error capturing: {e}"
            print(f"[{hostname}] {COLOR_BOLD_RED}Error capturing raw inventory: {e}{COLOR_RESET}")

        # --- Get 8800-LC-48H line card count and their slots ---
        stdin_platform, stdout_platform, stderr_platform = client.exec_command("show platform",
                                                                               timeout=30)  # Add timeout
        platform_output = stdout_platform.read().decode('utf-8')
        error_output = stderr_platform.read().decode(
            'utf-8')  # CORRECTED: Changed stderr_stderr_platform to stderr_platform

        if error_output:
            device_results["status"] = "Error"
            device_results["error_message"] = f"Error executing 'show platform': {error_output}"
            print(f"[{hostname}] {COLOR_BOLD_RED}Error executing 'show platform': {error_output}{COLOR_RESET}")
            return device_results

        lc_slots = parse_show_platform(platform_output)

        if not lc_slots:
            device_results["status"] = "No 8800-LC-48H found"
            device_results["error_message"] = "No 8800-LC-48H line cards found in 'show platform' output."
            print(f"[{hostname}] No 8800-LC-48H line cards found.")
            return device_results

        for slot in lc_slots:
            lc_data = {
                "slot": slot,
                "optics_counts": {},
                "total_optics": 0,
                "lc_error": None
            }
            command = f"show inventory location {slot}"
            try:
                stdin_lc, stdout_lc, stderr_lc = client.exec_command(command, timeout=30)  # Add timeout
                inventory_output = stdout_lc.read().decode('utf-8')
                error_output = stderr_lc.read().decode('utf-8')

                if error_output:
                    lc_data["lc_error"] = f"Error executing '{command}': {error_output}"
                    print(f"[{hostname}] {COLOR_BOLD_RED}Error on {slot}: {error_output}{COLOR_RESET}")
                else:
                    optics_category_counts = parse_show_inventory_location(inventory_output)
                    lc_data["optics_counts"] = optics_category_counts
                    lc_data["total_optics"] = sum(optics_category_counts.values())
                    print(f"[{hostname}] Processed optics for {slot}.")
            except Exception as e:
                lc_data["lc_error"] = f"Exception executing '{command}': {e}"
                print(f"[{hostname}] {COLOR_BOLD_RED}Exception on {slot}: {e}{COLOR_RESET}")

            device_results["line_cards"].append(lc_data)

    except paramiko.BadHostKeyException as e:
        device_results["status"] = "Bad Host Key"
        device_results["error_message"] = f"Bad host key: {e}. You might need to clear it from known_hosts."
        print(f"[{hostname}] {COLOR_BOLD_RED}Bad Host Key: {e}{COLOR_RESET}")
    except Exception as e:
        device_results["status"] = "Unexpected Error"
        device_results["error_message"] = f"An unexpected error occurred: {e}"
        print(f"[{hostname}] {COLOR_BOLD_RED}Unexpected Error: {e}{COLOR_RESET}")
    finally:
        if client:
            client.close()
            print(f"[{hostname}] SSH client closed.")

    return device_results


def main():
    all_devices_config = get_device_info_list()

    if not all_devices_config:
        return

    print(
        f"\n{COLOR_BOLD_YELLOW}Starting concurrent processing for {len(all_devices_config)} devices with {MAX_WORKERS} workers...{COLOR_RESET}")
    start_time = time.time()

    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    all_raw_inventory_filename = f"all_raw_inventory_{timestamp}.txt"
    csv_summary_filename = f"optics_summary_{timestamp}.csv"
    csv_summary_with_region_filename = f"optics_summary_with_region_{timestamp}.csv"

    # --- Open consolidated raw inventory file and CSV files once ---
    raw_inv_file_obj = None
    summary_csv_file_obj = None
    region_csv_file_obj = None
    summary_csv_writer = None
    region_csv_writer = None

    try:
        raw_inv_file_obj = open(all_raw_inventory_filename, 'w', encoding='utf-8')
        print(
            f"{COLOR_BOLD_GREEN}Consolidated raw inventory will be saved to: {all_raw_inventory_filename}{COLOR_RESET}")

        summary_csv_file_obj = open(csv_summary_filename, 'w', newline='', encoding='utf-8')
        summary_csv_writer = csv.writer(summary_csv_file_obj)
        summary_csv_writer.writerow(["Device", "Slot", "Total Optics Installed"])
        print(f"{COLOR_BOLD_GREEN}Summary CSV will be saved to: {csv_summary_filename}{COLOR_RESET}")

        region_csv_file_obj = open(csv_summary_with_region_filename, 'w', newline='', encoding='utf-8')
        region_csv_writer = csv.writer(region_csv_file_obj)
        region_csv_writer.writerow(["Region", "Device", "Slot", "Total Optics Installed"])
        print(
            f"{COLOR_BOLD_GREEN}Region-grouped Summary CSV will be saved to: {csv_summary_with_region_filename}{COLOR_RESET}")

        # --- Process devices concurrently ---
        processed_results = []  # To store structured results for console output and final PrettyTable
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Map device configurations to the processing function
            # Pass the shared raw inventory file handle and lock
            future_to_device = {
                executor.submit(process_device_optics, dev_conf, raw_inv_file_obj, raw_inventory_file_lock): dev_conf
                for dev_conf in all_devices_config
            }

            for future in as_completed(future_to_device):
                device_config = future_to_device[future]
                try:
                    result = future.result()
                    processed_results.append(result)

                    # --- Write summary data directly to CSVs ---
                    hostname = result["hostname"]
                    if result["status"] == "Success" and result["line_cards"]:
                        for lc_data in result["line_cards"]:
                            if not lc_data["lc_error"]:
                                summary_csv_writer.writerow([hostname, lc_data["slot"], lc_data["total_optics"]])
                                # Extract region for the region-grouped CSV
                                match = re.match(r'^([A-Z]+)', hostname)
                                region_code = match.group(1) if match else "UNKNOWN"
                                region_csv_writer.writerow(
                                    [region_code, hostname, lc_data["slot"], lc_data["total_optics"]])
                            else:
                                summary_csv_writer.writerow([hostname, lc_data["slot"], "Error"])
                                match = re.match(r'^([A-Z]+)', hostname)
                                region_code = match.group(1) if match else "UNKNOWN"
                                region_csv_writer.writerow([region_code, hostname, lc_data["slot"], "Error"])
                    elif result["status"] != "Success":
                        summary_csv_writer.writerow([hostname, "N/A (Device Error)", "N/A"])
                        match = re.match(r'^([A-Z]+)', hostname)
                        region_code = match.group(1) if match else "UNKNOWN"
                        region_csv_writer.writerow([region_code, hostname, "N/A (Device Error)", "N/A"])
                    else:  # Success status but no 8800-LC-48H found
                        summary_csv_writer.writerow([hostname, "No 8800-LC-48H", 0])
                        match = re.match(r'^([A-Z]+)', hostname)
                        region_code = match.group(1) if match else "UNKNOWN"
                        region_csv_writer.writerow([region_code, hostname, "No 8800-LC-48H", 0])

                except Exception as exc:
                    # This catches exceptions from the future.result() call, not from inside process_device_optics
                    # Errors within process_device_optics are typically caught and returned in the result dict
                    error_hostname = device_config["host"]
                    processed_results.append({
                        "hostname": error_hostname,
                        "status": "Thread Error",
                        "error_message": f"Generated an exception: {exc}",
                        "raw_inventory_save_status": "Not Captured (Thread Error)",
                        "line_cards": []
                    })
                    print(f"[{error_hostname}] {COLOR_BOLD_RED}Thread Exception: {exc}{COLOR_RESET}")
                    # Also write to CSV for thread errors
                    summary_csv_writer.writerow([error_hostname, "N/A (Thread Error)", "N/A"])
                    match = re.match(r'^([A-Z]+)', error_hostname)
                    region_code = match.group(1) if match else "UNKNOWN"
                    region_csv_writer.writerow([region_code, error_hostname, "N/A (Thread Error)", "N/A"])

    except IOError as e:
        print(f"{COLOR_BOLD_RED}Error opening files for writing: {e}{COLOR_RESET}")
        return  # Exit if files cannot be opened
    finally:
        if raw_inv_file_obj:
            raw_inv_file_obj.close()
            print(f"{COLOR_BOLD_GREEN}Consolidated raw inventory file closed.{COLOR_RESET}")
        if summary_csv_file_obj:
            summary_csv_file_obj.close()
            print(f"{COLOR_BOLD_GREEN}Summary CSV file closed.{COLOR_RESET}")
        if region_csv_file_obj:
            region_csv_file_obj.close()
            print(f"{COLOR_BOLD_GREEN}Region-grouped Summary CSV file closed.{COLOR_RESET}")

    end_time = time.time()
    print(
        f"\n{COLOR_BOLD_YELLOW}Finished processing all devices in {end_time - start_time:.2f} seconds.{COLOR_RESET}\n")

    # Sort results for consistent console output
    processed_results.sort(key=lambda x: x['hostname'])

    # --- Print detailed results for each device (console output) ---
    for device_result in processed_results:
        hostname = device_result["hostname"]
        print(f"\n{'=' * 10} Device: {hostname} {'=' * 10}")
        print(f"Status: {device_result['status']}")

        if device_result["error_message"]:
            print(f"{COLOR_BOLD_RED}Error: {device_result['error_message']}{COLOR_RESET}")

        # Report on raw show inventory output being saved to the single file
        if device_result["raw_inventory_save_status"] == "Saved":
            print(
                f"{COLOR_BOLD_GREEN}Raw 'show inventory' output for this device contributed to '{all_raw_inventory_filename}'{COLOR_RESET}")
        else:
            print(
                f"{COLOR_BOLD_RED}Raw 'show inventory' output for this device: {device_result['raw_inventory_save_status']}{COLOR_RESET}")

        print("\n-----------------------------------\n")

        if device_result["line_cards"]:
            print("8800-LC-48H Line Card Optics Details:")
            for lc_data in device_result["line_cards"]:
                print(f"\n  --- Line card {lc_data['slot']} ---")
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
                    print("    No optics found on this line card.")
        elif device_result["status"] == "Success":
            print("No 8800-LC-48H line cards found on this device.")

        print(f"{'=' * 30}\n")

    # --- Print Summary Table to Console (Still using PrettyTable for display) ---
    print(f"\n{'=' * 10} Summary: Total Optics per Device and Slot {'=' * 10}")
    summary_table = PrettyTable()
    summary_table.field_names = ["Device", "Slot", "Total Optics Installed"]
    summary_table.align["Device"] = "l"
    summary_table.align["Slot"] = "l"
    summary_table.align["Total Optics Installed"] = "r"
    summary_table.hrules = FRAME

    last_hostname = None
    for device_result in processed_results:
        hostname = device_result["hostname"]

        if last_hostname is not None and last_hostname != hostname:
            summary_table.add_row([''] * len(summary_table.field_names))
            summary_table.add_row([''] * len(summary_table.field_names))

        if device_result["status"] == "Success" and device_result["line_cards"]:
            for lc_data in device_result["line_cards"]:
                if not lc_data["lc_error"]:
                    summary_table.add_row([hostname, lc_data["slot"], lc_data["total_optics"]])
                else:
                    error_msg_console = f"{COLOR_BOLD_RED}Error{COLOR_RESET}"
                    summary_table.add_row([hostname, lc_data["slot"], error_msg_console])
        elif device_result["status"] != "Success":
            error_msg_console_device = f"{COLOR_BOLD_RED}N/A (Device Error){COLOR_RESET}"
            summary_table.add_row(
                [hostname, error_msg_console_device, error_msg_console_device])
        else:  # Success status but no 8800-LC-48H found
            summary_table.add_row([hostname, "No 8800-LC-48H", 0])

        last_hostname = hostname

    if summary_table._rows:
        print(summary_table)
    else:
        print(f"{COLOR_BOLD_YELLOW}No relevant optics data found for summary table.{COLOR_RESET}")
    print(f"{'=' * 50}\n")


if __name__ == "__main__":
    main()