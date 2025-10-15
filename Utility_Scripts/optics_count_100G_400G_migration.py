import getpass
import paramiko
import time
from prettytable import PrettyTable
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import datetime  # Import datetime for timestamps
import os  # Import os for path manipulation

# ANSI escape codes for text formatting
COLOR_BOLD_GREEN = "\033[1;92m"  # Bold and Green
COLOR_BOLD_RED = "\033[1;91m"  # Bold and Red for errors/warnings
COLOR_BOLD_YELLOW = "\033[1;93m"  # Bold and Yellow for warnings
COLOR_RESET = "\033[0m"  # Reset to default terminal color and style


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
            # Add an empty string to signify an empty line, for the double-enter check
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
    Parses the 'show platform' output to find 8800-LC-48H line cards and their slots.
    """
    lc_slots = []
    lines = output.splitlines()
    for line in lines:
        # Example line: 0/2/CPU0        8800-LC-48H              IOS XR RUN               NSHUT
        # Match lines that specifically contain "8800-LC-48H" and are in "IOS XR RUN" state
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


def process_device_optics(device_config):
    """
    Connects to a single device, finds 8800-LC-48H line cards,
    and counts optics on each. Also captures raw 'show inventory' output and saves it to a file.
    Returns a dictionary with device hostname and a list of line card details.
    """
    hostname = device_config["host"]
    username = device_config["username"]
    password = device_config["password"]

    device_results = {
        "hostname": hostname,
        "status": "Success",
        "error_message": None,
        "raw_show_inventory_file": None,  # Stores filename or error message for raw output
        "line_cards": []
    }

    client = None
    try:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # AutoAddPolicy for convenience, use with caution

        client.connect(hostname=hostname, username=username, password=password, timeout=10, look_for_keys=False,
                       allow_agent=False)

        # --- Capture raw 'show inventory' output and save to file ---
        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        # Sanitize hostname for filename (replace characters not allowed in filenames)
        safe_hostname = re.sub(r'[^\w.-]', '_', hostname)
        filename = f"raw_inventory_{safe_hostname}_{timestamp}.txt"

        # For IOS-XR, 'terminal length 0' and 'terminal width 511' are generally not needed
        # when using exec_command, as it typically returns the full output.
        # If output truncation is observed, consider using invoke_shell for interactive commands.

        stdin_inv, stdout_inv, stderr_inv = client.exec_command("show inventory")
        raw_inv_output = stdout_inv.read().decode('utf-8')
        raw_inv_error = stderr_inv.read().decode('utf-8')

        if raw_inv_error:
            device_results["raw_show_inventory_file"] = f"Error capturing raw 'show inventory': {raw_inv_error}"
        else:
            try:
                # Ensure the directory exists if you want to save it in a specific folder
                # e.g., os.makedirs('inventory_logs', exist_ok=True)
                # with open(os.path.join('inventory_logs', filename), 'w') as f:
                with open(filename, 'w') as f:
                    f.write(raw_inv_output)
                device_results["raw_show_inventory_file"] = filename
            except IOError as io_err:
                device_results[
                    "raw_show_inventory_file"] = f"Error saving raw 'show inventory' to file {filename}: {io_err}"

        # --- Get 8800-LC-48H line card count and their slots ---
        stdin_platform, stdout_platform, stderr_platform = client.exec_command("show platform")
        platform_output = stdout_platform.read().decode('utf-8')
        error_output = stderr_platform.read().decode('utf-8')

        if error_output:
            device_results["status"] = "Error"
            device_results["error_message"] = f"Error executing 'show platform': {error_output}"
            return device_results

        lc_slots = parse_show_platform(platform_output)

        if not lc_slots:
            device_results["status"] = "No 8800-LC-48H found"
            device_results["error_message"] = "No 8800-LC-48H line cards found in 'show platform' output."
            # We still want to return the raw_show_inventory_file status
            return device_results

        for slot in lc_slots:
            lc_data = {
                "slot": slot,
                "optics_counts": {},
                "total_optics": 0,
                "lc_error": None
            }
            command = f"show inventory location {slot}"
            stdin_lc, stdout_lc, stderr_lc = client.exec_command(command)
            inventory_output = stdout_lc.read().decode('utf-8')
            error_output = stderr_lc.read().decode('utf-8')

            if error_output:
                lc_data["lc_error"] = f"Error executing '{command}': {error_output}"
            else:
                optics_category_counts = parse_show_inventory_location(inventory_output)
                lc_data["optics_counts"] = optics_category_counts
                lc_data["total_optics"] = sum(optics_category_counts.values())

            device_results["line_cards"].append(lc_data)

    except paramiko.AuthenticationException:
        device_results["status"] = "Authentication Failed"
        device_results["error_message"] = "Authentication failed. Check username/password."
    except paramiko.SSHException as e:
        device_results["status"] = "SSH Error"
        device_results["error_message"] = f"SSH error: {e}"
    except paramiko.BadHostKeyException as e:
        device_results["status"] = "Bad Host Key"
        device_results["error_message"] = f"Bad host key: {e}. You might need to clear it from known_hosts."
    except Exception as e:
        device_results["status"] = "Unexpected Error"
        device_results["error_message"] = f"An unexpected error occurred: {e}"
    finally:
        if client:
            client.close()

    return device_results


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
                    "line_cards": []
                })

    end_time = time.time()
    print(
        f"\n{COLOR_BOLD_YELLOW}Finished processing all devices in {end_time - start_time:.2f} seconds.{COLOR_RESET}\n")

    # Sort results by hostname for consistent output
    results.sort(key=lambda x: x['hostname'])

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
                    f"{COLOR_BOLD_GREEN}Raw 'show inventory' output saved to: {device_result['raw_show_inventory_file']}{COLOR_RESET}")
        else:
            print(
                f"{COLOR_BOLD_YELLOW}Raw 'show inventory' output not captured (possibly due to connection error).{COLOR_RESET}")

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
        elif device_result["status"] == "Success":  # Only if no specific error, but no LCs found
            print("No 8800-LC-48H line cards found on this device.")

        print(f"{'=' * 30}\n")  # Separator for devices

    # --- Print Summary Table of Total Optics Installed per Device, per Slot ---
    print(f"\n{'=' * 10} Summary: Total Optics per Device and Slot {'=' * 10}")
    summary_table = PrettyTable()
    summary_table.field_names = ["Device", "Slot", "Total Optics Installed"]
    summary_table.align["Device"] = "l"
    summary_table.align["Slot"] = "l"
    summary_table.align["Total Optics Installed"] = "r"
    summary_table.hrules = PrettyTable.FRAME  # Only frame rules, no internal rules by default

    last_hostname = None
    for device_result in results:
        hostname = device_result["hostname"]

        # Add a separator row if the device changes (and it's not the very first device)
        if last_hostname is not None and last_hostname != hostname:
            summary_table.add_row([''] * len(summary_table.field_names))  # Add an empty row for spacing
            summary_table.add_hline()  # This adds a horizontal line across the table
            summary_table.add_row([''] * len(summary_table.field_names))  # Another empty row for spacing

        if device_result["status"] == "Success" and device_result["line_cards"]:
            for lc_data in device_result["line_cards"]:
                if not lc_data["lc_error"]:  # Only add to summary if no error getting LC optics
                    summary_table.add_row([hostname, lc_data["slot"], lc_data["total_optics"]])
                else:
                    summary_table.add_row([hostname, lc_data["slot"], f"{COLOR_BOLD_RED}Error{COLOR_RESET}"])
        elif device_result["status"] != "Success":
            summary_table.add_row(
                [hostname, f"{COLOR_BOLD_RED}N/A (Device Error){COLOR_RESET}", f"{COLOR_BOLD_RED}N/A{COLOR_RESET}"])
        else:  # Success status but no 8800-LC-48H found
            summary_table.add_row([hostname, "No 8800-LC-48H", 0])

        last_hostname = hostname  # Update last_hostname for the next iteration

    if summary_table._rows:  # Check if any rows were added
        print(summary_table)
    else:
        print(f"{COLOR_BOLD_YELLOW}No relevant optics data found for summary table.{COLOR_RESET}")
    print(f"{'=' * 50}\n")


if __name__ == "__main__":
    main()