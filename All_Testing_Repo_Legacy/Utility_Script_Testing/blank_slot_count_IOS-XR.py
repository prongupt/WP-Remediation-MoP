# This script is a chassis slot availability audit tool for Cisco IOS-XR 8800 series devices,
# optimized for large-scale execution (e.g., 7000+ devices).
#
# Key Capabilities:
#
# 1.  **IOS-XR Only Support:**
#     - Specifically targets 8812, 8818, 8808, and 8804 chassis types
#     - Calculates available/blank slots based on chassis specifications
#
# 2.  **Scale & Performance:**
#     - **High Concurrency:** Optimized for 7000+ devices with configurable thread pool
#     - **Retry Logic:** Includes robust retry mechanism for SSH connections
#     - **Efficient Processing:** Streamlined for slot availability calculation only
#
# 3.  **Chassis Slot Analysis:**
#     - **8812:** 12 slots (0-11) - calculates available slots
#     - **8818:** 18 slots (0-17) - calculates available slots
#     - **8808:** 8 slots (0-7) - calculates available slots
#     - **8804:** 4 slots (0-3) - calculates available slots
#
# 4.  **Reporting:**
#     - **Slot Availability Summary:** Shows blank slots per chassis type
#     - **Connection Failures:** Detailed failure reporting for unreachable devices
#     - **Compact Slot Display:** Contiguous slots shown with hyphens (e.g., 10-15)
#     - **User-Friendly Errors:** Clean, actionable error messages
#     - **Summary Files:** Separate CSV files for summary and detailed data
#
# Usage:
# Run the script, enter your SSH credentials, then provide the list of hostnames/IPs
#
# Requirements:
# - Python 3.x
# - paramiko (`pip install paramiko`)
# - prettytable (`pip install prettytable`)

__author__ = "Pronoy Dasgupta"
__copyright__ = "Copyright 2026 (C) Cisco Systems, Inc."
__credits__ = "Pronoy Dasgupta"
__version__ = "3.2.0"
__maintainer__ = "Pronoy Dasgupta"
__email__ = "prongupt@cisco.com"
__status__ = "production"

import getpass
import paramiko
import time
from prettytable import PrettyTable
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import datetime
import sys
import logging
import csv

# --- Configuration Constants ---
MAX_WORKERS = 100  # Increased for 7000+ devices - adjust based on your network capacity
MAX_RETRIES = 3
RETRY_DELAY = 2  # Reduced delay for faster processing
SSH_TIMEOUT = 15  # Reduced timeout for faster failure detection

# Chassis slot definitions
CHASSIS_SLOTS = {
    '8812': list(range(0, 12)),  # Slots 0-11
    '8818': list(range(0, 18)),  # Slots 0-17
    '8808': list(range(0, 8)),  # Slots 0-7
    '8804': list(range(0, 4))  # Slots 0-3
}

# ANSI escape codes for text formatting
COLOR_BOLD_GREEN = "\033[1;92m"
COLOR_BOLD_RED = "\033[1;91m"
COLOR_BOLD_YELLOW = "\033[1;93m"
COLOR_RESET = "\033[0m"

# Setup logging for better debugging at scale
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'slot_audit_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def sanitize_error_message(error_message):
    """
    Sanitizes error messages to make them more user-friendly and concise.
    Specifically handles SSH host key mismatch errors.
    """
    if not error_message:
        return "No error details available"

    # Handle host key mismatch errors
    if "Host key for server" in error_message and "does not match" in error_message:
        # Extract the server IP/hostname from the error message
        match = re.search(r"Host key for server '([^']+)'", error_message)
        if match:
            server = match.group(1)
            return f"SSH host key verification failed for {server}. The server's host key has changed or is not recognized. Clear the host key from known_hosts file and retry."
        else:
            return "SSH host key verification failed. The server's host key has changed or is not recognized."

    # Handle other common SSH errors
    if "timed out" in error_message.lower():
        return "Connection timed out"

    if "connection refused" in error_message.lower():
        return "Connection refused by server"

    if "authentication failed" in error_message.lower() or "auth" in error_message.lower():
        return "Authentication failed - check username/password"

    if "no route to host" in error_message.lower():
        return "No route to host - check network connectivity"

    if "name resolution" in error_message.lower() or "not known" in error_message.lower():
        return "Hostname resolution failed"

    # For other errors, truncate if too long but keep meaningful content
    if len(error_message) > 100:
        return error_message[:97] + "..."

    return error_message


def format_slot_ranges(slot_list):
    """
    Converts a list of slot numbers to a compact string representation.
    Contiguous slots are represented with hyphens.

    Examples:
    [10, 11, 12, 13, 14, 15] -> "10-15"
    [1, 2, 5, 6, 7, 10] -> "1-2, 5-7, 10"
    [1, 3, 5] -> "1, 3, 5"
    """
    if not slot_list:
        return "None"

    # Sort the list to ensure proper grouping
    sorted_slots = sorted(slot_list)

    ranges = []
    start = sorted_slots[0]
    end = sorted_slots[0]

    for i in range(1, len(sorted_slots)):
        if sorted_slots[i] == end + 1:
            # Continue the current range
            end = sorted_slots[i]
        else:
            # End the current range and start a new one
            if start == end:
                ranges.append(str(start))
            else:
                ranges.append(f"{start}-{end}")
            start = sorted_slots[i]
            end = sorted_slots[i]

    # Add the final range
    if start == end:
        ranges.append(str(start))
    else:
        ranges.append(f"{start}-{end}")

    return ", ".join(ranges)


def save_summary_to_file(results, filename_prefix):
    """
    Saves the slot availability summary to dedicated CSV files for easy analysis.
    This is separate from debug logs for better performance and analysis.
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    summary_filename = f"{filename_prefix}_summary_{timestamp}.csv"
    detailed_filename = f"{filename_prefix}_detailed_{timestamp}.csv"

    try:
        # Calculate totals per chassis type
        chassis_totals = {}
        successful_devices = []

        for result in results:
            if result["status"] == "Success":
                successful_devices.append(result)
                chassis_type = result["chassis_type"]
                available_count = result["available_slot_count"]

                if chassis_type not in chassis_totals:
                    chassis_totals[chassis_type] = 0
                chassis_totals[chassis_type] += available_count

        # Save summary CSV
        with open(summary_filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Header with metadata
            writer.writerow(['# Chassis Slot Availability Summary'])
            writer.writerow(['# Generated:', datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
            writer.writerow(['# Total Devices Processed:', len(results)])
            writer.writerow(['# Successful Devices:', len(successful_devices)])
            writer.writerow(['# Success Rate:', f"{(len(successful_devices) / len(results) * 100):.1f}%"])
            writer.writerow([])  # Empty row

            # Summary data
            writer.writerow(['Chassis_PID', 'Total_Blank_Slots'])
            total_available = 0
            for chassis_type in sorted(chassis_totals.keys()):
                count = chassis_totals[chassis_type]
                writer.writerow([chassis_type, count])
                total_available += count

            writer.writerow([])  # Empty row
            writer.writerow(['TOTAL_AVAILABLE_SLOTS', total_available])

        # Save detailed CSV
        with open(detailed_filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Header
            writer.writerow(['Device', 'Chassis_Type', 'Occupied_Slots', 'Available_Slots', 'Available_Count'])

            for result in sorted(successful_devices, key=lambda x: (x["chassis_type"], x["hostname"])):
                occupied_str = format_slot_ranges(result["occupied_slots"])
                available_str = format_slot_ranges(result["available_slots"])

                writer.writerow([
                    result["hostname"],
                    result["chassis_type"],
                    occupied_str,
                    available_str,
                    result["available_slot_count"]
                ])

        print(f"{COLOR_BOLD_GREEN}✓ Summary saved to: {summary_filename}{COLOR_RESET}")
        print(f"{COLOR_BOLD_GREEN}✓ Detailed data saved to: {detailed_filename}{COLOR_RESET}")

        # Also log to the debug log
        logger.info(f"Summary files created: {summary_filename}, {detailed_filename}")
        logger.info(f"Total available slots across all chassis: {total_available}")

        return summary_filename, detailed_filename

    except Exception as e:
        logger.error(f"Failed to save summary files: {e}")
        print(f"{COLOR_BOLD_RED}✗ Failed to save summary files: {e}{COLOR_RESET}")
        return None, None


def get_device_info_list():
    """
    Prompts the user for a list of router hostnames/IPs and credentials.
    """
    hostnames = []

    print("\nPaste your list of IOS-XR hostnames or IP addresses below, one per line.")
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

    print(f"\n{COLOR_BOLD_YELLOW}Total devices to process: {len(hostnames)}{COLOR_RESET}")
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


def parse_show_platform_for_slots(output):
    """
    Parses 'show platform' output to extract occupied slot numbers.
    Returns a list of occupied slot numbers (integers).
    """
    occupied_slots = []
    lines = output.splitlines()

    # Look for lines with slot format: 0/X/CPU0 where X is the slot number
    slot_pattern = r'^0/(\d+)/CPU0\s+.*?(?:IOS XR RUN|OPERATIONAL)'

    for line in lines:
        clean_line = line.strip()
        match = re.search(slot_pattern, clean_line)
        if match:
            slot_num = int(match.group(1))
            occupied_slots.append(slot_num)

    return sorted(occupied_slots)


def determine_chassis_type(show_version_output):
    """
    Determines chassis type from show version output.
    Returns chassis type (8812, 8818, 8808, 8804) or None if not found.
    """
    # Look for chassis information in show version
    patterns = [
        r'8812',
        r'8818',
        r'8808',
        r'8804'
    ]

    for pattern in patterns:
        if re.search(pattern, show_version_output, re.IGNORECASE):
            return pattern

    return None


def calculate_available_slots(chassis_type, occupied_slots):
    """
    Calculates available slots based on chassis type and occupied slots.
    """
    if chassis_type not in CHASSIS_SLOTS:
        return []

    total_slots = CHASSIS_SLOTS[chassis_type]
    available_slots = [slot for slot in total_slots if slot not in occupied_slots]

    return available_slots


def send_command_interactive(shell, command, wait_time=2, max_loops=15):
    """
    Sends a command to an interactive shell and waits for the output.
    Optimized for faster response.
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
    Optimized for scale with better error handling.
    """
    last_exception = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Optimized connection parameters for scale
            client.connect(
                hostname=hostname,
                username=username,
                password=password,
                timeout=SSH_TIMEOUT,
                look_for_keys=False,
                allow_agent=False,
                banner_timeout=10,
                auth_timeout=10
            )

            shell = client.invoke_shell()
            time.sleep(0.5)  # Reduced wait time
            if shell.recv_ready():
                shell.recv(65535)

            shell.send("terminal length 0\n")
            time.sleep(0.5)  # Reduced wait time
            if shell.recv_ready():
                shell.recv(65535)

            return client, shell

        except Exception as e:
            last_exception = e
            # Removed duplicate timestamp - logging formatter will add it
            logger.warning(f"Attempt {attempt}/{MAX_RETRIES} failed for {hostname}: {str(e)[:100]}")
            if client:
                client.close()
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
            else:
                raise last_exception


def process_device_slots(device_config):
    """
    Connects to a single IOS-XR device and calculates slot availability.
    """
    hostname = device_config["host"]
    username = device_config["username"]
    password = device_config["password"]

    device_results = {
        "hostname": hostname,
        "status": "Success",
        "error_message": None,
        "chassis_type": "Unknown",
        "occupied_slots": [],
        "available_slots": [],
        "available_slot_count": 0
    }

    client = None
    shell = None

    try:
        # Connect with retry mechanism
        client, shell = connect_with_retry(hostname, username, password)

        # Verify it's IOS-XR
        version_output = send_command_interactive(shell, 'show version', wait_time=1, max_loops=10)

        if "Cisco IOS XR Software" not in version_output:
            device_results["status"] = "Not IOS-XR"
            device_results["error_message"] = "Device is not running IOS-XR"
            return device_results

        # Determine chassis type
        chassis_type = determine_chassis_type(version_output)
        if not chassis_type:
            device_results["status"] = "Unsupported Chassis"
            device_results["error_message"] = "Chassis type not supported (not 8812/8818/8808/8804)"
            return device_results

        device_results["chassis_type"] = chassis_type

        # Get platform information
        platform_output = send_command_interactive(shell, "show platform", wait_time=1, max_loops=10)

        if "authorization failed" in platform_output.lower():
            device_results["status"] = "Authorization Failed"
            device_results["error_message"] = "User does not have permission to run 'show platform'"
            return device_results

        # Parse occupied slots
        occupied_slots = parse_show_platform_for_slots(platform_output)
        device_results["occupied_slots"] = occupied_slots

        # Calculate available slots
        available_slots = calculate_available_slots(chassis_type, occupied_slots)
        device_results["available_slots"] = available_slots
        device_results["available_slot_count"] = len(available_slots)

        # Removed duplicate timestamp - logging formatter will add it
        logger.info(
            f"Successfully processed {hostname}: {chassis_type} chassis, {len(available_slots)} available slots")

    except Exception as e:
        device_results["status"] = "Connection Error"
        device_results["error_message"] = str(e)
        # Removed duplicate timestamp - logging formatter will add it
        logger.error(f"Failed to process {hostname}: {str(e)}")
    finally:
        if client:
            client.close()

    return device_results


def print_slot_availability_summary(results):
    """
    Prints summary table showing available slots count per chassis type.
    """
    print(f"\n{'=' * 10} Chassis Slot Availability Summary {'=' * 10}")

    # Calculate totals per chassis type
    chassis_totals = {}

    for result in results:
        if result["status"] == "Success":
            chassis_type = result["chassis_type"]
            available_count = result["available_slot_count"]

            if chassis_type not in chassis_totals:
                chassis_totals[chassis_type] = 0
            chassis_totals[chassis_type] += available_count

    if chassis_totals:
        summary_table = PrettyTable()
        summary_table.field_names = ["Chassis PID", "Blank Slots Count"]
        summary_table.align = "l"
        summary_table.align["Blank Slots Count"] = "r"

        # Sort by chassis type for consistent output
        for chassis_type in sorted(chassis_totals.keys()):
            summary_table.add_row([chassis_type, chassis_totals[chassis_type]])

        print(summary_table)

        # Print grand total
        total_available = sum(chassis_totals.values())
        print(f"\n{COLOR_BOLD_GREEN}Total Available Slots Across All Chassis: {total_available}{COLOR_RESET}")
    else:
        print(f"{COLOR_BOLD_YELLOW}No successful chassis slot data found.{COLOR_RESET}")

    print(f"{'=' * 50}\n")


def print_detailed_device_info(results):
    """
    Prints detailed per-device slot information with compact range formatting.
    """
    print(f"\n{'=' * 10} Detailed Device Slot Information {'=' * 10}")

    successful_results = [r for r in results if r["status"] == "Success"]

    if not successful_results:
        print(f"{COLOR_BOLD_YELLOW}No successful devices to display.{COLOR_RESET}")
        return

    detail_table = PrettyTable()
    detail_table.field_names = ["Device", "Chassis Type", "Occupied Slots", "Available Slots", "Available Count"]
    detail_table.align = "l"
    detail_table.align["Available Count"] = "r"
    detail_table.max_width["Occupied Slots"] = 30
    detail_table.max_width["Available Slots"] = 30

    for result in sorted(successful_results, key=lambda x: (x["chassis_type"], x["hostname"])):
        occupied_str = format_slot_ranges(result["occupied_slots"])
        available_str = format_slot_ranges(result["available_slots"])

        detail_table.add_row([
            result["hostname"],
            result["chassis_type"],
            occupied_str,
            available_str,
            result["available_slot_count"]
        ])

    print(detail_table)
    print(f"{'=' * 50}\n")


def print_failures(results):
    """
    Prints a table of devices that failed connection or processing.
    """
    failed_devices = [r for r in results if r.get("status") != "Success"]

    if not failed_devices:
        print(f"{COLOR_BOLD_GREEN}✓ All devices processed successfully!{COLOR_RESET}")
        return

    print(f"\n{'=' * 10} Connection / Audit Failures {'=' * 10}")
    fail_table = PrettyTable()
    fail_table.field_names = ["Device", "Status", "Error Details"]
    fail_table.align = "l"
    fail_table.max_width["Error Details"] = 60

    for dev in failed_devices:
        # Sanitize the error message for better readability
        sanitized_error = sanitize_error_message(dev["error_message"])

        fail_table.add_row([
            dev["hostname"],
            f"{COLOR_BOLD_RED}{dev['status']}{COLOR_RESET}",
            sanitized_error
        ])

    print(fail_table)
    print(f"{COLOR_BOLD_RED}Failed Devices: {len(failed_devices)}{COLOR_RESET}")
    print(f"{'=' * 50}\n")


def main():
    print(f"{COLOR_BOLD_YELLOW}IOS-XR Chassis Slot Availability Audit Tool v3.2.0{COLOR_RESET}")
    print(f"Optimized for large-scale deployment (7000+ devices)")
    print(f"Supported chassis: 8812 (12 slots), 8818 (18 slots), 8808 (8 slots), 8804 (4 slots)")

    all_devices_config = get_device_info_list()

    if not all_devices_config:
        return

    print(f"\n{COLOR_BOLD_YELLOW}Starting concurrent processing for {len(all_devices_config)} devices...")
    print(f"Max Workers: {MAX_WORKERS} | Max Retries: {MAX_RETRIES} | SSH Timeout: {SSH_TIMEOUT}s{COLOR_RESET}")

    start_time = time.time()
    results = []
    completed_count = 0
    total_devices = len(all_devices_config)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_device = {executor.submit(process_device_slots, dev_conf): dev_conf
                            for dev_conf in all_devices_config}

        for future in as_completed(future_to_device):
            device_config = future_to_device[future]
            completed_count += 1

            # Progress indicator
            progress_percent = (completed_count / total_devices) * 100
            sys.stdout.write(
                f"\r[Progress] {completed_count}/{total_devices} ({progress_percent:.1f}%) devices processed...")
            sys.stdout.flush()

            try:
                result = future.result()
                results.append(result)
            except Exception as exc:
                logger.error(f"Thread execution error for {device_config['host']}: {exc}")
                results.append({
                    "hostname": device_config["host"],
                    "status": "Thread Error",
                    "error_message": f"Thread execution exception: {exc}",
                    "chassis_type": "Unknown",
                    "occupied_slots": [],
                    "available_slots": [],
                    "available_slot_count": 0
                })

    end_time = time.time()
    print(f"\n\n{COLOR_BOLD_YELLOW}Processing completed in {end_time - start_time:.2f} seconds.{COLOR_RESET}")

    # Calculate success rate
    successful_devices = len([r for r in results if r["status"] == "Success"])
    success_rate = (successful_devices / total_devices) * 100
    print(f"{COLOR_BOLD_GREEN}Success Rate: {successful_devices}/{total_devices} ({success_rate:.1f}%){COLOR_RESET}\n")

    # Sort results by chassis type, then hostname
    results.sort(key=lambda x: (x.get('chassis_type', 'ZZZ'), x['hostname']))

    # Print reports to console
    print_slot_availability_summary(results)
    print_detailed_device_info(results)
    print_failures(results)

    # Save summary data to separate files
    print(f"\n{COLOR_BOLD_YELLOW}Generating summary files...{COLOR_RESET}")
    save_summary_to_file(results, "slot_audit")

    # Log summary to debug log
    logger.info(f"Audit completed: {successful_devices}/{total_devices} devices successful")


if __name__ == "__main__":
    main()