# This script is a chassis slot availability audit tool for Cisco IOS-XR and SONiC devices,
# optimized for large-scale execution (e.g., 7000+ devices).
#
# Key Capabilities:
#
# 1.  **Multi-OS Support:**
#     - Supports both IOS-XR and SONiC operating systems
#     - Automatically detects OS type during connection
#     - Targets 8812, 8818, 8808, and 8804 chassis types for both OS types
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
# 4.  **SONiC Integration:**
#     - **SONiC Detection:** Uses 'show version | egrep -i version' for OS detection
#     - **Slot Detection:** Uses 'show platform inventory' to identify occupied slots
#     - **Chassis Detection:** Parses chassis information from platform inventory
#
# 5.  **Reporting:**
#     - **Slot Availability Summary:** Shows blank slots per chassis type and OS
#     - **Connection Failures:** Detailed failure reporting for unreachable devices
#     - **Compact Slot Display:** Contiguous slots shown with spaced hyphens (e.g., 1 - 2)
#     - **User-Friendly Errors:** Clean, actionable error messages
#     - **Summary Files:** Separate CSV files for summary and detailed data
#     - **Excel-Safe Format:** Uses spaced hyphens to prevent date interpretation
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
__version__ = "4.4.0"
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

# Chassis slot definitions (same for both IOS-XR and SONiC)
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
    Contiguous slots are represented with spaced hyphens to prevent Excel date interpretation.

    Examples:
    [10, 11, 12, 13, 14, 15] -> "10 - 15"
    [1, 2, 5, 6, 7, 10] -> "1 - 2, 5 - 7, 10"
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
                ranges.append(f"{start} - {end}")  # Space before and after hyphen
            start = sorted_slots[i]
            end = sorted_slots[i]

    # Add the final range
    if start == end:
        ranges.append(str(start))
    else:
        ranges.append(f"{start} - {end}")  # Space before and after hyphen

    return ", ".join(ranges)


def save_summary_to_file(results, filename_prefix):
    """
    Saves the slot availability summary to dedicated CSV files for easy analysis.
    Uses spaced hyphen format (3 - 7) to prevent Excel date interpretation.
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    summary_filename = f"{filename_prefix}_summary_{timestamp}.csv"
    detailed_filename = f"{filename_prefix}_detailed_{timestamp}.csv"

    try:
        # Calculate totals per chassis type and OS
        chassis_os_totals = {}
        successful_devices = []

        for result in results:
            if result["status"] == "Success":
                successful_devices.append(result)
                chassis_type = result["chassis_type"]
                os_type = result["os_type"]
                available_count = result["available_slot_count"]

                key = f"{chassis_type}_{os_type}"
                if key not in chassis_os_totals:
                    chassis_os_totals[key] = 0
                chassis_os_totals[key] += available_count

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

            # Summary data with OS type
            writer.writerow(['Chassis_PID', 'OS_Type', 'Total_Blank_Slots'])
            total_available = 0
            for key in sorted(chassis_os_totals.keys()):
                chassis_type, os_type = key.split('_', 1)
                count = chassis_os_totals[key]
                writer.writerow([chassis_type, os_type, count])
                total_available += count

            writer.writerow([])  # Empty row
            writer.writerow(['TOTAL_AVAILABLE_SLOTS', '', total_available])

        # Save detailed CSV with spaced hyphen format
        with open(detailed_filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Header with OS Type column
            writer.writerow(
                ['Device', 'OS_Type', 'Chassis_Type', 'Occupied_Slots', 'Available_Slots', 'Available_Count'])

            for result in sorted(successful_devices, key=lambda x: (x["os_type"], x["chassis_type"], x["hostname"])):
                occupied_str = format_slot_ranges(result["occupied_slots"])
                available_str = format_slot_ranges(result["available_slots"])

                # Clean format with spaced hyphens
                writer.writerow([
                    result["hostname"],
                    result["os_type"],
                    result["chassis_type"],
                    occupied_str,  # Will display as: 1 - 2
                    available_str,  # Will display as: 0, 3
                    result["available_slot_count"]
                ])

        print(f"{COLOR_BOLD_GREEN}✓ Summary saved to: {summary_filename}{COLOR_RESET}")
        print(f"{COLOR_BOLD_GREEN}✓ Detailed data saved to: {detailed_filename}{COLOR_RESET}")
        print(
            f"{COLOR_BOLD_GREEN}✓ Using spaced hyphen format (3 - 7) to prevent Excel date interpretation{COLOR_RESET}")

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

    print("\nPaste your list of device hostnames or IP addresses below, one per line.")
    print("(Supports both IOS-XR and SONiC devices)")
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


def parse_sonic_platform_for_slots(output):
    """
    Parses SONiC 'show platform inventory' output to extract occupied slot numbers.
    Looks for Line Cards section and identifies which LC slots are present vs "not present"

    Example parsing from:
    Line Cards
        LC0                 88-LC0-36FH-M   1.0      FOC2710N8TB     Cisco 8800 36x400GE QSFP56-DD Line Card with MacSec
        LC1                 88-LC0-36FH     1.0      FJZ27210HBB     Cisco 8800 36x400GE QSFP56-DD Line Card
        LC2                 88-LC0-36FH     1.0      FOC2725N9AY     Cisco 8800 36x400GE QSFP56-DD Line Card
        LC3 -- not present
        LC4 -- not present
    """
    occupied_slots = []
    lines = output.splitlines()

    # Look for the Line Cards section
    in_line_cards_section = False

    for line in lines:
        clean_line = line.strip()

        # Identify the Line Cards section
        if clean_line == "Line Cards":
            in_line_cards_section = True
            continue

        # Stop when we hit the next section (empty line or new section)
        if in_line_cards_section and (
                not clean_line or clean_line in ["Fabric Cards", "Power Supplies", "Cooling Devices", "FPDs"]):
            if clean_line in ["Fabric Cards", "Power Supplies", "Cooling Devices", "FPDs"]:
                break
            continue

        # Parse line card entries
        if in_line_cards_section and clean_line:
            # Look for pattern: LC0, LC1, etc. (not "-- not present")
            lc_match = re.match(r'^LC(\d+)\s+.*', clean_line)
            if lc_match and "-- not present" not in clean_line:
                slot_num = int(lc_match.group(1))
                occupied_slots.append(slot_num)

    logger.debug(f"SONiC occupied slots parsed: {occupied_slots}")
    return sorted(occupied_slots)


def determine_sonic_chassis_type(inventory_output):
    """
    Determines chassis type from SONiC 'show platform inventory' output.
    Looks for the Chassis section to identify the chassis model.

    Example parsing from:
    Chassis
        CHASSIS             8808            1.0                  FOX2723PE96     Cisco 8808 8-slot Chassis
    """
    lines = inventory_output.splitlines()

    # Look for chassis information in the Chassis section
    in_chassis_section = False

    for line in lines:
        clean_line = line.strip()

        # Identify the Chassis section
        if clean_line == "Chassis":
            in_chassis_section = True
            continue

        # Stop when we hit the next section (empty line or new section)
        if in_chassis_section and (not clean_line or clean_line in ["Route Processors", "Line Cards", "Fabric Cards"]):
            if clean_line in ["Route Processors", "Line Cards", "Fabric Cards"]:
                break
            continue

        # Parse chassis entry
        if in_chassis_section and clean_line and "CHASSIS" in clean_line:
            # Look for pattern: CHASSIS 8808 1.0 FOX2723PE96
            parts = clean_line.split()
            if len(parts) >= 2:
                product_id = parts[1]
                # Check if it matches our supported chassis types
                patterns = ['8812', '8818', '8808', '8804']
                for pattern in patterns:
                    if pattern == product_id:
                        logger.debug(f"SONiC chassis type detected: {pattern}")
                        return pattern

    logger.debug("SONiC chassis type not found in inventory output")
    return None


def detect_os_type(shell):
    """
    Detects whether the device is running IOS-XR or SONiC.
    Returns tuple: (os_type, os_version, chassis_type)
    """
    # First try IOS-XR detection
    xr_output = send_command_interactive(shell, 'show version | i "Cisco IOS XR Software"', wait_time=1, max_loops=8)

    if "Cisco IOS XR Software" in xr_output and "Version" in xr_output:
        # It's IOS-XR
        full_version_output = send_command_interactive(shell, 'show version', wait_time=2)

        # Parse IOS-XR version
        os_version = "Unknown"
        for line in full_version_output.splitlines():
            if "Label" in line and ":" in line:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    os_version = parts[1].strip()
                    break

        if os_version == "Unknown":
            # Fallback parse for IOS-XR
            for line in xr_output.splitlines():
                if "Version" in line:
                    parts = line.split("Version", 1)
                    if len(parts) > 1:
                        os_version = parts[1].strip().split(" ")[0]
                        break

        # Parse IOS-XR chassis
        chassis_type = determine_chassis_type(full_version_output)

        return "IOS-XR", os_version, chassis_type

    else:
        # Try SONiC detection
        sonic_output = send_command_interactive(shell, 'show version | egrep -i version', wait_time=1, max_loops=8)

        if "SONiC Software Version" in sonic_output or "SONiC OS Version" in sonic_output:
            # It's SONiC
            os_version = "Unknown"

            # Parse SONiC version
            for line in sonic_output.splitlines():
                if "SONiC Software Version:" in line:
                    parts = line.split("SONiC Software Version:", 1)
                    if len(parts) > 1:
                        os_version = parts[1].strip()
                        break

            # For SONiC, get chassis info from platform inventory
            inventory_output = send_command_interactive(shell, 'show platform inventory', wait_time=2, max_loops=10)
            chassis_type = determine_sonic_chassis_type(inventory_output)

            if not chassis_type:
                # Fallback: try hostname pattern matching
                hostname_output = send_command_interactive(shell, 'hostname', wait_time=1, max_loops=5)
                chassis_type = determine_chassis_from_hostname(hostname_output)

            return "SONiC", os_version, chassis_type

    return "Unknown", "Unknown", None


def determine_chassis_from_hostname(hostname_output):
    """
    Attempts to determine chassis type from hostname pattern.
    This is a fallback method for SONiC devices.
    """
    hostname = hostname_output.strip()

    # Look for chassis indicators in hostname
    patterns = [
        r'8812',
        r'8818',
        r'8808',
        r'8804'
    ]

    for pattern in patterns:
        if re.search(pattern, hostname, re.IGNORECASE):
            return pattern

    return None


def parse_show_platform_for_slots(output):
    """
    Parses IOS-XR 'show platform' output to extract occupied slot numbers.
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

    logger.debug(f"IOS-XR occupied slots parsed: {occupied_slots}")
    return sorted(occupied_slots)


def determine_chassis_type(show_version_output):
    """
    Determines chassis type from IOS-XR show version output.
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
            # Check for both IOS-XR (#) and SONiC ($) prompts
            if output.strip().endswith('#') or output.strip().endswith('$'):
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

            # Set terminal length for both OS types
            shell.send("terminal length 0\n")  # Works for both IOS-XR and SONiC
            time.sleep(0.5)  # Reduced wait time
            if shell.recv_ready():
                shell.recv(65535)

            return client, shell

        except Exception as e:
            last_exception = e
            logger.warning(f"Attempt {attempt}/{MAX_RETRIES} failed for {hostname}: {str(e)[:100]}")
            if client:
                client.close()
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
            else:
                raise last_exception


def process_device_slots(device_config):
    """
    Connects to a single device and calculates slot availability.
    Supports both IOS-XR and SONiC devices.
    """
    hostname = device_config["host"]
    username = device_config["username"]
    password = device_config["password"]

    device_results = {
        "hostname": hostname,
        "status": "Success",
        "error_message": None,
        "os_type": "Unknown",
        "os_version": "Unknown",
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

        # Detect OS type, version, and chassis
        os_type, os_version, chassis_type = detect_os_type(shell)

        device_results["os_type"] = os_type
        device_results["os_version"] = os_version
        device_results["chassis_type"] = chassis_type

        if os_type == "Unknown":
            device_results["status"] = "Unknown OS"
            device_results["error_message"] = "Device is not running IOS-XR or SONiC"
            return device_results

        if not chassis_type:
            device_results["status"] = "Unsupported Chassis"
            device_results["error_message"] = f"Chassis type not supported (not 8812/8818/8808/8804) for {os_type}"
            return device_results

        # Get platform information based on OS type
        if os_type == "IOS-XR":
            platform_output = send_command_interactive(shell, "show platform", wait_time=1, max_loops=10)

            if "authorization failed" in platform_output.lower():
                device_results["status"] = "Authorization Failed"
                device_results["error_message"] = "User does not have permission to run 'show platform'"
                return device_results

            occupied_slots = parse_show_platform_for_slots(platform_output)

        elif os_type == "SONiC":
            # Use SONiC platform inventory command
            platform_output = send_command_interactive(shell, "show platform inventory", wait_time=2, max_loops=10)

            if "command not found" in platform_output.lower() or "invalid command" in platform_output.lower():
                device_results["status"] = "Command Not Found"
                device_results["error_message"] = "SONiC 'show platform inventory' command not available"
                return device_results

            occupied_slots = parse_sonic_platform_for_slots(platform_output)

        device_results["occupied_slots"] = occupied_slots

        # Calculate available slots
        available_slots = calculate_available_slots(chassis_type, occupied_slots)
        device_results["available_slots"] = available_slots
        device_results["available_slot_count"] = len(available_slots)

        logger.info(
            f"Successfully processed {hostname}: {os_type} {chassis_type} chassis, {len(available_slots)} available slots")

    except Exception as e:
        device_results["status"] = "Connection Error"
        device_results["error_message"] = str(e)
        logger.error(f"Failed to process {hostname}: {str(e)}")
    finally:
        if client:
            client.close()

    return device_results


def print_slot_availability_summary(results):
    """
    Prints summary table showing available slots count per chassis type and OS.
    """
    print(f"\n{'=' * 10} Chassis Slot Availability Summary {'=' * 10}")

    # Calculate totals per chassis type and OS
    chassis_os_totals = {}

    for result in results:
        if result["status"] == "Success":
            chassis_type = result["chassis_type"]
            os_type = result["os_type"]
            available_count = result["available_slot_count"]

            key = f"{chassis_type}_{os_type}"
            if key not in chassis_os_totals:
                chassis_os_totals[key] = 0
            chassis_os_totals[key] += available_count

    if chassis_os_totals:
        summary_table = PrettyTable()
        summary_table.field_names = ["Chassis PID", "OS Type", "Blank Slots Count"]
        summary_table.align = "l"
        summary_table.align["Blank Slots Count"] = "r"

        # Sort by chassis type, then OS type
        for key in sorted(chassis_os_totals.keys()):
            chassis_type, os_type = key.split('_', 1)
            summary_table.add_row([chassis_type, os_type, chassis_os_totals[key]])

        print(summary_table)

        # Print grand total
        total_available = sum(chassis_os_totals.values())
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
    detail_table.field_names = ["Device", "OS Type", "Chassis Type", "Occupied Slots", "Available Slots",
                                "Available Count"]
    detail_table.align = "l"
    detail_table.align["Available Count"] = "r"
    detail_table.max_width["Occupied Slots"] = 25
    detail_table.max_width["Available Slots"] = 25

    for result in sorted(successful_results, key=lambda x: (x["os_type"], x["chassis_type"], x["hostname"])):
        occupied_str = format_slot_ranges(result["occupied_slots"])
        available_str = format_slot_ranges(result["available_slots"])

        detail_table.add_row([
            result["hostname"],
            result["os_type"],
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
    print(f"{COLOR_BOLD_YELLOW}Multi-OS Chassis Slot Availability Audit Tool v4.4.0{COLOR_RESET}")
    print(f"Optimized for large-scale deployment (7000+ devices)")
    print(f"Supported OS: IOS-XR and SONiC")
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
                    "os_type": "Unknown",
                    "os_version": "Unknown",
                    "chassis_type": "Unknown",
                    "occupied_slots": [],
                    "available_slots": [],
                    "available_slot_count": 0
                })

    end_time = time.time()
    print(f"\n\n{COLOR_BOLD_YELLOW}Processing completed in {end_time - start_time:.2f} seconds.{COLOR_RESET}")

    # Calculate success rate and OS distribution
    successful_devices = len([r for r in results if r["status"] == "Success"])
    success_rate = (successful_devices / total_devices) * 100

    # Count devices by OS type
    os_counts = {}
    for result in results:
        if result["status"] == "Success":
            os_type = result["os_type"]
            os_counts[os_type] = os_counts.get(os_type, 0) + 1

    print(f"{COLOR_BOLD_GREEN}Success Rate: {successful_devices}/{total_devices} ({success_rate:.1f}%){COLOR_RESET}")
    for os_type, count in sorted(os_counts.items()):
        print(f"{COLOR_BOLD_GREEN}{os_type}: {count} devices{COLOR_RESET}")

    # Sort results by OS type, chassis type, then hostname
    results.sort(key=lambda x: (x.get('os_type', 'ZZZ'), x.get('chassis_type', 'ZZZ'), x['hostname']))

    # Print reports to console
    print_slot_availability_summary(results)
    print_detailed_device_info(results)
    print_failures(results)

    # Save summary data to separate files
    print(f"\n{COLOR_BOLD_YELLOW}Generating summary files...{COLOR_RESET}")
    save_summary_to_file(results, "slot_audit")

    # Log summary to debug log
    logger.info(f"Audit completed: {successful_devices}/{total_devices} devices successful")
    logger.info(f"OS distribution: {os_counts}")


if __name__ == "__main__":
    main()