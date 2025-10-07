import time
import paramiko
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import getpass  # Import getpass for secure password input

# Define the list of commands to be executed
commands = [
    "show version | i Label",
    "show version | i uptime",
    "show platform"  # Added the show platform command
]


def ssh_and_get_outputs(hostname, username, password, commands):
    """
    Connects to a device via SSH, executes commands, and returns the outputs.
    """
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, username=username, password=password, timeout=10)

        outputs = {}
        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            output = stdout.read().decode().strip()
            outputs[cmd] = output

        ssh.close()
        return {"device": hostname, "outputs": outputs}
    except Exception as e:
        return {"device": hostname, "error": str(e)}


def extract_label(output):
    """
    Extracts the Label value from the command output.
    """
    match = re.search(r'Label\s+:\s*(.+)', output, re.IGNORECASE)
    return match.group(1).strip() if match else "N/A"


def extract_uptime(output):
    """
    Extracts the uptime value from the command output.
    """
    match = re.search(r'Uptime\s+is\s+(.+)', output, re.IGNORECASE)
    return match.group(1).strip() if match else "N/A"


def format_slots_to_ranges(slots):
    """
    Formats a list of slot numbers into a comma-separated range string (e.g., "0-9,16-17").
    """
    if not slots:
        return ""

    slots = sorted(list(set(slots)))  # Ensure unique and sorted

    ranges = []
    if not slots:  # Check again after sorting and making unique
        return ""

    current_start = slots[0]
    current_end = slots[0]

    for i in range(1, len(slots)):
        if slots[i] == current_end + 1:
            current_end = slots[i]
        else:
            if current_start == current_end:
                ranges.append(str(current_start))
            else:
                ranges.append(f"{current_start}-{current_end}")
            current_start = slots[i]
            current_end = slots[i]

    # Add the last range after the loop finishes
    if current_start == current_end:
        ranges.append(str(current_start))
    else:
        ranges.append(f"{current_start}-{current_end}")

    return ",".join(ranges)


def get_line_card_info(device_name, show_platform_output):
    """
    Parses the 'show platform' output to find line card information and counts card types.

    Args:
        device_name (str): The name of the network device.
        show_platform_output (str): The raw output from the 'show platform' command.

    Returns:
        dict: A dictionary containing 'Name of Device', 'Slots populated', 'Slots used',
              and 'Card Type Counts' (a dict of card_type: count).
    """
    line_card_slots = []
    card_type_counts = {}

    for line in show_platform_output.splitlines():
        # Skip header and separator lines
        if "Node" in line and "Type" in line and "State" in line:
            continue
        if "----" in line:
            continue

        # Match lines that look like a node entry, specifically for CPU0 nodes
        # This regex captures the 'Type' column (second column) more generally.
        match = re.match(r"^(0/(\d+)/CPU0)\s+(\S+.*?)\s+.*", line)
        if match:
            slot_num_str = match.group(2)  # e.g., "0" from "0/0/CPU0"
            raw_card_type = match.group(3).strip()  # e.g., "88-LC0-36FH" or "8800-LC-48H"

            # Clean up the card type if it contains (Active) or (Standby)
            card_type = re.sub(r'\s*\(Active\)|\s*\(Standby\)', '', raw_card_type).strip()

            # Apply filtering logic for line cards:
            # Must contain "LC" (Line Card)
            # Must NOT contain "RP" (Route Processor)
            # Must NOT contain "BMC" (Baseboard Management Controller)
            # Must NOT contain "FC" (Fabric Card)
            # Must NOT contain "FT" (Fan Tray)
            # Must NOT contain "PT" (Power Tray)
            if "LC" in card_type and \
                    "RP" not in card_type and \
                    "BMC" not in card_type and \
                    "FC" not in card_type and \
                    "FT" not in card_type and \
                    "PT" not in card_type:
                try:
                    slot_num = int(slot_num_str)
                    line_card_slots.append(slot_num)

                    # --- IMPORTANT DEBUGGING LINE ---
                    # This will show you exactly what card type string is being identified.
                    # Look for this output when you run the script.
                    print(f"DEBUG: Device {device_name}, Slot {slot_num}, Extracted Card Type: '{card_type}'")
                    # --- END DEBUGGING LINE ---

                    card_type_counts[card_type] = card_type_counts.get(card_type, 0) + 1
                except ValueError:
                    # Should not happen if regex matches digits, but good for robustness
                    pass

    line_card_slots.sort()  # Ensure slots are sorted for range formatting

    slots_populated_str = format_slots_to_ranges(line_card_slots)
    slots_used_count = len(line_card_slots)

    return {
        "Name of Device": device_name,
        "Slots populated": slots_populated_str,
        "Slots used": slots_used_count,
        "Card Type Counts": card_type_counts
    }


def main():
    # --- User Input Section ---
    username = input("Enter SSH username: ")
    password = getpass.getpass("Enter SSH password: ")  # Securely prompt for password

    print("\nPaste your list of hostnames or IP addresses below, one per line.")
    print("Press Enter twice when you are finished (i.e., an empty line):")

    host_lines = []
    while True:
        line = input()
        if not line:  # Empty line signifies end of input
            break
        host_lines.append(line.strip())

    devices_input = []
    for host in host_lines:
        if host:  # Ensure the line is not empty after stripping whitespace
            devices_input.append({
                "hostname": host,
                "username": username,
                "password": password
            })

    if not devices_input:
        print("No devices entered. Exiting.")
        return

    start_time = time.time()

    # This will store processed data for each device, including parsed line card info
    processed_device_data = {}

    # Using ThreadPoolExecutor to connect to devices concurrently
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_index = {
            executor.submit(
                ssh_and_get_outputs,
                device["hostname"],
                device["username"],
                device["password"],
                commands,  # Now includes "show platform"
            ): idx for idx, device in enumerate(devices_input)
        }
        for future in as_completed(future_to_index):
            idx = future_to_index[future]
            raw_result = future.result()  # Get the raw output from SSH

            device_hostname = raw_result['device']

            # Initialize data for this device with defaults
            device_data = {
                "device": device_hostname,
                "label": "N/A",
                "uptime": "N/A",
                "line_card_info": {
                    "Name of Device": device_hostname,
                    "Slots populated": "N/A",
                    "Slots used": "N/A",
                    "Card Type Counts": {}  # Initialize for line card type counts
                }
            }

            if 'error' in raw_result:
                error_msg = f"Error: {raw_result['error']}"
                device_data["label"] = error_msg
                device_data["uptime"] = error_msg
                device_data["line_card_info"]["Slots populated"] = error_msg
                device_data["line_card_info"]["Slots used"] = "N/A"
            else:
                outputs = raw_result['outputs']

                # Extract Label and Uptime
                device_data["label"] = extract_label(outputs.get(commands[0], ""))
                device_data["uptime"] = extract_uptime(outputs.get(commands[1], ""))

                # Extract Line Card Info
                show_platform_output = outputs.get("show platform", "")
                if show_platform_output:
                    line_card_details = get_line_card_info(device_hostname, show_platform_output)
                    device_data["line_card_info"] = line_card_details
                else:
                    device_data["line_card_info"]["Slots populated"] = "No 'show platform' output"
                    device_data["line_card_info"]["Slots used"] = "N/A"

            processed_device_data[idx] = device_data

    end_time = time.time()

    # Print the first table (Device, Label, Uptime)
    print(f"\n| {'Device':<30} | {'Label':<30} | {'Uptime':<40} |")
    print(f"|{'-' * 32}|{'-' * 32}|{'-' * 42}|")

    for idx in range(len(devices_input)):  # Iterate by index to maintain original order
        data = processed_device_data.get(idx, {})
        print(f"| {data.get('device', 'N/A'):<30} | {data.get('label', 'N/A'):<30} | {data.get('uptime', 'N/A'):<40} |")

    # Print the second table (Line Card Information)
    print("\nLine Card Information:")
    print(f"{'Name of Device':<25} | {'Slots populated':<20} | {'Slots used':<12}")
    print(f"{'-' * 25} | {'-' * 20} | {'-' * 12}")

    # Initialize total card type counts across all devices (flexible)
    all_aggregated_lc_type_counts = {}

    for idx in range(len(devices_input)):  # Iterate by index to maintain original order
        data = processed_device_data.get(idx, {})
        lc_info = data.get('line_card_info', {})

        # Print device-specific line card info
        print(
            f"{lc_info.get('Name of Device', 'N/A'):<25} | {lc_info.get('Slots populated', 'N/A'):<20} | {lc_info.get('Slots used', 'N/A'):<12}")

        # Aggregate card type counts for the totals
        device_card_counts = lc_info.get('Card Type Counts', {})
        for card_type, count in device_card_counts.items():
            all_aggregated_lc_type_counts[card_type] = all_aggregated_lc_type_counts.get(card_type, 0) + count

    # Print the total line card type counts for the specific types requested
    print("\nTotal Line Card Type Counts Across All Devices:")
    # Use .get() with a default of 0 to handle cases where a specific type wasn't found at all
    print(f"Number of 88-LC0-36FH-M cards: {all_aggregated_lc_type_counts.get('88-LC0-36FH-M', 0)}")
    print(f"Number of 88-LC0-36FH cards: {all_aggregated_lc_type_counts.get('88-LC0-36FH', 0)}")
    print(f"Number of 8800-LC-48H cards: {all_aggregated_lc_type_counts.get('8800-LC-48H', 0)}")

    # --- IMPORTANT: This section will show ALL unique card types found ---
    print("\n--- All aggregated Line Card Types found (for debugging) ---")
    if not all_aggregated_lc_type_counts:
        print("No line cards found or processed.")
    else:
        for card_type, count in sorted(all_aggregated_lc_type_counts.items()):
            print(f"  '{card_type}': {count}")
    print("------------------------------------------------------------")
    # --- END IMPORTANT SECTION ---

    print(f"\nTotal execution time: {end_time - start_time:.2f} seconds")


if __name__ == "__main__":
    main()