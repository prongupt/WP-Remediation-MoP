#Added code to get slot population per device per DC

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

    ranges = []
    current_start = slots[0]
    current_end = slots[0]

    for i in range(1, len(slots)):
        if slots[i] == current_end + 1:
            current_end = slots[i]
            # If we've reached the end of the list and it's a consecutive slot,
            # ensure the range is added.
            if i == len(slots) - 1:
                if current_start == current_end:
                    ranges.append(str(current_start))
                else:
                    ranges.append(f"{current_start}-{current_end}")
        else:
            if current_start == current_end:
                ranges.append(str(current_start))
            else:
                ranges.append(f"{current_start}-{current_end}")
            current_start = slots[i]
            current_end = slots[i]
            # If this is the last element and not part of a range
            if i == len(slots) - 1:
                ranges.append(str(current_start))

    # Add the last range if it hasn't been added yet (for single elements or ranges at the end)
    if not ranges or (slots and slots[-1] not in [int(s) for r in ranges for s in (r.split('-') if '-' in r else [r])]):
        if current_start == current_end:
            ranges.append(str(current_start))
        else:
            ranges.append(f"{current_start}-{current_end}")

    return ",".join(sorted(list(set(ranges)), key=lambda x: int(x.split('-')[0])))  # Sort to ensure correct order


def get_line_card_info(device_name, show_platform_output):
    """
    Parses the 'show platform' output to find line card information.

    Args:
        device_name (str): The name of the network device.
        show_platform_output (str): The raw output from the 'show platform' command.

    Returns:
        dict: A dictionary containing 'Name of Device', 'Slots populated', and 'Slots used'.
    """
    line_card_slots = []

    for line in show_platform_output.splitlines():
        # Skip header and separator lines
        if "Node" in line and "Type" in line and "State" in line:
            continue
        if "----" in line:
            continue

        # Match lines that look like a node entry, specifically for CPU0 nodes
        match = re.match(r"^(0/(\d+)/CPU0)\s+(.*?)\s+.*", line)
        if match:
            slot_num_str = match.group(2)  # e.g., "0" from "0/0/CPU0"
            card_type = match.group(3)  # e.g., "88-LC0-36FH"

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
                except ValueError:
                    # Should not happen if regex matches digits, but good for robustness
                    pass

    line_card_slots.sort()  # Ensure slots are sorted for range formatting

    slots_populated_str = format_slots_to_ranges(line_card_slots)
    slots_used_count = len(line_card_slots)

    return {
        "Name of Device": device_name,
        "Slots populated": slots_populated_str,
        "Slots used": slots_used_count
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
                    "Slots used": "N/A"
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

    for idx in range(len(devices_input)):  # Iterate by index to maintain original order
        data = processed_device_data.get(idx, {})
        lc_info = data.get('line_card_info', {})
        print(
            f"{lc_info.get('Name of Device', 'N/A'):<25} | {lc_info.get('Slots populated', 'N/A'):<20} | {lc_info.get('Slots used', 'N/A'):<12}")

    print(f"\nTotal execution time: {end_time - start_time:.2f} seconds")


if __name__ == "__main__":
    main()