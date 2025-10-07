import time
import paramiko
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import getpass

# Define the list of commands to be executed
commands = [
    "show version | i Label",
    "show version | i uptime",
    "show platform"
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

    slots = sorted(list(set(slots)))

    ranges = []
    if not slots:
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
        if "Node" in line and "Type" in line and "State" in line:
            continue
        if "----" in line:
            continue

        # Regex to capture node (e.g., 0/0/CPU0) and the Type field
        match = re.match(r"^(0/(\d+)/CPU0)\s+(\S+.*?)\s+.*", line)
        if match:
            slot_num_str = match.group(2)
            raw_card_type = match.group(3).strip()

            # Clean up the card type if it contains (Active) or (Standby)
            card_type = re.sub(r'\s*\(Active\)|\s*\(Standby\)', '', raw_card_type).strip()

            # Apply filtering logic for line cards (must contain "LC" and not be RP, BMC, FC, FT, PT)
            if "LC" in card_type and \
                    "RP" not in card_type and \
                    "BMC" not in card_type and \
                    "FC" not in card_type and \
                    "FT" not in card_type and \
                    "PT" not in card_type:
                try:
                    slot_num = int(slot_num_str)
                    line_card_slots.append(slot_num)
                    card_type_counts[card_type] = card_type_counts.get(card_type, 0) + 1
                except ValueError:
                    pass  # Should not happen if regex matches digits

    line_card_slots.sort()

    slots_populated_str = format_slots_to_ranges(line_card_slots)
    slots_used_count = len(line_card_slots)

    return {
        "Name of Device": device_name,
        "Slots populated": slots_populated_str,
        "Slots used": slots_used_count,
        "Card Type Counts": card_type_counts
    }


def main():
    username = input("Enter SSH username: ")
    password = getpass.getpass("Enter SSH password: ")

    print("\nPaste your list of hostnames or IP addresses below, one per line.")
    print("Press Enter twice when you are finished (i.e., an empty line):")

    host_lines = []
    while True:
        line = input()
        if not line:
            break
        host_lines.append(line.strip())

    devices_input = []
    for host in host_lines:
        if host:
            devices_input.append({
                "hostname": host,
                "username": username,
                "password": password
            })

    if not devices_input:
        print("No devices entered. Exiting.")
        return

    start_time = time.time()

    processed_device_data = {}

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_index = {
            executor.submit(
                ssh_and_get_outputs,
                device["hostname"],
                device["username"],
                device["password"],
                commands,
            ): idx for idx, device in enumerate(devices_input)
        }
        for future in as_completed(future_to_index):
            idx = future_to_index[future]
            raw_result = future.result()

            device_hostname = raw_result['device']

            device_data = {
                "device": device_hostname,
                "label": "N/A",
                "uptime": "N/A",
                "line_card_info": {
                    "Name of Device": device_hostname,
                    "Slots populated": "N/A",
                    "Slots used": "N/A",
                    "Card Type Counts": {}
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

                device_data["label"] = extract_label(outputs.get(commands[0], ""))
                device_data["uptime"] = extract_uptime(outputs.get(commands[1], ""))

                show_platform_output = outputs.get("show platform", "")
                if show_platform_output:
                    line_card_details = get_line_card_info(device_hostname, show_platform_output)
                    device_data["line_card_info"] = line_card_details
                else:
                    device_data["line_card_info"]["Slots populated"] = "No 'show platform' output"
                    device_data["line_card_info"]["Slots used"] = "N/A"

            processed_device_data[idx] = device_data

    end_time = time.time()

    print(f"\n| {'Device':<30} | {'Label':<30} | {'Uptime':<40} |")
    print(f"|{'-' * 32}|{'-' * 32}|{'-' * 42}|")

    for idx in range(len(devices_input)):
        data = processed_device_data.get(idx, {})
        print(f"| {data.get('device', 'N/A'):<30} | {data.get('label', 'N/A'):<30} | {data.get('uptime', 'N/A'):<40} |")

    print("\nLine Card Information:")
    print(f"{'Name of Device':<25} | {'Slots populated':<20} | {'Slots used':<12}")
    print(f"{'-' * 25} | {'-' * 20} | {'-' * 12}")

    all_aggregated_lc_type_counts = {}
    total_slots_used_from_script = 0

    for idx in range(len(devices_input)):
        data = processed_device_data.get(idx, {})
        lc_info = data.get('line_card_info', {})

        current_slots_used = lc_info.get('Slots used', 'N/A')
        print(
            f"{lc_info.get('Name of Device', 'N/A'):<25} | {lc_info.get('Slots populated', 'N/A'):<20} | {current_slots_used:<12}")

        if isinstance(current_slots_used, int):
            total_slots_used_from_script += current_slots_used

        device_card_counts = lc_info.get('Card Type Counts', {})
        for card_type, count in device_card_counts.items():
            all_aggregated_lc_type_counts[card_type] = all_aggregated_lc_type_counts.get(card_type, 0) + count

    print("\nTotal Line Card Type Counts Across All Devices:")

    # These counts directly reflect what was found in the 'show platform' output
    # If a specific type (e.g., without -M) was not found, its count will be 0.
    count_36FH_M = all_aggregated_lc_type_counts.get('88-LC0-36FH-M', 0)
    print(f"Number of 88-LC0-36FH-M cards: {count_36FH_M}")

    count_36FH = all_aggregated_lc_type_counts.get('88-LC0-36FH', 0)
    print(f"Number of 88-LC0-36FH cards: {count_36FH}")

    count_48H = all_aggregated_lc_type_counts.get('8800-LC-48H', 0)
    print(f"Number of 8800-LC-48H cards: {count_48H}")

    # This line confirms the consistency between summed 'Slots used' and aggregated card types
    print(f"\nTotal sum of 'Slots used' from all devices (excluding N/A): {total_slots_used_from_script}")

    print(f"\nTotal execution time: {end_time - start_time:.2f} seconds")


if __name__ == "__main__":
    main()