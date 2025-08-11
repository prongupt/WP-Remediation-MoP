import os
from netmiko import ConnectHandler
import re

# Global exclusion lists
EXCLUDE_BY_NAME = ["Nu0", "Mg0/RP0/CPU0/0"]
EXCLUDE_BY_PREFIX = ["BE", "Lo", "ti"]


def get_device_credentials():
    """
    Prompts the user for device connection details.
    Uses environment variables as default if set.
    """
    print("Please provide device connection details:")
    # Changed from device_ip to device_host to allow hostname or IP
    device_host = os.getenv("NETMIKO_DEVICE_HOST") or input("Enter device hostname or IP address: ")
    username = os.getenv("NETMIKO_USERNAME") or input("Enter username: ")
    password = os.getenv("NETMIKO_PASSWORD") or input("Enter password: ")
    # Made device_type prompt examples more generic
    device_type = os.getenv("NETMIKO_DEVICE_TYPE") or input(
        "Enter device type (e.g., cisco_ios, cisco_xe, cisco_xr, cisco_nxos, juniper_junos): "
    )
    return device_host, username, password, device_type


def get_interface_output(device_host, username, password, device_type):
    """
    Connects to a device, runs 'show interface summary' and 'show interface brief',
    and returns the brief output.
    """
    device = {
        "device_type": device_type,
        "host": device_host,  # Using device_host here
        "username": username,
        "password": password,
    }
    try:
        print(f"\nAttempting to connect to {device_host}...")  # Using device_host in print
        net_connect = ConnectHandler(**device)
        print("Connection successful.")

        # Run "show interface summary" (output will not be printed to console)
        summary_output = net_connect.send_command("show interface summary")

        # Run "show interface brief" (output will not be printed to console)
        brief_output = net_connect.send_command("show interface brief")

        net_connect.disconnect()
        print(f"\nDisconnected from {device_host}.")  # Using device_host in print
        return brief_output
    except Exception as e:
        print(f"Error connecting or running commands: {e}")
        return None


def parse_interface_brief(brief_output):
    """
    Parses the 'show interface brief' output to identify interfaces
    that should be included in the shutdown list based on specific criteria.
    Returns a list of these interface names.
    """
    if not brief_output:
        return []

    interfaces_to_shutdown = []
    lines = brief_output.strip().splitlines()

    separator_index = -1
    for i, line in enumerate(lines):
        if "--------------------------------------------------------------------------------" in line:
            separator_index = i
            break

    if separator_index == -1 or separator_index < 2:
        print("Error: Could not find the separator line or sufficient header lines in 'show interface brief' output.")
        print("Please provide a sample output for debugging if this persists.")
        return []

    header_line_2 = lines[separator_index - 1]
    data_start_index = separator_index + 1

    header_parts_2 = [part for part in re.split(r'\s{2,}', header_line_2.strip()) if part]

    intf_state_col_idx = -1
    linep_state_col_idx = -1

    if len(header_parts_2) >= 3:
        intf_state_col_idx = 1
        linep_state_col_idx = 2

    if intf_state_col_idx == -1 or linep_state_col_idx == -1:
        print("Error: Could not determine 'Intf State' or 'LineP State' column index from header.")
        print("Please provide a sample output for debugging if this persists.")
        return []

    # Process data lines
    for line in lines[data_start_index:]:
        line = line.strip()
        if not line:
            continue

        parts = [part for part in re.split(r'\s{2,}', line) if part]

        if len(parts) <= max(intf_state_col_idx, linep_state_col_idx):
            continue

        interface_name = parts[0]

        # Check for explicit name exclusion
        if interface_name in EXCLUDE_BY_NAME:
            continue

        # Check for exclusion by prefix (e.g., BE, Lo, ti)
        if any(interface_name.startswith(prefix) for prefix in EXCLUDE_BY_PREFIX):
            continue

        current_intf_state = parts[intf_state_col_idx].lower()
        current_linep_state = parts[linep_state_col_idx].lower()

        is_explicitly_admin_down = False
        if "admin-down" in current_intf_state or "admin-down" in current_linep_state:
            is_explicitly_admin_down = True

        if not is_explicitly_admin_down:
            interfaces_to_shutdown.append(interface_name)

    return interfaces_to_shutdown


def get_down_only_interfaces(brief_output):
    """
    Parses the 'show interface brief' output to identify interfaces
    that are in a 'down/down' operational state (but not admin-down)
    and are not in the exclusion lists.
    Returns a list of these interface names.
    """
    if not brief_output:
        return []

    down_only_interfaces = []
    lines = brief_output.strip().splitlines()

    separator_index = -1
    for i, line in enumerate(lines):
        if "--------------------------------------------------------------------------------" in line:
            separator_index = i
            break

    if separator_index == -1 or separator_index < 2:
        # Error message for this specific function
        print("Error: Could not find the separator line or sufficient header lines for 'down only' check.")
        return []

    header_line_2 = lines[separator_index - 1]
    data_start_index = separator_index + 1

    header_parts_2 = [part for part in re.split(r'\s{2,}', header_line_2.strip()) if part]

    intf_state_col_idx = -1
    linep_state_col_idx = -1

    if len(header_parts_2) >= 3:
        intf_state_col_idx = 1
        linep_state_col_idx = 2

    if intf_state_col_idx == -1 or linep_state_col_idx == -1:
        # Error message for this specific function
        print("Error: Could not determine 'Intf State' or 'LineP State' column index for 'down only' check.")
        return []

    for line in lines[data_start_index:]:
        line = line.strip()
        if not line:
            continue

        parts = [part for part in re.split(r'\s{2,}', line) if part]

        if len(parts) <= max(intf_state_col_idx, linep_state_col_idx):
            continue

        interface_name = parts[0]

        # Apply global exclusions
        if interface_name in EXCLUDE_BY_NAME:
            continue
        if any(interface_name.startswith(prefix) for prefix in EXCLUDE_BY_PREFIX):
            continue

        current_intf_state = parts[intf_state_col_idx].lower()
        current_linep_state = parts[linep_state_col_idx].lower()

        is_explicitly_admin_down = False
        if "admin-down" in current_intf_state or "admin-down" in current_linep_state:
            is_explicitly_admin_down = True

        # Criteria for "down only" interfaces:
        # 1. Not admin-down
        # 2. Both Intf State and LineP State are 'down'
        if not is_explicitly_admin_down and \
           current_intf_state == 'down' and \
           current_linep_state == 'down':
            down_only_interfaces.append(interface_name)

    return down_only_interfaces


def parse_interface_name_for_range(interface_name):
    """
    Parses an interface name to extract its type, common prefix, and port number.
    Handles common interface naming conventions like GigabitEthernet0/0/0/1 or Loopback0.
    Returns (interface_type, prefix_part, port_number) or (None, None, None) if not parsable for range.
    """
    # Regex for interfaces with a final port number (e.g., GigabitEthernet0/0/0/1, Ethernet1/1)
    # This also handles your "FH0/0/0/0" and "Hu0/8/0/0" format
    match = re.match(r"([a-zA-Z]+)(\d+(?:/\d+)*)/(\d+)$", interface_name)
    if match:
        interface_type = match.group(1)  # e.g., FH, Hu
        prefix_part = match.group(2)  # e.g., 0/0/0, 0/8/0
        port_number = int(match.group(3))  # e.g., 0, 1, 35
        return interface_type, f"{interface_type}{prefix_part}/", port_number

    # Regex for interfaces that are just a type followed by a single number (e.g., Nu0, Loopback0, Management1)
    match_single_num = re.match(r"([a-zA-Z]+)(\d+)$", interface_name)
    if match_single_num:
        interface_type = match_single_num.group(1)  # e.g., Nu, Loopback, Management
        port_number = int(match_single_num.group(2))  # e.g., 0
        return interface_type, f"{interface_type}", port_number  # Prefix is just the type for these

    # Interfaces like Mg0/RP0/CPU0/0, PT0/RP0/CPU0/0 are complex and won't form ranges.
    # They will be handled as individual interfaces.
    return None, None, None  # Not a parsable interface for range consolidation


def consolidate_and_generate_range_commands(interface_list):
    """
    Consolidates a list of interface names into 'interface range' commands
    where possible, and individual 'interface' commands otherwise.
    """
    grouped_interfaces = {}  # Key: (interface_type, prefix_part), Value: sorted list of port_numbers
    single_interfaces = []  # Interfaces that cannot be grouped into ranges

    for iface in interface_list:
        iface_type, prefix, port_num = parse_interface_name_for_range(iface)

        if iface_type and prefix and port_num is not None:
            key = (iface_type, prefix)
            if key not in grouped_interfaces:
                grouped_interfaces[key] = []
            grouped_interfaces[key].append(port_num)
        else:
            single_interfaces.append(iface)

    consolidated_commands = []

    # Process grouped interfaces
    for (iface_type, prefix), port_nums in grouped_interfaces.items():
        port_nums.sort()  # Ensure port numbers are sorted for range detection

        if not port_nums:
            continue

        current_range_start = port_nums[0]
        current_range_end = port_nums[0]

        for i in range(1, len(port_nums)):
            if port_nums[i] == current_range_end + 1:
                current_range_end = port_nums[i]
            else:
                # End of a range, or a gap
                if current_range_start == current_range_end:
                    # Single interface in this "range"
                    consolidated_commands.append(f"interface {prefix}{current_range_start} shutdown")
                else:
                    # A range found
                    consolidated_commands.append(
                        f"interface range {prefix}{current_range_start} - {current_range_end} shutdown")

                # Start a new range
                current_range_start = port_nums[i]
                current_range_end = port_nums[i]

        # Add the last range/single interface
        if current_range_start == current_range_end:
            consolidated_commands.append(f"interface {prefix}{current_range_start} shutdown")
        else:
            consolidated_commands.append(
                f"interface range {prefix}{current_range_start} - {current_range_end} shutdown")

    # Add single interfaces that couldn't be grouped
    for iface in single_interfaces:
        consolidated_commands.append(f"interface {iface} shutdown")

    # Sort the final commands for  consistent output (optional)
    consolidated_commands.sort()

    return consolidated_commands


if __name__ == "__main__":
    # Get device connection details from user input or environment variables
    device_host, username, password, device_type = get_device_credentials()

    # Retrieve the 'show interface brief' output
    brief_output = get_interface_output(device_host, username, password, device_type)

    if brief_output:
        while True: # Keep presenting the menu until 'q' is chosen
            print("\n--- Choose an Option ---")
            print("a) Generate a shutdown list")
            print("b) Get the current interface 'down only' list")
            print("q) Quit")
            choice = input("Enter your choice (a/b/q): ").lower()

            if choice == 'a':
                # Logic for generating shutdown commands
                interfaces_to_process = parse_interface_brief(brief_output)

                if interfaces_to_process:
                    consolidated_shutdown_commands = consolidate_and_generate_range_commands(interfaces_to_process)

                    print("\n--- Generated Interface Shutdown Commands (Consolidated) ---")
                    print("The following commands are for interfaces that meet the specified criteria for shutdown.")
                    print("*************************************************************************")
                    print("* WARNING: These commands will shut down active interfaces.             *")
                    print("*          Review them carefully before applying to a live network.     *")
                    print("*************************************************************************")
                    for command in consolidated_shutdown_commands:
                        print(command)
                else:
                    print("\nNo interfaces found that meet the criteria for shutdown.")
                # Removed 'break' here to loop back to the menu

            elif choice == 'b':
                # Logic for listing "down only" interfaces
                down_only_interfaces_list = get_down_only_interfaces(brief_output)
                if down_only_interfaces_list:
                    print("\n--- Interfaces in 'down/down' Operational State (Not Admin-Down) ---")
                    print("These interfaces are currently operationally down but not administratively shut down,")
                    print("and are not in the exclusion lists (BE, Lo, ti, Nu0, Mg0/RP0/CPU0/0).")
                    for iface in sorted(down_only_interfaces_list):
                        print(iface)
                else:
                    print("\nNo interfaces found in 'down/down' operational state (excluding admin-down and specified exclusions).")
                # Removed 'break' here to loop back to the menu

            elif choice == 'q':
                print("Exiting script.")
                break # Exit loop if user quits

            else:
                print("Invalid choice. Please enter 'a', 'b', or 'q'.")
    else:
        print("\nFailed to retrieve interface brief output. Cannot proceed.")