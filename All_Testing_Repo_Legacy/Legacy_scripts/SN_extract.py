import time
import paramiko
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import getpass  # Import getpass for secure password input
from tabulate import tabulate  # Import tabulate for better table formatting
import socket  # Import socket for hostname resolution

# --- User Input for Devices ---
devices_input = []  # Store raw user input (identifier, username, password)
print("Enter device details. Type 'done' for identifier when you are finished.")
while True:
    # Prompt for either IP address or hostname
    identifier = input(
        "Enter IP address or hostname (e.g., 192.168.1.1 or router.example.com) (or 'done' to finish): ").strip()
    if identifier.lower() == 'done':
        break
    username = input(f"Enter username for {identifier}: ").strip()
    # Use getpass for secure password input to prevent password visibility
    password = getpass.getpass(f"Enter password for {identifier}: ").strip()
    devices_input.append({"identifier": identifier, "username": username, "password": password})

if not devices_input:
    print("No devices entered. Exiting.")
    exit()

# Only run "show inventory" as requested
commands = [
    "show inventory"
]


def ssh_and_get_outputs(ip, username, password, commands):
    """
    Connects to a device via SSH and executes commands, returning their outputs.
    Includes more specific error handling and ensures connection closure.
    """
    ssh = paramiko.SSHClient()
    # Using AutoAddPolicy for simplicity in a script, but for production,
    # consider using WarningPolicy and managing known_hosts for better security.
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    outputs = {}
    try:
        ssh.connect(ip, username=username, password=password, timeout=10)
        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            # Read stdout and stderr to prevent blocking if command output is large
            output = stdout.read().decode().strip()
            error_output = stderr.read().decode().strip()
            if error_output:
                outputs[cmd] = f"ERROR: {error_output}"  # Store stderr as error
            else:
                outputs[cmd] = output
    except paramiko.AuthenticationException:
        return {"error": "Authentication failed. Check username and password."}
    except paramiko.SSHException as e:
        return {"error": f"SSH connection error: {e}"}
    except Exception as e:  # Catch other potential network or general errors
        return {"error": f"An unexpected error occurred: {e}"}
    finally:
        if ssh:
            ssh.close()  # Ensure SSH connection is closed even if errors occur

    return outputs


def parse_inventory_details(output):
    """
    Parses the full 'show inventory' output to extract details for Line Cards (LC),
    Fabric Cards (FC), and Route Processors (RP), including their type, a unique identifier
    (like slot/FC/RP number), serial number (SN), and vendor ID (VID).
    Returns a list of dictionaries, where each dict represents a component.
    """
    components = []
    # Split the output into blocks based on 'NAME: ' to process each component
    blocks = re.split(r'NAME: ', output)

    for block in blocks:
        if not block.strip():
            continue  # Skip empty blocks

        comp_type = None
        comp_number = None  # This will store the slot/FC/RP number
        sn = 'N/A'
        vid = 'N/A'

        # Try to match Fabric Card (FC)
        fc_match = re.search(r'"0/FC(\d+)"', block)
        if fc_match:
            comp_type = 'FC'
            comp_number = fc_match.group(1)
        else:
            # Try to match Line Card (LC)
            lc_match = re.search(r'"0/(\d+)/CPU0"', block)
            if lc_match:
                # Exclude RPs which also match /CPU0 but have 'RP' in their name
                if "RP" not in block:
                    comp_type = 'LC'
                    comp_number = lc_match.group(1)

        # Try to match Route Processor (RP) - this should be distinct from LC
        rp_match = re.search(r'"0/RP(\d+)/CPU0"', block)
        if rp_match:
            comp_type = 'RP'
            comp_number = rp_match.group(1)

        # If a component type and number were identified
        if comp_type and comp_number is not None:  # comp_number can be '0'
            # Extract Serial Number (SN)
            ser_match = re.search(r'SN:\s*([\w-]+)', block)
            if ser_match:
                sn = ser_match.group(1)

            # Extract Vendor ID (VID)
            vid_match = re.search(r'VID:\s*([\w-]+)', block)
            if vid_match:
                vid = vid_match.group(1)

            components.append({
                'type': comp_type,
                'number': comp_number,  # Store the extracted number
                'SN': sn,
                'VID': vid
            })
    return components


start_time = time.time()
results = []  # Stores raw results from SSH connections
device_errors = []  # To store resolution or connection errors

# Prepare devices for concurrent processing, resolving hostnames to IPs
devices_for_processing = []
for dev_input in devices_input:
    identifier = dev_input["identifier"]
    resolved_ip = None
    try:
        # Simple check if the identifier looks like an IP address
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", identifier):
            resolved_ip = identifier
        else:
            # Attempt to resolve hostname to IP address
            resolved_ip = socket.gethostbyname(identifier)

        devices_for_processing.append({
            "original_identifier": identifier,  # Keep original input for display
            "ip": resolved_ip,  # Use resolved IP for connection
            "username": dev_input["username"],
            "password": dev_input["password"]
        })
    except socket.gaierror as e:
        device_errors.append(f"Error resolving '{identifier}': {e}")
    except Exception as e:
        device_errors.append(f"Unexpected error preparing '{identifier}': {e}")

# --- Concurrently connect to devices and get outputs ---
with ThreadPoolExecutor(max_workers=10) as executor:
    futures = []
    # Create a mapping from future to device for easier result processing
    future_to_device = {executor.submit(
        ssh_and_get_outputs,
        device["ip"],
        device["username"],
        device["password"],
        commands,
    ): device for device in devices_for_processing}

    for future in as_completed(future_to_device):
        device_info = future_to_device[future]  # This contains original_identifier, ip, username, password
        outputs = future.result()
        results.append({
            "original_identifier": device_info["original_identifier"],  # Use original identifier for results
            "outputs": outputs
        })

end_time = time.time()

# --- Prepare data for the split tables ---
all_parsed_components = []  # Stores dicts like {'hostname', 'type', 'number', 'SN', 'VID'}
# device_errors already populated with resolution errors, now add connection errors

for result in results:
    original_identifier = result["original_identifier"]
    outputs = result["outputs"]

    if isinstance(outputs, dict) and "error" in outputs:
        device_errors.append(f"Error connecting to {original_identifier}: {outputs['error']}")
        continue  # Skip to next device if connection error

    full_inventory_output = outputs.get(commands[0], "")
    components_found = parse_inventory_details(full_inventory_output)

    if components_found:
        for comp in components_found:
            all_parsed_components.append({
                'hostname': original_identifier,  # Use original identifier for display
                'type': comp['type'],
                'number': comp['number'],
                'SN': comp['SN'],
                'VID': comp['VID']
            })
    else:
        # If no components were found, but no connection error, it might be an empty inventory or parse issue
        all_parsed_components.append({
            'hostname': original_identifier,
            'type': 'N/A',
            'number': 'N/A',
            'SN': 'N/A',
            'VID': 'N/A'
        })

# Sort all components for consistent display across tables
all_parsed_components.sort(key=lambda x: (
    x['hostname'],
    {'FC': 0, 'LC': 1, 'RP': 2, 'N/A': 99}.get(x['type'], 99),  # Custom sort order for types
    int(x['number']) if str(x['number']).isdigit() else x['number'] if x['number'] != 'N/A' else 0
))

# Populate raw data for each table type
lc_table_raw = []
fc_table_raw = []
rp_table_raw = []
other_table_raw = []  # For 'N/A' or unclassified components

for comp in all_parsed_components:
    component_string = 'N/A'
    if comp['type'] == 'LC':
        component_string = f"LC{comp['number']}"
        lc_table_raw.append([comp['hostname'], component_string, comp['SN'], comp['VID']])
    elif comp['type'] == 'FC':
        component_string = f"FC{comp['number']}"
        fc_table_raw.append([comp['hostname'], component_string, comp['SN'], comp['VID']])
    elif comp['type'] == 'RP':
        component_string = f"RP{comp['number']}"
        rp_table_raw.append([comp['hostname'], component_string, comp['SN'], comp['VID']])
    else:
        # Handle cases where component type is 'N/A' or other unclassified types
        other_table_raw.append([comp['hostname'], comp['type'], comp['SN'], comp['VID']])


# Function to prepare table data for display, suppressing duplicate hostnames
def prepare_table_for_display(raw_data):
    processed_data = []
    current_hostname = None
    for row in raw_data:
        hostname = row[0]
        if hostname == current_hostname:
            processed_data.append([''] + row[1:])  # Replace hostname with empty string
        else:
            processed_data.append(row)
            current_hostname = hostname
    return processed_data


# Apply hostname suppression to each table's data
lc_table_display = prepare_table_for_display(lc_table_raw)
fc_table_display = prepare_table_for_display(fc_table_raw)
rp_table_display = prepare_table_for_display(rp_table_raw)
other_table_display = prepare_table_for_display(other_table_raw)

# Headers for the tables
headers = ['Hostname', 'Component', 'Serial Number', 'VID']


# Function to print a table using tabulate
def print_table_tabulate(title, data, headers):
    print(f"\n--- {title} ---")
    if not data:
        print("No data found.")
        return
    print(tabulate(data, headers=headers, tablefmt="grid"))  # "grid" is a clean format


# --- Print the tables ---
print("\n--- Hardware Inventory Summary ---")

# Print connection errors first
if device_errors:
    print("\n--- Device Connection/Processing Errors ---")
    for error_msg in device_errors:
        print(error_msg)

# Print specific component tables
print_table_tabulate("Hardware Inventory - Line Cards (LC)", lc_table_display, headers)
print_table_tabulate("Hardware Inventory - Fabric Cards (FC)", fc_table_display, headers)
print_table_tabulate("Hardware Inventory - Route Processors (RP)", rp_table_display, headers)

if other_table_display:
    print_table_tabulate("Hardware Inventory - Other Components", other_table_display, headers)

print(f"\nTotal execution time: {end_time - start_time:.2f} seconds")