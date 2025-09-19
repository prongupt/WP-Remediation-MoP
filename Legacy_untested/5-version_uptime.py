import time
import paramiko
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import getpass # Import getpass for secure password input

# Define the list of commands to be executed
commands = [
    "show version | i Label",
    "show version | i uptime"
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

def main():
    # --- User Input Section ---
    username = input("Enter SSH username: ")
    password = getpass.getpass("Enter SSH password: ") # Securely prompt for password

    print("\nPaste your list of hostnames or IP addresses below, one per line.")
    print("Press Enter twice when you are finished (i.e., an empty line):")

    host_lines = []
    while True:
        line = input()
        if not line: # Empty line signifies end of input
            break
        host_lines.append(line.strip())

    devices = []
    for host in host_lines:
        if host: # Ensure the line is not empty after stripping whitespace
            devices.append({
                "hostname": host,
                "username": username,
                "password": password
            })

    if not devices:
        print("No devices entered. Exiting.")
        return

    start_time = time.time()

    results_dict = {}
    # Using ThreadPoolExecutor to connect to devices concurrently
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_index = {
            executor.submit(
                ssh_and_get_outputs,
                device["hostname"],
                device["username"],
                device["password"],
                commands,
            ): idx for idx, device in enumerate(devices)
        }
        for future in as_completed(future_to_index):
            idx = future_to_index[future]
            results_dict[idx] = future.result()

    end_time = time.time()

    # Print the table header
    print(f"\n| {'Device':<30} | {'Label':<30} | {'Uptime':<40} |")
    # Corrected formatting for the separator line
    print(f"|{'-' * 32}|{'-' * 32}|{'-' * 42}|")

    # Iterate through the original devices list to ensure consistent order
    for idx, device in enumerate(devices):
        result = results_dict.get(idx, {'device': device['hostname'], 'error': 'No result'})
        device_name = result['device']
        if 'error' in result:
            label = uptime = f"Error: {result['error']}"
        else:
            outputs = result['outputs']
            label = extract_label(outputs.get(commands[0], ""))
            uptime = extract_uptime(outputs.get(commands[1], ""))
        print(f"| {device_name:<30} | {label:<30} | {uptime:<40} |")

    print(f"\nTotal execution time: {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    main()