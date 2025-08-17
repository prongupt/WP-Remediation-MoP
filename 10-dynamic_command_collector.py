import time
import paramiko
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import os  # Import os module for file existence check


def ssh_and_get_outputs(hostname, username, password, commands):
    """
    Connects to a device via SSH and executes a list of commands,
    returning a dictionary of command outputs.
    """
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, username=username, password=password, timeout=10)
        outputs = {}
        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            if error:
                outputs[cmd] = f"Error: {error}"
            else:
                outputs[cmd] = output
        ssh.close()
        return {"device": hostname, "outputs": outputs}
    except Exception as e:
        return {"device": hostname, "error": str(e)}


def main():
    # --- Get User Input ---
    print("--- SSH Command Runner ---")

    hostnames = []
    while True:
        hostname_source = input(
            "How would you like to provide hostnames/IPs? (1) Enter directly (comma-separated), (2) Provide a file path, or (3) Paste list directly: ")

        if hostname_source == '1':
            hostnames_input = input("Enter hostnames/IPs (comma-separated, e.g., 192.168.1.1,device2.local): ")
            hostnames = [h.strip() for h in hostnames_input.split(',') if h.strip()]
            break
        elif hostname_source == '2':
            file_path = input("Enter the path to the file containing hostnames/IPs (one per line): ")
            if not os.path.exists(file_path):
                print(f"Error: File not found at '{file_path}'. Please try again.")
                continue
            try:
                with open(file_path, 'r') as f:
                    hostnames = [line.strip() for line in f if line.strip()]
                break
            except Exception as e:
                print(f"Error reading file: {e}. Please try again.")
                continue
        elif hostname_source == '3':
            print("Paste your list of hostnames/IPs below (one per line). Type 'END' on a new line when finished:")
            pasted_lines = []
            while True:
                line = input()
                if line.strip().upper() == 'END':
                    break
                pasted_lines.append(line)
            hostnames = [h.strip() for h in pasted_lines if h.strip()]
            break
        else:
            print("Invalid choice. Please enter '1', '2', or '3'.")

    if not hostnames:
        print("No hostnames/IPs provided. Exiting.")
        return

    # Get credentials
    username = input("Enter SSH username: ")
    password = input("Enter SSH password: ")

    # Get commands
    commands_input = input(
        "Enter commands to run (separate multiple commands with a semicolon ';' or a comma ',', e.g., show version;show ip int brief or show version,show ip int brief): ")

    # Normalize the input: replace all commas with semicolons
    normalized_commands_input = commands_input.replace(',', ';')

    # Split by semicolon to get individual commands
    commands = [c.strip() for c in normalized_commands_input.split(';') if c.strip()]

    if not commands:
        print("No commands provided. Exiting.")
        return

    # Construct devices list
    devices = []
    for h in hostnames:
        devices.append({"hostname": h, "username": username, "password": password})

    # --- Print Pre-execution Summary (Pretty Format) ---
    print("\n--- Execution Plan ---")
    print("Devices to connect to:")
    for device in devices:
        print(f"  - {device['hostname']} (User: {device['username']})")
    print("\nCommands to execute on each device:")
    for cmd in commands:
        print(f"  - '{cmd}'")
    print("-" * 30 + "\n")

    start_time = time.time()

    results_dict = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_device = {
            executor.submit(
                ssh_and_get_outputs,
                device["hostname"],
                device["username"],
                device["password"],
                commands,
            ): device["hostname"] for device in devices
        }
        for future in as_completed(future_to_device):
            hostname = future_to_device[future]
            results_dict[hostname] = future.result()

    # --- Prepare and Print Results ---
    print("\n--- Command Execution Results ---")

    for device_info in devices:
        hostname = device_info["hostname"]
        result = results_dict.get(hostname, {'device': hostname, 'error': 'No result'})

        print(f"\n--- Results for {hostname} ---")
        if 'error' in result:
            print(f"  Error: {result['error']}")
        else:
            for cmd in commands:  # Iterate through the original list of commands
                output_content = result['outputs'].get(cmd, "N/A (Command not found in output)")
                print(f"  Command: '{cmd}'")
                print(f"  Output:\n{output_content}\n")
        print("-" * (len(f"--- Results for {hostname} ---")))

    end_time = time.time()
    print(f"\nTotal execution time: {end_time - start_time:.2f} seconds")


if __name__ == "__main__":
    main()