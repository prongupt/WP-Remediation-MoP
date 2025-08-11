import time
import paramiko
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# List of devices with SSH details (same as before)
devices = [
    {"hostname": "10.29.88.73", "username": "cisco", "password": "cisco123"},
    # ... (other devices)
]

# List of commands to execute

commands = [
    "show version | i Label",
    "show version | i uptime",
    "show interface summary | i uptime"
]

def ssh_and_get_outputs(hostname, username, password, commands):
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
    match = re.search(r'Label\s*:\s*(.+)', output, re.IGNORECASE)
    return match.group(1).strip() if match else "N/A"

def extract_uptime(output):
    match = re.search(r'Uptime\s+is\s+(.+)', output, re.IGNORECASE)
    return match.group(1).strip() if match else "N/A"

def extract_if_summary(output):
    # Example extraction: you may need to adjust regex based on actual output format
    # For instance, extract the line containing 'uptime' or relevant summary info
    lines = output.splitlines()
    for line in lines:
        if 'uptime' in line.lower():
            return line.strip()
    return "N/A"

start_time = time.time()

results_dict = {}
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

# Prepare table header dynamically
header = ["Device", "Label", "Uptime", "I/F Summary"]
print(f"| {' | '.join(header)} |")
print(f"|{'|'.join(['-' * (len(h) + 2) for h in header])}|")

for idx, device in enumerate(devices):
    result = results_dict.get(idx, {'device': device['hostname'], 'error': 'No result'})
    device_name = result['device']
    if 'error' in result:
        row = [device_name] + [result['error']] * (len(header) - 1)
    else:
        outputs = result['outputs']
        label = extract_label(outputs.get(commands[0], ""))
        uptime = extract_uptime(outputs.get(commands[1], ""))
        if_summary = extract_if_summary(outputs.get(commands[2], ""))
        row = [device_name, label, uptime, if_summary]
    print(f"| {' | '.join(row)} |")

end_time = time.time()
print(f"Total execution time: {end_time - start_time:.2f} seconds")
