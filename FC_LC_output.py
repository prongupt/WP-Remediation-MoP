import time
import paramiko
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Device SSH details
devices = [
    {"hostname": "PHX10-0100-0100-01RHE", "ip": "10.29.88.73", "username": "cisco", "password": "cisco123"},
    {"hostname": "PHX10-0100-0100-02RHE", "ip": "10.195.143.192", "username": "cisco", "password": "cisco123"},
    {"hostname": "PHX10-0100-0100-03RHE", "ip": "10.195.143.112", "username": "cisco", "password": "cisco123"}
    # Add more devices...
]

commands = [
    "show inventory | utility egrep 0/FC -A1 -B1",
    "show inventory | utility egrep /CPU0 -A1 -B1"
]


def ssh_and_get_outputs(ip, username, password, commands):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=10)

        outputs = {}
        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            output = stdout.read().decode().strip()
            outputs[cmd] = output

        ssh.close()
        return outputs
    except Exception as e:
        return {"error": str(e)}


def extract_fc_values(output):
    """
    Returns a dict: {0: value_for_FC0, 1: value_for_FC1, ..., 7: value_for_FC7}
    Value is VID (if found), else Serial, else '1' if present, else blank.
    """
    fc_values = {}
    blocks = re.split(r'NAME: ', output)
    for block in blocks:
        fc_match = re.search(r'0/FC(\d+)', block)
        if fc_match:
            fc_num = int(fc_match.group(1))
            if 0 <= fc_num <= 7:
                vid_match = re.search(r'VID\s*:\s*([\w-]+)', block)
                ser_match = re.search(r'SN:\s*([\w-]+)', block)
                if vid_match:
                    fc_values[fc_num] = vid_match.group(1)
                elif ser_match:
                    fc_values[fc_num] = ser_match.group(1)
                else:
                    fc_values[fc_num] = '1'
    return fc_values


def extract_lc_values(output):
    """
    Returns a dict: {0: value_for_LC0, 1: value_for_LC1, ..., 17: value_for_LC17}
    Value is VID (if found), else Serial, else '1' if present, else blank.
    """
    lc_values = {}
    blocks = re.split(r'NAME: ', output)
    for block in blocks:
        lc_match = re.search(r'(\d+)/CPU0', block)
        if lc_match:
            lc_num = int(lc_match.group(1))
            if 0 <= lc_num <= 17: # This condition correctly allows up to LC17
                vid_match = re.search(r'VID\s*:\s*([\w-]+)', block)
                ser_match = re.search(r'SN:\s*([\w-]+)', block)
                if vid_match:
                    lc_values[lc_num] = vid_match.group(1)
                elif ser_match:
                    lc_values[lc_num] = ser_match.group(1)
                else:
                    lc_values[lc_num] = '1'
    return lc_values


def parse_rng_dc(hostname):
    rng = hostname[-3:]
    dc = hostname[:5]
    return rng, dc


start_time = time.time()
results = []

with ThreadPoolExecutor(max_workers=10) as executor:
    # Create a dictionary to map futures back to their original device data
    future_to_device = {executor.submit(
        ssh_and_get_outputs,
        device.get("ip", device["hostname"]), # Use hostname as IP if 'ip' key is missing
        device["username"],
        device["password"],
        commands,
    ): device for device in devices}

    for future in as_completed(future_to_device):
        # Correctly retrieve the device dictionary associated with this completed future
        device = future_to_device[future]
        outputs = future.result()
        results.append({
            "hostname": device["hostname"],
            "outputs": outputs
        })

end_time = time.time()

# Column settings for FC table
headers_fc = ['Hostname', 'RNG', 'DC'] + [f'FC{i}' for i in range(8)]
col_widths_fc = [28, 6, 8] + [7] * 8

# Column settings for LC table (updated to support up to LC17)
MAX_LC_INDEX = 17
headers_lc = ['Hostname', 'RNG', 'DC'] + [f'LC{i}' for i in range(MAX_LC_INDEX + 1)]
col_widths_lc = [28, 6, 8] + [7] * (MAX_LC_INDEX + 1)


# Print FC Table
print("\nFC Table")
header_row_fc = "".join(f"{h:<{w}}" for h, w in zip(headers_fc, col_widths_fc))
print(header_row_fc)
print("-" * sum(col_widths_fc))

for result in results:
    hostname = result["hostname"]
    rng, dc = parse_rng_dc(hostname)
    outputs = result["outputs"]
    if isinstance(outputs, dict) and "error" in outputs:
        row_items = [hostname, rng, dc] + ['ERROR'] * len([f'FC{i}' for i in range(8)])
    else:
        output = outputs.get(commands[0], "")
        fc_values = extract_fc_values(output)
        fc_cols = [str(fc_values.get(i, '')) for i in range(8)]
        row_items = [hostname, rng, dc] + fc_cols
    row = "".join(f"{item:<{w}}" for item, w in zip(row_items, col_widths_fc))
    print(row)

# Print LC Table
print("\nLC Table")
header_row_lc = "".join(f"{h:<{w}}" for h, w in zip(headers_lc, col_widths_lc))
print(header_row_lc)
print("-" * sum(col_widths_lc))

for result in results:
    hostname = result["hostname"]
    rng, dc = parse_rng_dc(hostname)
    outputs = result["outputs"]
    if isinstance(outputs, dict) and "error" in outputs:
        row_items = [hostname, rng, dc] + ['ERROR'] * len([f'LC{i}' for i in range(MAX_LC_INDEX + 1)])
    else:
        output = outputs.get(commands[1], "")
        lc_values = extract_lc_values(output)
        lc_cols = [str(lc_values.get(i, '')) for i in range(MAX_LC_INDEX + 1)]
        row_items = [hostname, rng, dc] + lc_cols
    row = "".join(f"{item:<{w}}" for item, w in zip(row_items, col_widths_lc))
    print(row)

print(f"\nTotal execution time: {end_time - start_time:.2f} seconds")