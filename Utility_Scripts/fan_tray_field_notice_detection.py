#!/usr/bin/env python3
"""
Fan Tray Field Notice Detection Scanner
Scans multiple Cisco devices for fan tray field notice conditions
"""

import sys
import os
import time
import getpass
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
import re
import paramiko
from prettytable import PrettyTable
import logging

# Disable paramiko logging to reduce noise
logging.getLogger("paramiko").setLevel(logging.WARNING)

# Configuration
SSH_TIMEOUT_SECONDS = 15
MAX_CONCURRENT_CONNECTIONS = 10  # Adjust based on your network capacity
DEVICE_TIMEOUT_SECONDS = 300  # 5 minutes per device
PROMPT_PATTERNS = [
    r'#\s*$',
    r'>\s*$',
    r'\]\s*$',
    r'\)\s*$'
]

# Fan tray field notice versions
FAN_IMPACTED_VERSIONS = {
    "8804-FAN": {"Not Impacted": ["V03"], "Impacted": ["V01", "V02"]},
    "8808-FAN": {"Not Impacted": ["V03"], "Impacted": ["V01", "V02"]},
    "8812-FAN": {"Not Impacted": ["V02"], "Impacted": ["V01"]},
    "8818-FAN": {"Not Impacted": ["V03"], "Impacted": ["V01", "V02"]},
}


@dataclass
class FanTrayIssue:
    device_name: str
    ft_location: str
    failure_condition: str
    pid_vid: str
    replacement_needed: bool


@dataclass
class DeviceResult:
    device_name: str
    success: bool
    fan_issues: List[FanTrayIssue]
    error_message: str = ""


class ProgressTracker:
    def __init__(self, total_devices):
        self.total_devices = total_devices
        self.completed = 0
        self.failed = 0
        self.lock = threading.Lock()

    def update(self, success=True):
        with self.lock:
            self.completed += 1
            if not success:
                self.failed += 1

            progress = (self.completed / self.total_devices) * 100
            print(f"\rProgress: {self.completed}/{self.total_devices} ({progress:.1f}%) - "
                  f"Failed: {self.failed}", end='', flush=True)


def read_and_print_realtime(shell_obj: paramiko.Channel, timeout_sec: int = 60) -> Tuple[str, bool]:
    """Read output from shell until prompt is found"""
    full_output_buffer = ""
    start_time = time.time()
    prompt_found = False
    prompt_check_buffer = ""

    while time.time() - start_time < timeout_sec:
        if shell_obj.recv_ready():
            try:
                data = shell_obj.recv(65535).decode('utf-8', errors='ignore')
                if data:
                    full_output_buffer += data
                    prompt_check_buffer += data
                    if len(prompt_check_buffer) > 500:
                        prompt_check_buffer = prompt_check_buffer[-500:]

                    lines = prompt_check_buffer.strip().splitlines()
                    if lines:
                        last_line = lines[-1]
                        for pattern in PROMPT_PATTERNS:
                            if re.search(pattern, last_line):
                                prompt_found = True
                                return full_output_buffer, prompt_found
            except Exception:
                break
        else:
            time.sleep(0.1)

    return full_output_buffer, prompt_found


def execute_command_in_shell(shell: paramiko.Channel, command: str, timeout: int = 60) -> str:
    """Execute command and return output"""
    # Pre-command buffer flush
    pre_flush_start_time = time.time()
    while time.time() - pre_flush_start_time < 0.5:
        if shell.recv_ready():
            shell.recv(65535).decode('utf-8', errors='ignore')
        else:
            break

    shell.send(command + "\n")
    time.sleep(0.5)
    output, prompt_found = read_and_print_realtime(shell, timeout_sec=timeout)

    if not prompt_found:
        shell.send("\n")
        output_retry, prompt_found_retry = read_and_print_realtime(shell, timeout_sec=5)
        output += output_retry
        prompt_found = prompt_found_retry

        if not prompt_found:
            raise Exception(f"Failed to reach prompt after command: {command}")

    return output


def connect_with_retry(client, router_ip, username, password, max_retries=3):
    """Retry SSH connection with increasing delays"""
    for attempt in range(max_retries):
        try:
            client.connect(
                router_ip,
                port=22,
                username=username,
                password=password,
                timeout=SSH_TIMEOUT_SECONDS,
                look_for_keys=False,
                allow_agent=False,
                banner_timeout=30,
                auth_timeout=30,
                disabled_algorithms={'keys': ['rsa-sha2-256', 'rsa-sha2-512']}
            )
            time.sleep(2)
            return True
        except Exception as e:
            if attempt < max_retries - 1:
                wait_time = (attempt + 1) * 2
                time.sleep(wait_time)
            else:
                raise e
    return False


def get_hostname(shell: paramiko.Channel) -> str:
    """Get hostname from device"""
    try:
        output = execute_command_in_shell(shell, "show running-config | i hostname", timeout=10)
        for line in output.splitlines():
            match = re.search(r"^\s*hostname\s+(\S+)", line)
            if match:
                hostname = match.group(1).replace('.', '-')
                return hostname
    except Exception:
        pass
    return "unknown_host"


def get_fan_tray_locations(shell: paramiko.Channel) -> List[str]:
    """Get fan tray locations from show platform"""
    try:
        output = execute_command_in_shell(shell, "show platform", timeout=60)
        ft_locations = []

        lines = output.splitlines()
        card_pattern = re.compile(r"^\s*(\S+)\s+(\S+)\s+(.+?)\s{2,}(\S+).*$")

        for line in lines:
            match = card_pattern.match(line)
            if match:
                location = match.group(1)
                if "FT" in location:
                    ft_locations.append(location)

        return ft_locations
    except Exception:
        return []


def parse_inventory_for_fan_trays(inventory_output: str) -> Dict[str, Dict[str, str]]:
    """Parse inventory output for fan tray information"""
    card_info = {}
    lines = inventory_output.splitlines()
    current_location = None

    for line in lines:
        name_match = re.search(r'NAME: "(\d+/FT\d+)",', line)
        if name_match:
            current_location = name_match.group(1)

        pid_vid_sn_match = re.search(r'PID:\s*([^,]+?)\s*,\s*VID:\s*([^,]+?)\s*,\s*SN:\s*(\S+)', line)
        if pid_vid_sn_match and current_location:
            card_info[current_location] = {
                "PID": pid_vid_sn_match.group(1).strip(),
                "VID": pid_vid_sn_match.group(2).strip(),
                "SN": pid_vid_sn_match.group(3).strip()
            }
            current_location = None

    return card_info


def check_fan_tray_field_notice(shell: paramiko.Channel, device_name: str) -> List[FanTrayIssue]:
    """Check fan tray field notice conditions for a device"""
    fan_issues = []

    try:
        # Get fan tray locations
        ft_locations = get_fan_tray_locations(shell)
        if not ft_locations:
            return fan_issues

        # Get inventory information
        inventory_output = execute_command_in_shell(shell, "show inventory | utility egrep 0/FT -A1 -B1", timeout=60)
        fan_inventory = parse_inventory_for_fan_trays(inventory_output)

        # Check for FT-specific active alarms
        ft_alarm_output = execute_command_in_shell(shell, "show alarms brief system active | i FT", timeout=60)
        ft_alarms_detected = []

        for line in ft_alarm_output.splitlines():
            stripped_line = line.strip()
            if not stripped_line or 'show alarms' in stripped_line or '#' in stripped_line:
                continue
            if any(keyword in stripped_line.lower() for keyword in
                   ['voltage', 'current', 'sensor', 'absent', 'input_vol', 'input_cur']):
                ft_alarms_detected.append(stripped_line)

        # Check each fan tray
        for ft_location in ft_locations:
            try:
                output = execute_command_in_shell(shell, f"show environment all location {ft_location}", timeout=60)

                issues = []
                field_notice_symptoms = []

                # Get PID/VID information
                fan_info = fan_inventory.get(ft_location, {})
                pid = fan_info.get("PID", "N/A")
                vid = fan_info.get("VID", "N/A")
                pid_vid = f"{pid}/{vid}"

                # Check if fan tray is missing
                missing_indicators = ["not present", "no such instance", "data not found", "absent"]
                if any(indicator in output.lower() for indicator in missing_indicators):
                    field_notice_symptoms.append("Missing Fan Tray")
                    issues.append("Fan Tray Missing")

                # Check voltage issues
                voltage_line_match = re.search(r'(?:Input_Vol|Input Voltage)\s+(\S+)', output)
                if voltage_line_match:
                    voltage_str = voltage_line_match.group(1).strip()
                    if voltage_str == "-":
                        field_notice_symptoms.append("Invalid Voltage Read")
                        issues.append("- Input Voltage")
                    else:
                        try:
                            input_voltage_mv = float(voltage_str)
                            input_voltage_volts = input_voltage_mv / 1000.0

                            if input_voltage_volts == 0:
                                field_notice_symptoms.append("0V Voltage")
                                issues.append("0V Input Voltage")
                            elif input_voltage_volts > 60:
                                field_notice_symptoms.append(f"High Voltage ({input_voltage_volts:.1f}V)")
                                issues.append(f"High Voltage ({input_voltage_volts:.1f}V)")
                            elif input_voltage_volts < 40:
                                field_notice_symptoms.append(f"Low Voltage ({input_voltage_volts:.1f}V)")
                                issues.append(f"Low Voltage ({input_voltage_volts:.1f}V)")
                        except ValueError:
                            field_notice_symptoms.append("Invalid Voltage Data")
                            issues.append("Invalid Voltage")

                # Check current issues
                current_line_match = re.search(r'(?:Input_Cur|Input Current)\s+(\S+)', output)
                if current_line_match:
                    current_str = current_line_match.group(1).strip()
                    if current_str == "-":
                        field_notice_symptoms.append("Invalid Current Read")
                        issues.append("- Input Current")
                    else:
                        try:
                            input_current_ma = float(current_str)
                            if input_current_ma == 0:
                                field_notice_symptoms.append("0A Current")
                                issues.append("0A Input Current")
                        except ValueError:
                            field_notice_symptoms.append("Invalid Current Data")
                            issues.append("Invalid Current")

                # Check Power Used status
                power_line_match = re.search(
                    r'^\s*' + re.escape(
                        ft_location) + r'\s+\S+\s+(\S+)\s+(\S+)\s+(ON|OFF|UNPOWERED|POWERED_OFF|SHUTDOWN)',
                    output, re.MULTILINE
                )
                if power_line_match:
                    power_used = power_line_match.group(2)
                    status = power_line_match.group(3)

                    if power_used == "-":
                        field_notice_symptoms.append("Power Used '-'")
                        issues.append("- Power Used")

                    if status != "ON":
                        issues.append(f"Status: {status}")

                # Determine if replacement is needed
                replacement_needed = False
                if pid in FAN_IMPACTED_VERSIONS:
                    impacted_versions = FAN_IMPACTED_VERSIONS[pid].get("Impacted", [])
                    if vid in impacted_versions and issues:
                        replacement_needed = True

                # Add to issues if problems found
                if issues:
                    failure_condition = "; ".join(issues[:2])  # Keep it brief, max 2 conditions
                    if len(issues) > 2:
                        failure_condition += f" (+{len(issues) - 2} more)"

                    fan_issues.append(FanTrayIssue(
                        device_name=device_name,
                        ft_location=ft_location,
                        failure_condition=failure_condition,
                        pid_vid=pid_vid,
                        replacement_needed=replacement_needed
                    ))

            except Exception as e:
                # If we can't check a specific fan tray, note it
                fan_issues.append(FanTrayIssue(
                    device_name=device_name,
                    ft_location=ft_location,
                    failure_condition=f"Check failed: {str(e)[:50]}",
                    pid_vid="N/A",
                    replacement_needed=False
                ))

    except Exception as e:
        # If we can't check fan trays at all, create a general error
        fan_issues.append(FanTrayIssue(
            device_name=device_name,
            ft_location="Unknown",
            failure_condition=f"Device check failed: {str(e)[:50]}",
            pid_vid="N/A",
            replacement_needed=False
        ))

    return fan_issues


def scan_device(device_ip: str, username: str, password: str, progress_tracker: ProgressTracker) -> DeviceResult:
    """Scan a single device for fan tray issues"""
    client = None
    shell = None
    device_name = device_ip  # Default to IP, will try to get hostname

    try:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect with timeout
        connect_with_retry(client, device_ip, username, password)

        shell = client.invoke_shell()
        time.sleep(1)
        read_and_print_realtime(shell, timeout_sec=2)

        # Configure terminal
        execute_command_in_shell(shell, "terminal length 0", timeout=5)
        execute_command_in_shell(shell, "terminal width 511", timeout=5)

        # Get hostname
        try:
            device_name = get_hostname(shell)
        except:
            device_name = device_ip

        # Check fan trays
        fan_issues = check_fan_tray_field_notice(shell, device_name)

        progress_tracker.update(success=True)
        return DeviceResult(
            device_name=device_name,
            success=True,
            fan_issues=fan_issues
        )

    except Exception as e:
        progress_tracker.update(success=False)
        return DeviceResult(
            device_name=device_name,
            success=False,
            fan_issues=[],
            error_message=str(e)
        )

    finally:
        if shell:
            try:
                shell.send("exit\n")
                time.sleep(1)
                shell.close()
            except:
                pass
        if client:
            try:
                client.close()
            except:
                pass


def read_device_list() -> List[str]:
    """Read device list from user input"""
    print("Enter device hostnames/IP addresses (one per line).")
    print("Enter 'DONE' when finished, or provide a filename with 'FILE:filename.txt':")

    devices = []
    while True:
        line = input().strip()
        if line.upper() == 'DONE':
            break
        elif line.upper().startswith('FILE:'):
            filename = line[5:].strip()
            try:
                with open(filename, 'r') as f:
                    file_devices = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
                    devices.extend(file_devices)
                    print(f"Loaded {len(file_devices)} devices from {filename}")
            except FileNotFoundError:
                print(f"File {filename} not found. Please try again.")
            except Exception as e:
                print(f"Error reading file {filename}: {e}")
        elif line:
            devices.append(line)

    return devices


def main():
    print("=" * 60)
    print("Fan Tray Field Notice Detection Scanner")
    print("=" * 60)

    # Get device list
    devices = read_device_list()
    if not devices:
        print("No devices provided. Exiting.")
        return

    print(f"\nTotal devices to scan: {len(devices)}")

    # Get credentials
    username = input("Enter SSH username: ")
    password = getpass.getpass("Enter SSH password: ")

    print(f"\nStarting scan of {len(devices)} devices...")
    print(f"Using {MAX_CONCURRENT_CONNECTIONS} concurrent connections")
    print(f"Device timeout: {DEVICE_TIMEOUT_SECONDS} seconds")

    # Initialize progress tracker
    progress_tracker = ProgressTracker(len(devices))

    # Scan devices concurrently
    results = []
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_CONNECTIONS) as executor:
        # Submit all jobs
        future_to_device = {
            executor.submit(scan_device, device, username, password, progress_tracker): device
            for device in devices
        }

        # Collect results as they complete
        for future in as_completed(future_to_device, timeout=DEVICE_TIMEOUT_SECONDS * len(devices)):
            device = future_to_device[future]
            try:
                result = future.result(timeout=DEVICE_TIMEOUT_SECONDS)
                results.append(result)
            except Exception as e:
                progress_tracker.update(success=False)
                results.append(DeviceResult(
                    device_name=device,
                    success=False,
                    fan_issues=[],
                    error_message=f"Timeout or error: {str(e)}"
                ))

    print()  # New line after progress

    # Process results
    total_time = time.time() - start_time
    successful_scans = sum(1 for r in results if r.success)
    failed_scans = len(results) - successful_scans
    # Count how many successful scans actually found hardware issues
    devices_with_issues = sum(1 for r in results if r.success and len(r.fan_issues) > 0)

    # Collect all fan issues that need replacement
    replacement_needed = []
    all_issues = []

    for result in results:
        if result.success:
            for issue in result.fan_issues:
                all_issues.append(issue)
                if issue.replacement_needed:
                    replacement_needed.append(issue)

    # Print summary
    print(f"\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    print(f"Total devices scanned: {len(devices)}")
    print(f"Successful scans: {successful_scans}")
    print(f"Failed scans: {failed_scans}")
    print(f"Total scan time: {total_time:.1f} seconds")
    print(f"Average time per device: {total_time / len(devices):.1f} seconds")

    # Print fan tray issues requiring replacement
    if replacement_needed:
        print(f"\n" + "=" * 80)
        print("FAN TRAYS REQUIRING REPLACEMENT (Field Notice Impacted)")
        print("=" * 80)

        replacement_table = PrettyTable()
        replacement_table.field_names = ["Device Name", "Failed FT", "Failure Condition", "PID/VID"]
        replacement_table.align = "l"

        for issue in replacement_needed:
            replacement_table.add_row([
                issue.device_name,
                issue.ft_location,
                issue.failure_condition,
                issue.pid_vid
            ])

        print(replacement_table)
    else:
        print(f"\n✅ No fan trays requiring immediate replacement found!")

    # Print all fan tray issues (including non-critical)
    if all_issues:
        print(f"\n" + "=" * 80)
        print("ALL FAN TRAY ISSUES DETECTED")
        print("=" * 80)

        all_issues_table = PrettyTable()
        all_issues_table.field_names = ["Device Name", "Failed FT", "Failure Condition", "PID/VID", "Replace?"]
        all_issues_table.align = "l"

        for issue in all_issues:
            replace_status = "YES" if issue.replacement_needed else "Monitor"
            all_issues_table.add_row([
                issue.device_name,
                issue.ft_location,
                issue.failure_condition,
                issue.pid_vid,
                replace_status
            ])

        print(all_issues_table)

    # Print failed device scans
    failed_devices = [r for r in results if not r.success]
    if failed_devices:
        print(f"\n" + "=" * 60)
        print("FAILED DEVICE SCANS")
        print("=" * 60)

        failed_table = PrettyTable()
        failed_table.field_names = ["Device", "Error Message"]
        failed_table.align = "l"

        for device in failed_devices:
            error_msg = device.error_message[:60] + "..." if len(device.error_message) > 60 else device.error_message
            failed_table.add_row([device.device_name, error_msg])

        print(failed_table)

    print(f"\nScan completed!")


if __name__ == "__main__":
    main()