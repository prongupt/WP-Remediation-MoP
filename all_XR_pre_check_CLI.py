import paramiko
import time
import getpass
import re
import logging
from prettytable import PrettyTable
import platform
import subprocess
import datetime
import os
import sys  # Import sys module
from typing import List, Tuple, Dict, Any, Optional # Added Optional

# Set logger level to DEBUG for detailed parsing logs
logger = logging.getLogger()
logger.setLevel(logging.INFO)
# Initial cleanup of handlers to ensure a clean slate, especially if run multiple times
if logger.handlers:
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()

SSH_TIMEOUT_SECONDS = 15

PROMPT_PATTERNS = [
    r'#\s*$',
    r'>\s*$',  # Add for privilege mode if applicable
]

FAN_IMPACTED_VERSIONS = {
    "8804-FAN": {"Not Impacted": ["V03"], "Impacted": ["V01", "V02"]},
    "8808-FAN": {"Not Impacted": ["V03"], "Impacted": ["V01", "V02"]},
    "8812-FAN": {"Not Impacted": ["V02"], "Impacted": ["V01"]},
    "8818-FAN": {"Not Impacted": ["V03"], "Impacted": ["V01", "V02"]},
}


class SSHConnectionError(Exception):
    pass


class RouterCommandError(Exception):
    pass


class PlatformStatusError(Exception):
    pass


class FabricReachabilityError(Exception):
    pass


class FabricLinkDownError(Exception):
    pass


class NpuLinkError(Exception):
    pass


class NpuStatsError(Exception):
    pass


class NpuDriverError(Exception):
    pass


class FabricPlaneStatsError(Exception):
    pass


class AsicErrorsError(Exception):
    pass


class InterfaceStatusError(Exception):
    pass


class AlarmError(Exception):
    pass


class LcAsicErrorsError(Exception):
    pass


class FanTrayError(Exception):
    pass


class EnvironmentError(Exception):
    pass


# New: Custom stream to redirect stdout to both console and a file
class Tee:
    def __init__(self, stdout, file_object):
        self.stdout = stdout
        self.file_object = file_object

    def write(self, data):
        self.stdout.write(data)
        self.file_object.write(data)

    def flush(self):
        self.stdout.flush()
        self.file_object.flush()


def read_and_print_realtime(shell_obj: paramiko.Channel, timeout_sec: int = 60, print_real_time: bool = True) -> Tuple[
    str, bool]:
    full_output_buffer = ""
    start_time = time.time()
    prompt_found = False
    prompt_check_buffer = ""
    while time.time() - start_time < timeout_sec:
        if shell_obj.recv_ready():
            try:
                data = shell_obj.recv(65535).decode('utf-8', errors='ignore')
                if data:
                    if print_real_time:
                        print(f"{data}", end='')
                    full_output_buffer += data
                    prompt_check_buffer += data
                    # Keep only the last 500 characters to check for prompt efficiently
                    if len(prompt_check_buffer) > 500:
                        prompt_check_buffer = prompt_check_buffer[-500:]
                    lines = prompt_check_buffer.strip().splitlines()
                    if lines:
                        last_line = lines[-1]
                        for pattern in PROMPT_PATTERNS:
                            if re.search(pattern, last_line):
                                prompt_found = True
                                if print_real_time and not data.endswith('\n'):
                                    print()
                                return full_output_buffer, prompt_found
            except Exception as e:
                logger.error(f"Error receiving data: {e}")
                break
        else:
            time.sleep(0.1)
    if print_real_time and full_output_buffer and not full_output_buffer.endswith('\n'):
        print()
    return full_output_buffer, prompt_found


def execute_command_in_shell(shell: paramiko.Channel, command: str, command_description: str,
                             timeout: int = 30, print_real_time_output: bool = True, cli_output_file=None) -> str:
    logger.info(f"Sending '{command_description}'...")
    if cli_output_file:
        cli_output_file.write(f"\n--- Command: {command} ---\n")
        cli_output_file.flush()
    shell.send(command + "\n")
    output, prompt_found = read_and_print_realtime(shell, timeout_sec=timeout, print_real_time=print_real_time_output)
    if cli_output_file:
        cli_output_file.write(output)
        cli_output_file.flush()
    if not prompt_found:
        logger.warning(f"Prompt not detected after '{command_description}'. Attempting to send newline and re-check.")
        shell.send("\n")
        output_retry, prompt_found_retry = read_and_print_realtime(shell, timeout_sec=5,
                                                                   print_real_time=print_real_time_output)
        if cli_output_file:
            cli_output_file.write(output_retry)
            cli_output_file.flush()
        output += output_retry
        prompt_found = prompt_found_retry
        if not prompt_found:
            raise RouterCommandError(
                f"Failed to reach prompt after '{command_description}' re-check. Output: {output}")
    return output


def get_hostname(shell: paramiko.Channel, cli_output_file=None) -> str:
    logger.info("Attempting to retrieve hostname using 'show running-config | i hostname'...")
    output = execute_command_in_shell(shell, "show running-config | i hostname", "get hostname", timeout=10,
                                      print_real_time_output=False, cli_output_file=cli_output_file)
    for line in output.splitlines():
        match = re.search(r"^\s*hostname\s+(\S+)", line)
        if match:
            hostname = match.group(1)
            # First, replace dots with hyphens as explicitly requested for file names
            hostname = hostname.replace('.', '-')
            # Then, sanitize further by removing any other characters not suitable for filenames
            hostname = re.sub(r'[^a-zA-Z0-9_-]', '', hostname)
            logger.info(f"Hostname detected: {hostname}")
            return hostname
    logger.warning("Could not parse hostname from 'show running-config | i hostname' output. Using 'unknown_host'.")
    return "unknown_host"


def parse_inventory_for_serial_numbers(inventory_output: str) -> Dict[str, Dict[str, str]]:
    card_info = {}
    lines = inventory_output.splitlines()
    current_location = None
    for line in lines:
        name_match = re.search(r'NAME: "(\d+/\S+)",', line)
        if name_match:
            current_location = name_match.group(1)
        pid_vid_sn_match = re.search(r'PID: (\S+)\s*,\s*VID: (\S+),\s*SN: (\S+)', line)
        if pid_vid_sn_match and current_location:
            card_info[current_location] = {
                "PID": pid_vid_sn_match.group(1),
                "VID": pid_vid_sn_match.group(2),
                "SN": pid_vid_sn_match.group(3)
            }
            current_location = None
    return card_info


# Continue from Part 1

def check_fabric_reachability(shell: paramiko.Channel, cli_output_file=None):
    logger.info(f"Checking Fabric Reachability (show controller fabric fsdb-pla rack 0)...")
    fabric_output = execute_command_in_shell(shell, "show controller fabric fsdb-pla rack 0",
                                             "show controller fabric fsdb-pla rack 0", timeout=120,
                                             print_real_time_output=False, cli_output_file=cli_output_file)
    problematic_fabric_rows = []
    header_separator_found = False
    lines = fabric_output.splitlines()
    for line in lines:
        if "----------------------------------------------------------------------------------------------" in line:
            header_separator_found = True
            continue
        if header_separator_found:
            if not line.strip() or re.match(r'Mon\s+\w+\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+',
                                            line.strip()) or re.match(r'RP/\d+/\S+#', line.strip()):
                continue
            parts = line.split()
            if len(parts) >= 12:
                reach_mask_value = parts[9]
                if reach_mask_value not in ["4/4", "2/2"]:
                    if reach_mask_value != "----":
                        problematic_fabric_rows.append([
                            parts[0], parts[1], parts[2], parts[3], parts[4],
                            parts[5], parts[6], parts[7], parts[8],
                            parts[9], parts[11]
                        ])
    if problematic_fabric_rows:
        logger.error(f"!!! FABRIC REACHABILITY ERRORS DETECTED !!!")
        fabric_table = PrettyTable()
        fabric_table.field_names = ["Destination Address", "p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7",
                                    "Reach-mask links/asic", "Oper Up links/asic"]
        for row in problematic_fabric_rows:
            fabric_table.add_row(row)
        print(fabric_table)
        raise FabricReachabilityError("Fabric reachability check failed. Unexpected Reach-mask values detected.")
    else:
        logger.info(f"Fabric Reachability check passed. No issues detected.")


def check_fabric_link_down_status(shell: paramiko.Channel, cli_output_file=None):
    logger.info(f"Checking Fabric Link Down Status...")
    commands_and_descriptions = {
        "show controller fabric link port s1 rx down": "Fabric S1 RX Down Links",
        "show controller fabric link port fia rx down": "Fabric FIA RX Down Links"
    }
    all_down_links_found = []
    for command, description in commands_and_descriptions.items():
        output = execute_command_in_shell(shell, command, description, timeout=60, print_real_time_output=False,
                                          cli_output_file=cli_output_file)
        if "s1 rx down" in command:
            link_pattern = re.compile(r'^\s*(\S+)\s+(\S+)\s+(?:NA\s+){4}(\S+)\s*$')
            headers = ["Interface", "Admin/Oper State", "Other End"]
        elif "fia rx down" in command:
            link_pattern = re.compile(r'^\s*(\S+)\s+(\S+)\s+(\S+)\s*$', re.MULTILINE)
            headers = ["Interface", "Admin/Oper State", "Other End"]
        else:
            logger.warning(f"Unknown command for parsing fabric link down status: {command}")
            continue
        lines = output.splitlines()
        for line in lines:
            stripped_line = line.strip()
            if not stripped_line: continue
            if re.match(r'^\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+$', stripped_line): continue
            if re.match(r'^RP/\d+/\S+:\S+#', stripped_line): continue
            if re.escape(command.strip()) in re.escape(stripped_line): continue
            if re.match(r'Description:', stripped_line) or \
                    re.match(r'R/S/A/P\s+-\s+Rack/Slot/Asic/Port', stripped_line) or \
                    re.match(r'DN\s+-\s+Down,\s+NA\s+-\s+Not Available/Applicable', stripped_line) or \
                    re.match(r'SFE port\s+Admin\s+Retimer RX', stripped_line) or \
                    re.match(r'R/S/A/P\s+/Oper\s+R/I/P', stripped_line) or \
                    re.match(r'FIA Port\s+Admin\s+Other End', stripped_line) or \
                    re.match(r'----------------+', stripped_line) or \
                    re.match(r'R/S/A/P\s+/Oper\s+R/S/A/P', stripped_line): continue
            match = link_pattern.match(stripped_line)
            if match:
                all_down_links_found.append({
                    "Interface": match.group(1),
                    "Admin/Oper State": match.group(2),
                    "Other End": match.group(3)
                })
    if all_down_links_found:
        logger.error(f"!!! FABRIC LINK DOWN STATUS ERRORS DETECTED !!!")
        link_down_table = PrettyTable()
        link_down_table.field_names = headers
        for link_info in all_down_links_found:
            link_down_table.add_row([link_info["Interface"], link_info["Admin/Oper State"], link_info["Other End"]])
        print(link_down_table)
        raise FabricLinkDownError("Fabric link down status check failed. Down links reported.")
    else:
        logger.info(f"Fabric Link Down Status check passed. No issues detected.")


def check_npu_link_info(shell: paramiko.Channel, cli_output_file=None):
    logger.info(f"Checking NPU Link Information...")
    command = r'show controllers npu link-info rx 0 255 topo instance all location all | ex "EN/UP" | ex "NC              NC"'
    output = execute_command_in_shell(shell, command, "show controllers npu link-info", timeout=180,
                                      print_real_time_output=False, cli_output_file=cli_output_file)
    problematic_links = []
    lines = output.splitlines()
    location_pattern = re.compile(r'^\d+/\S+/\d+/\d+$')
    for line in lines:
        stripped_line = line.strip()
        if not stripped_line: continue
        if re.match(r'^\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+$', stripped_line): continue
        if re.match(r'^RP/\d+/\S+:\S+#$', stripped_line): continue
        if re.escape(command.strip()) in re.escape(stripped_line): continue
        if re.match(r'^Node ID: (\S+)$', stripped_line): continue
        if re.match(r'^-+$', stripped_line): continue
        if re.match(r'^Link ID\s+Log\s+Link\s+Asic', stripped_line): continue
        parts = stripped_line.split()
        if len(parts) >= 7:
            link_id = parts[0]
            far_end_link_fsdb = parts[6]
            if location_pattern.match(link_id) and location_pattern.match(far_end_link_fsdb):
                problematic_links.append({
                    "Link ID": link_id,
                    "Far-End Link (FSDB)": far_end_link_fsdb
                })
    if problematic_links:
        logger.error(f"!!! NPU LINK ERRORS DETECTED !!!")
        npu_table = PrettyTable()
        npu_table.field_names = ["Link ID", "Far-End Link (FSDB)"]
        for link in problematic_links:
            npu_table.add_row([link["Link ID"], link["Far-End Link (FSDB)"]])
        print(npu_table)
        raise NpuLinkError("NPU link info check failed. Links are reported as down.")
    else:
        logger.info(f"NPU Link Information check passed. No down links reported.")


def check_npu_stats_link(shell: paramiko.Channel, cli_output_file=None):
    logger.info(f"Checking NPU Stats Link for UCE/CRC Errors...")
    command = r'show controllers npu stats link all instance all location all | ex "0        0        0"'
    output = execute_command_in_shell(shell, command, "show controllers npu stats link", timeout=180,
                                      print_real_time_output=False, cli_output_file=cli_output_file)
    problematic_stats = []
    current_node_id = None
    lines = output.splitlines()
    for i, line in enumerate(lines):
        stripped_line = line.strip()
        if not stripped_line: continue
        if re.match(r'^\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+$', stripped_line) or \
                re.match(r'^RP/\d+/\S+:\S+#$', stripped_line) or \
                re.escape(command.strip()) in re.escape(stripped_line) or \
                re.match(r'^-+$', stripped_line) or \
                re.match(r'^In Data\s+Out Data\s+CE\s+UCE\s+CRC$', stripped_line): continue
        node_id_match = re.match(r'^Node ID: (\S+)$', stripped_line)
        if node_id_match:
            current_node_id = node_id_match.group(1)
            continue
        numbers = re.findall(r'\d+', stripped_line)
        if len(numbers) >= 5:
            try:
                uce_errors = int(numbers[-2])
                crc_errors = int(numbers[-1])
                if uce_errors > 0 or crc_errors > 0:
                    if current_node_id:
                        problematic_stats.append({
                            "Node ID": current_node_id,
                            "UCE Errors": uce_errors,
                            "CRC Errors": crc_errors
                        })
            except ValueError:
                pass
    if problematic_stats:
        logger.error(f"!!! NPU STATS ERRORS DETECTED (UCE/CRC) !!!")
        stats_table = PrettyTable()
        stats_table.field_names = ["Node ID", "UCE Errors", "CRC Errors"]
        for stat in problematic_stats:
            stats_table.add_row([stat["Node ID"], stat["UCE Errors"], stat["CRC Errors"]])
        print(stats_table)
        raise NpuStatsError("NPU stats link check failed. Non-zero UCE or CRC errors detected.")
    else:
        logger.info(f"NPU Stats Link check passed. No non-zero UCE or CRC errors detected.")


def check_npu_driver_status(shell: paramiko.Channel, cli_output_file=None):
    logger.info(f"Checking NPU Driver Status (Asic states)...")
    command = "show controllers npu driver location 0/RP0/CPU0"
    output = execute_command_in_shell(shell, command, "show controllers npu driver", timeout=120,
                                      print_real_time_output=False, cli_output_file=cli_output_file)
    problematic_asics = []
    asics_table_header_separator = "+------------------------------------------------------------------------------+"
    asics_table_end_marker = "SI Info :"
    parsing_asics_table_data = False
    header_separator_count = 0
    lines = output.splitlines()
    for line in lines:
        stripped_line = line.strip()
        if asics_table_end_marker in stripped_line:
            parsing_asics_table_data = False
            break
        if asics_table_header_separator in stripped_line:
            header_separator_count += 1
            if header_separator_count == 2:
                parsing_asics_table_data = True
                continue
        if parsing_asics_table_data:
            if not stripped_line or re.match(r'^\+---', stripped_line): continue
            parts = [p.strip() for p in stripped_line.split('|')]
            if not re.match(r'^\d+/\S+/\d+$', parts[1]): continue
            if len(parts) >= 13:
                asic_instance = parts[1]
                slice_state = parts[4]
                admin_state = parts[6]
                oper_state = parts[7]
                asic_state = parts[8]
                expected_slice_state = "UP"
                expected_admin_state = "UP"
                expected_oper_state = "UP"
                expected_asic_state = "NRML"
                current_asic_issues = []
                if slice_state != expected_slice_state: current_asic_issues.append(
                    f"Slice state: {slice_state} (Expected: {expected_slice_state})")
                if admin_state != expected_admin_state: current_asic_issues.append(
                    f"Admin state: {admin_state} (Expected: {expected_admin_state})")
                if oper_state != expected_oper_state: current_asic_issues.append(
                    f"Oper state: {oper_state} (Expected: {expected_oper_state})")
                if asic_state != expected_asic_state: current_asic_issues.append(
                    f"Asic state: {asic_state} (Expected: {expected_asic_state})")
                if current_asic_issues:
                    problematic_asics.append({
                        "Asic Instance": asic_instance,
                        "Issues": ", ".join(current_asic_issues)
                    })
    if problematic_asics:
        logger.error(f"!!! NPU DRIVER STATUS ERRORS DETECTED (Asic states) !!!")
        npu_driver_table = PrettyTable()
        npu_driver_table.field_names = ["Asic Instance", "Problematic States"]
        for asic in problematic_asics:
            npu_driver_table.add_row([asic["Asic Instance"], asic["Issues"]])
        print(npu_driver_table)
        raise NpuDriverError("NPU driver status check failed. Asic states are not as expected.")
    else:
        logger.info(f"NPU Driver Status check passed. All Asic states are as expected.")


def check_fabric_plane_stats(shell: paramiko.Channel, cli_output_file=None):
    logger.info(f"Checking Fabric Plane Statistics (CE/UCE/PE Packets)...")
    command = "show controllers fabric plane all statistics"
    output = execute_command_in_shell(shell, command, "show controllers fabric plane all statistics", timeout=120,
                                      print_real_time_output=False, cli_output_file=cli_output_file)
    problematic_planes = []
    data_start_marker = "--------------------------------------------------------------------------------"
    parsing_data = False
    lines = output.splitlines()
    for line in lines:
        stripped_line = line.strip()
        if data_start_marker in stripped_line:
            parsing_data = True
            continue
        if parsing_data:
            if not stripped_line or re.match(r'Mon\s+\w+\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+',
                                             stripped_line) or re.match(r'RP/\d+/\S+#', stripped_line):
                continue
            parts = stripped_line.split()
            if len(parts) >= 6:
                try:
                    plane_id = parts[0]
                    ce_packets = int(parts[3])
                    uce_packets = int(parts[4])
                    pe_packets = int(parts[5])
                    if ce_packets > 0 or uce_packets > 0 or pe_packets > 0:
                        problematic_planes.append({
                            "Plane ID": plane_id,
                            "CE Packets": ce_packets,
                            "UCE Packets": uce_packets,
                            "PE Packets": pe_packets
                        })
                except ValueError:
                    pass
    if problematic_planes:
        logger.error(f"!!! FABRIC PLANE STATISTICS ERRORS DETECTED (Non-zero CE/UCE/PE Packets) !!!")
        stats_table = PrettyTable()
        stats_table.field_names = ["Plane ID", "CE Packets", "UCE Packets", "PE Packets"]
        for plane in problematic_planes:
            stats_table.add_row([plane["Plane ID"], plane["CE Packets"], plane["UCE Packets"], plane["PE Packets"]])
        print(stats_table)
        raise FabricPlaneStatsError("Fabric plane statistics check failed. Non-zero CE/UCE/PE packets detected.")
    else:
        logger.info(f"Fabric Plane Statistics check passed. No non-zero CE, UCE, or PE packets detected.")


def check_asic_errors(shell: paramiko.Channel, cli_output_file=None):
    logger.info(f"Checking ASIC Errors (rx_link_status_down, count, npu[])...")
    command = r'show asic-errors all detail location 0/RP0/CPU0 | inc "rx_link_status_down|count|npu\\["'
    output = execute_command_in_shell(shell, command, "show asic-errors", timeout=120, print_real_time_output=False,
                                      cli_output_file=cli_output_file)
    problematic_asic_errors = []
    current_fc_location = None
    current_npu_number = None
    lines = output.splitlines()
    for i, line in enumerate(lines):
        stripped_line = line.strip()
        if not stripped_line: continue
        if re.match(r'^\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+$', stripped_line) or \
                re.match(r'^RP/\d+/\S+:\S+#$', stripped_line) or \
                re.escape(command.strip()) in re.escape(stripped_line): continue
        npu_info_match = re.match(r'^\s*\d+,\s*\S+,\s*(\d+/\S+),\s*npu\[(\d+)\]', stripped_line)
        error_count_match = re.search(r'Error count\s*:\s*(\d+)', stripped_line)
        if npu_info_match:
            current_fc_location = npu_info_match.group(1)
            current_npu_number = npu_info_match.group(2)
            continue
        if error_count_match and current_fc_location and current_npu_number:
            error_count = int(error_count_match.group(1))
            if error_count > 0:
                problematic_asic_errors.append({
                    "FC Location": current_fc_location,
                    "NPU number": current_npu_number,
                    "Error count": error_count
                })
            current_fc_location = None
            current_npu_number = None
            continue
        if re.search(r'Name\s*:', stripped_line) and current_fc_location and current_npu_number: continue
    if problematic_asic_errors:
        logger.error(f"!!! ASIC ERRORS DETECTED (Non-zero Error Counts) !!!")
        asic_error_table = PrettyTable()
        asic_error_table.field_names = ["FC Location", "NPU number", "Error count"]
        for item in problematic_asic_errors:
            asic_error_table.add_row([item["FC Location"], item["NPU number"], item["Error count"]])
        print(asic_error_table)
        raise AsicErrorsError("ASIC errors check failed. Non-zero error counts detected.")
    else:
        logger.info(f"ASIC Errors check passed. No non-zero error counts detected.")


def run_show_inventory(shell: paramiko.Channel, cli_output_file=None):
    logger.info(f"Running show inventory (output captured silently)...")
    execute_command_in_shell(shell, "show inventory", "show inventory", timeout=120,
                             print_real_time_output=False, cli_output_file=cli_output_file)
    logger.info("show inventory command executed and output captured.")


def check_interface_status(shell: paramiko.Channel, cli_output_file=None):
    logger.info(f"Checking Interface Status...")
    summary_output = execute_command_in_shell(shell, "show interface summary", "show interface summary", timeout=60,
                                              print_real_time_output=False, cli_output_file=cli_output_file)
    all_types_data = None
    lines = summary_output.splitlines()
    for line in lines:
        stripped_line = line.strip()
        if stripped_line.startswith("ALL TYPES"):
            parts = stripped_line.split()
            if len(parts) >= 6:
                try:
                    all_types_data = {
                        "Total": int(parts[2]),
                        "UP": int(parts[3]),
                        "Down": int(parts[4]),
                        "Admin Down": int(parts[5])
                    }
                    break
                except ValueError:
                    pass
    if all_types_data:
        print(f"Interface Summary (ALL TYPES):")
        summary_table = PrettyTable()
        summary_table.field_names = ["Total", "UP", "Down", "Admin Down"]
        summary_table.add_row([
            all_types_data["Total"],
            all_types_data["UP"],
            all_types_data["Down"],
            all_types_data["Admin Down"]
        ])
        print(summary_table)
        logger.info(f"Interface summary for ALL TYPES successfully retrieved.")
    else:
        logger.error(f"!!! INTERFACE STATUS ERROR !!!")
        logger.error(f" - Could not find or parse 'ALL TYPES' row in 'show interface summary'.")
        raise InterfaceStatusError("Interface summary for ALL TYPES could not be retrieved.")
    execute_command_in_shell(shell, "show interface brief", "show interface brief", timeout=120,
                             print_real_time_output=False, cli_output_file=cli_output_file)
    logger.info("show interface brief executed silently.")
    execute_command_in_shell(shell, "show interface description | ex admin",
                             "show interface description (excluding admin)", timeout=120, print_real_time_output=False,
                             cli_output_file=cli_output_file)
    logger.info("show interface description | ex admin executed silently.")


def check_and_capture_alarms_and_logs(shell: paramiko.Channel, cli_output_file=None):
    logger.info(f"Checking Alarms and Capturing Install Logs...")
    execute_command_in_shell(shell, "show alarms brief system", "show alarms brief system", timeout=60,
                             print_real_time_output=False, cli_output_file=cli_output_file)
    logger.info("show alarms brief system executed and output captured.")
    alarm_command = r'show alarms brief system active | ex Optics | ex Coherent'
    alarm_output = execute_command_in_shell(shell, alarm_command, "show alarms brief system active (filtered)",
                                            timeout=60, print_real_time_output=False, cli_output_file=cli_output_file)
    cleaned_alarm_lines = []
    alarm_command_pattern = re.compile(re.escape(alarm_command.strip()))
    for line in alarm_output.splitlines():
        stripped_line = line.strip()
        if not stripped_line: continue
        if re.match(r'^\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+$', stripped_line): continue
        if re.match(r'^RP/\d+/\S+:\S+#', stripped_line): continue
        if alarm_command_pattern.search(stripped_line): continue
        if re.match(r'^-+$', stripped_line) or \
                re.match(r'Active Alarms', stripped_line) or \
                re.match(r'Location\s+Severity\s+Group\s+Set Time\s+Description', stripped_line): continue
        cleaned_alarm_lines.append(stripped_line)
    if cleaned_alarm_lines:
        logger.error(f"!!! ACTIVE ALARMS DETECTED (excluding Optics/Coherent) !!!")
        print(f"\nActive Alarms (excluding Optics/Coherent):")
        for alarm_line in cleaned_alarm_lines:
            print(f" {alarm_line}")
        raise AlarmError("Active alarms detected after filtering.")
    else:
        logger.info(f"No active alarms detected (excluding Optics/Coherent).")
    execute_command_in_shell(shell, "show install log detail", "show install log detail", timeout=120,
                             print_real_time_output=False, cli_output_file=cli_output_file)
    logger.info("show install log detail executed and output captured.")


def check_lc_asic_errors(shell: paramiko.Channel, lc_locations: List[str], cli_output_file=None):
    logger.info(f"Checking LC ASIC Errors...")
    problematic_lc_asic_errors = []
    for lc_location in lc_locations:
        command = f'show asic-errors all location {lc_location} | i "CPU|Bit|Reset|Parity" | ex ": 0"'
        description = f"show asic-errors for {lc_location}"
        output = execute_command_in_shell(shell, command, description, timeout=180, print_real_time_output=False,
                                          cli_output_file=cli_output_file)
        cleaned_lines = []
        command_pattern = re.compile(re.escape(command.strip()))
        for line in output.splitlines():
            stripped_line = line.strip()
            if not stripped_line: continue
            if re.match(r'^\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+$', stripped_line): continue
            if re.match(r'^RP/\d+/\S+:\S+#$', stripped_line): continue
            if command_pattern.search(stripped_line): continue
            lc_marker_regex = re.compile(r'^\*\s+\d+_\d+_CPU\d+\s+\*$')
            if lc_marker_regex.search(stripped_line): continue
            if "No asics are registered with asic_errors on this node" in stripped_line: continue
            cleaned_lines.append(stripped_line)
        if cleaned_lines:
            problematic_lc_asic_errors.append({
                "LC Location": lc_location,
                "Error Output": "\n".join(cleaned_lines)
            })
    if problematic_lc_asic_errors:
        logger.error(f"!!! LC ASIC ERRORS DETECTED !!!")
        asic_error_table = PrettyTable()
        asic_error_table.field_names = ["LC Location", "Error Output"]
        for item in problematic_lc_asic_errors:
            asic_error_table.add_row([item["LC Location"], item["Error Output"]])
        print(asic_error_table)
        raise LcAsicErrorsError("LC ASIC errors check failed. Non-blank output detected for some LCs.")
    else:
        logger.info(f"LC ASIC Errors check passed. No non-blank output detected.")


def check_fan_tray_status(shell: paramiko.Channel, ft_locations: List[str],
                          all_card_inventory_info: Dict[str, Dict[str, str]], cli_output_file=None):
    logger.info(f"Checking Fan Tray Status...")
    execute_command_in_shell(shell, "show environment fan", "show environment fan", timeout=60,
                             print_real_time_output=False, cli_output_file=cli_output_file)
    logger.info("show environment fan executed and output captured.")
    problematic_fan_trays = []
    for ft_location in ft_locations:
        logger.info(f"Checking fan tray: {ft_location}")
        command = f"show environment all location {ft_location}"
        output = execute_command_in_shell(shell, command, f"show environment for {ft_location}", timeout=60,
                                          print_real_time_output=False, cli_output_file=cli_output_file)
        issues = []
        replacement_recommended = "No"
        if "not present" in output.lower() or "no such instance" in output.lower() or "data not found" in output.lower():
            issues.append("Fan Tray is missing or not detected.")
            replacement_recommended = "Yes (Missing)"
            problematic_fan_trays.append({
                "Fan Tray Location": ft_location,
                "Detected Issues": "; ".join(issues),
                "Replacement Recommended": replacement_recommended
            })
            continue
        input_voltage_mv = None
        input_current_ma = None
        voltage_line_match = re.search(r'Input Voltage\s+(\d+)', output)
        if voltage_line_match:
            voltage_str = voltage_line_match.group(1).strip()
            if voltage_str == "-":
                issues.append("Invalid Sensor Read: Input Voltage is '-'.")
            else:
                try:
                    input_voltage_mv = float(voltage_str)
                    input_voltage_volts = input_voltage_mv / 1000.0
                    if input_voltage_volts == 0:
                        issues.append("Voltage Issue: Input Voltage is 0V.")
                    elif input_voltage_volts > 60:
                        issues.append(f"Voltage Issue: Input Voltage is {input_voltage_volts:.2f}V (Greater than 60V).")
                except ValueError:
                    issues.append(f"Invalid Sensor Read: Input Voltage '{voltage_str}' is not a valid number.")
        else:
            issues.append("Input Voltage reading not found.")
        current_line_match = re.search(r'Input Current\s+(\d+)', output)
        if current_line_match:
            current_str = current_line_match.group(1).strip()
            if current_str == "-":
                issues.append("Invalid Sensor Read: Input Current is '-'.")
            else:
                try:
                    input_current_ma = float(current_str)
                    if input_current_ma == 0: issues.append("Current Issue: Input Current is 0A.")
                except ValueError:
                    issues.append(f"Invalid Sensor Read: Input Current '{current_str}' is not a valid number.")
        else:
            issues.append("Input Current reading not found.")
        fan_tray_inventory = all_card_inventory_info.get(ft_location, {})
        pid = fan_tray_inventory.get("PID", "N/A")
        vid = fan_tray_inventory.get("VID", "N/A")
        if pid in FAN_IMPACTED_VERSIONS:
            impacted_versions = FAN_IMPACTED_VERSIONS[pid].get("Impacted", [])
            if vid in impacted_versions:
                if issues:
                    replacement_recommended = f"Yes (Impacted Version {vid} with symptoms)"
                else:
                    replacement_recommended = f"Consider (Impacted Version {vid}, no current symptoms)"
            elif vid in FAN_IMPACTED_VERSIONS[pid].get("Not Impacted", []):
                replacement_recommended = f"No (Not Impacted Version {vid})"
            else:
                replacement_recommended = f"Unknown (PID: {pid}, VID: {vid} not in known versions)"
        else:
            replacement_recommended = f"Unknown (PID: {pid} not in known impacted list)"
        if issues:
            problematic_fan_trays.append({
                "Fan Tray Location": ft_location,
                "Detected Issues": "; ".join(issues),
                "Replacement Recommended": replacement_recommended
            })
    if problematic_fan_trays:
        logger.error(f"!!! FAN TRAY STATUS ERRORS DETECTED !!!")
        ft_table = PrettyTable()
        ft_table.field_names = ["Fan Tray Location", "Detected Issues", "Replacement Recommended"]
        for ft_issue in problematic_fan_trays:
            ft_table.add_row([
                ft_issue["Fan Tray Location"],
                ft_issue["Detected Issues"],
                ft_issue["Replacement Recommended"]
            ])
        print(ft_table)
        raise FanTrayError("Fan tray status check failed. Issues detected.")
    else:
        logger.info(f"Fan Tray Status check passed. No issues detected.")


def check_environment_status(shell: paramiko.Channel, cli_output_file=None):
    logger.info(f"Checking Environment Status (Temperature, Voltage, Power Supply)...")
    command = "show environment"
    output = execute_command_in_shell(shell, command, "show environment", timeout=180, print_real_time_output=False,
                                      cli_output_file=cli_output_file)

    temp_issues = []
    voltage_issues = []
    power_supply_issues = []

    lines = output.splitlines()
    current_section = None
    current_location = None

    # Regex patterns for section headers
    temp_section_pattern = re.compile(r'Location\s+TEMPERATURE')
    voltage_section_pattern = re.compile(r'Location\s+VOLTAGE')
    current_section_pattern = re.compile(r'Location\s+CURRENT')
    power_supply_section_pattern = re.compile(r'Power\s+Module\s+Type')

    # Regex for parsing location lines (e.g., "0/RP0/CPU0")
    location_line_pattern = re.compile(r'^\s*(\d+/\S+)\s*$')

    # Corrected regex for temperature sensor data lines
    # Groups: (Sensor Name), (Value), (Crit Lo), (Major Lo), (Minor Lo), (Minor Hi), (Major Hi), (Crit Hi - optional)
    temp_sensor_data_pattern = re.compile(
        r'^\s*(\S+)\s+([\d\.-]+)\s+([\d\.-]+|\S+)\s+([\d\.-]+|\S+)\s+([\d\.-]+|\S+)\s+([\d\.-]+|\S+)\s+([\d\.-]+|\S+)\s*([\d\.-]+|\S+)?\s*$'
    )

    # Corrected regex for voltage sensor data lines
    # Groups: (Sensor Name), (Value), (Crit Lo), (Minor Lo), (Minor Hi), (Crit Hi - optional)
    voltage_sensor_data_pattern = re.compile(
        r'^\s*(\S+)\s+([\d\.-]+)\s+([\d\.-]+|\S+)\s+([\d\.-]+|\S+)\s+([\d\.-]+|\S+)\s*([\d\.-]+|\S+)?\s*$'
    )

    # Power supply pattern (as is)
    power_supply_data_pattern = re.compile(
        r'^\s*(\S+)\s+(\S+)\s+([\d\.]+)/([\d\.]+)\s+([\d\.]+)/([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)\s+(.+)$'
    )

    for i, line in enumerate(lines):
        stripped_line = line.strip()

        # Skip common non-data lines (timestamps, prompts, separators)
        if not stripped_line or \
                re.match(r'^\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+$', stripped_line) or \
                re.match(r'^RP/\d+/\S+:\S+#', stripped_line) or \
                re.match(r'^-+$', stripped_line) or \
                "================================================================================" in stripped_line or \
                "Flags:" in stripped_line or "Check detail option." in stripped_line:
            continue

        # Check for section headers
        if temp_section_pattern.search(stripped_line):
            current_section = "TEMPERATURE"
            current_location = None  # Reset location for new section
            continue
        elif voltage_section_pattern.search(stripped_line):
            current_section = "VOLTAGE"
            current_location = None  # Reset location for new section
            continue
        elif current_section_pattern.search(stripped_line):
            current_section = "CURRENT"  # Changed from "SKIP" to "CURRENT"
            current_location = None
            continue
        elif power_supply_section_pattern.search(stripped_line):
            current_section = "POWER_SUPPLY"
            current_location = None  # Reset location for new section
            continue

        # Process data within identified sections
        if current_section == "TEMPERATURE":
            # Check for location line within temperature block (e.g., "0/RP0/CPU0")
            location_match = location_line_pattern.match(stripped_line)
            if location_match:
                current_location = location_match.group(1)
                continue  # This line was just a location header

            # Skip the sensor header line within the temperature block (e.g., "Sensor Value Crit Major...")
            if re.match(r'^\s*Sensor\s+Value\s+Crit\s+Major\s+Minor\s+Minor\s+Major\s+Crit', stripped_line):
                continue

            # Process temperature sensor data
            if current_location:  # Ensure a location has been identified before processing sensor data
                match = temp_sensor_data_pattern.match(stripped_line)
                if match:
                    # Unpack the groups into the correct variables
                    sensor, value_str, crit_lo, major_lo, minor_lo, minor_hi, major_hi, crit_hi = match.groups()

                    try:
                        value = float(value_str)
                        # Ensure None values are handled before float conversion
                        crit_lo = float(crit_lo) if crit_lo is not None and crit_lo not in ['NA', '-'] else None
                        major_lo = float(major_lo) if major_lo is not None and major_lo not in ['NA', '-'] else None
                        minor_lo = float(minor_lo) if minor_lo is not None and minor_lo not in ['NA', '-'] else None
                        minor_hi = float(minor_hi) if minor_hi is not None and minor_hi not in ['NA', '-'] else None
                        major_hi = float(major_hi) if major_hi is not None and major_hi not in ['NA', '-'] else None
                        crit_hi = float(crit_hi) if crit_hi is not None and crit_hi not in ['NA', '-'] else None

                        issue_found = False
                        issue_desc = []

                        # Check critical low
                        if crit_lo is not None and value < crit_lo:
                            issue_desc.append(f"Critical Low (Value: {value}, Threshold: {crit_lo})")
                            issue_found = True
                        # Check major low (only if not already critical low)
                        elif major_lo is not None and value < major_lo:
                            issue_desc.append(f"Major Low (Value: {value}, Threshold: {major_lo})")
                            issue_found = True
                        # Check minor low (only if not already major/critical low)
                        elif minor_lo is not None and value < minor_lo:
                            issue_desc.append(f"Minor Low (Value: {value}, Threshold: {minor_lo})")
                            issue_found = True

                        # Check critical high
                        if crit_hi is not None and value > crit_hi:
                            issue_desc.append(f"Critical High (Value: {value}, Threshold: {crit_hi})")
                            issue_found = True
                        # Check major high (only if not already critical high)
                        elif major_hi is not None and value > major_hi:
                            issue_desc.append(f"Major High (Value: {value}, Threshold: {major_hi})")
                            issue_found = True
                        # Check minor high (only if not already major/critical high)
                        elif minor_hi is not None and value > minor_hi:
                            issue_desc.append(f"Minor High (Value: {value}, Threshold: {minor_hi})")
                            issue_found = True

                        if issue_found:
                            temp_issues.append({
                                "Location": current_location,
                                "Sensor": sensor,
                                "Problem": "; ".join(issue_desc)
                            })
                    except ValueError:
                        logger.warning(
                            f"Could not parse numeric values for temperature sensor '{sensor}' at '{current_location}'. Line: '{stripped_line}'")
                        pass  # Skip this line if parsing fails
        elif current_section == "VOLTAGE":
            # Check for location line within voltage block (e.g., "0/RP0/CPU0")
            location_match = location_line_pattern.match(stripped_line)
            if location_match:
                current_location = location_match.group(1)
                continue  # This line was just a location header

            # Skip the sensor header line within the voltage block (e.g., "Sensor Value Crit Minor Minor Crit")
            if re.match(r'^\s*Sensor\s+Value\s+Crit\s+Minor\s+Minor\s+Crit', stripped_line):
                continue

            # Process voltage sensor data
            if current_location:
                match = voltage_sensor_data_pattern.match(stripped_line)
                if match:
                    # Groups: (Sensor Name), (Value), (Crit Lo), (Minor Lo), (Minor Hi), (Crit Hi - optional)
                    sensor, value_str, crit_lo, minor_lo, minor_hi, crit_hi = match.groups()
                    try:
                        value = float(value_str)
                        crit_lo = float(crit_lo) if crit_lo is not None and crit_lo not in ['NA', '-'] else None
                        minor_lo = float(minor_lo) if minor_lo is not None and minor_lo not in ['NA', '-'] else None
                        minor_hi = float(minor_hi) if minor_hi is not None and minor_hi not in ['NA', '-'] else None
                        crit_hi = float(crit_hi) if crit_hi is not None and crit_hi not in ['NA', '-'] else None

                        issue_found = False
                        issue_desc = []

                        if crit_lo is not None and value < crit_lo:
                            issue_desc.append(f"Critical Low (Value: {value}mV, Threshold: {crit_lo}mV)")
                            issue_found = True
                        elif minor_lo is not None and value < minor_lo:
                            issue_desc.append(f"Minor Low (Value: {value}mV, Threshold: {minor_lo}mV)")
                            issue_found = True

                        if crit_hi is not None and value > crit_hi:
                            issue_desc.append(f"Critical High (Value: {value}mV, Threshold: {crit_hi}mV)")
                            issue_found = True
                        elif minor_hi is not None and value > minor_hi:
                            issue_desc.append(f"Minor High (Value: {value}mV, Threshold: {minor_hi}mV)")
                            issue_found = True

                        if issue_found:
                            voltage_issues.append({
                                "Location": current_location,
                                "Sensor": sensor,
                                "Problem": "; ".join(issue_desc)
                            })
                    except ValueError:
                        logger.warning(
                            f"Could not parse numeric values for voltage sensor '{sensor}' at '{current_location}'. Line: '{stripped_line}'")
                        pass  # Skip this line if parsing fails
        elif current_section == "POWER_SUPPLY":
            # Skip the header line for power supply section
            if re.match(r'^\s*Power\s+Module\s+Type\s+---Input----\s+---Output---\s+Status', stripped_line):
                continue
            # Also skip the sub-header line
            if re.match(r'^\s*Volts\s+A/B\s+Amps\s+A/B\s+Volts\s+Amps', stripped_line):
                continue

            match = power_supply_data_pattern.match(stripped_line)
            if match:
                location, ps_type, in_v_a_str, in_v_b_str, in_a_a_str, in_a_b_str, out_v_str, out_a_str, status = match.groups()
                current_ps_issues = []
                try:
                    in_v_a = float(in_v_a_str)
                    in_v_b = float(in_v_b_str)
                    in_a_a = float(in_a_a_str)
                    in_a_b = float(in_a_b_str)
                    out_v = float(out_v_str)
                    out_a = float(out_a_str)

                    if in_v_a == 0 or in_v_b == 0: current_ps_issues.append("Zero Input Voltage detected.")
                    if in_a_a == 0 or in_a_b == 0: current_ps_issues.append("Zero Input Current detected.")
                    if out_v == 0: current_ps_issues.append("Zero Output Voltage detected.")
                    if out_a == 0: current_ps_issues.append("Zero Output Current detected.")
                except ValueError:
                    current_ps_issues.append("Invalid numeric value in voltage/current fields.")

                if status.strip().upper() != "OK":
                    current_ps_issues.append(f"Status is '{status.strip()}' (Expected: OK).")

                if current_ps_issues:
                    power_supply_issues.append({
                        "Location": location,
                        "Type": ps_type,
                        "Problem": "; ".join(current_ps_issues)
                    })

    all_env_issues_found = False
    if temp_issues:
        all_env_issues_found = True
        logger.error(f"!!! ENVIRONMENT TEMPERATURE ALARMS DETECTED !!!")
        temp_table = PrettyTable()
        temp_table.field_names = ["Location", "Sensor", "Problem"]
        for issue in temp_issues:
            temp_table.add_row([issue["Location"], issue["Sensor"], issue["Problem"]])
        print(temp_table)
    if voltage_issues:
        all_env_issues_found = True
        logger.error(f"!!! ENVIRONMENT VOLTAGE ALARMS DETECTED !!!")
        voltage_table = PrettyTable()
        voltage_table.field_names = ["Location", "Sensor", "Problem"]
        for issue in voltage_issues:
            voltage_table.add_row([issue["Location"], issue["Sensor"], issue["Problem"]])
        print(voltage_table)
    if power_supply_issues:
        all_env_issues_found = True
        logger.error(f"!!! POWER SUPPLY MODULE ISSUES DETECTED !!!")
        ps_table = PrettyTable()
        ps_table.field_names = ["Location", "Type", "Problem"]
        for issue in power_supply_issues:
            ps_table.add_row([issue["Location"], issue["Type"], issue["Problem"]])
        print(ps_table)

    if all_env_issues_found:
        raise EnvironmentError("Environment status check failed. Issues detected.")
    else:
        logger.info(
            f"Environment Status check passed. No critical/major temperature/voltage alarms or power supply issues detected.")


def print_final_summary_table(statuses: Dict[str, str]):
    print(f"\n--- Final Script Summary ---")
    summary_table = PrettyTable()
    summary_table.field_names = ["Section Name", "Status"]
    for section, status in statuses.items():
        summary_table.add_row([section, status])
    print(summary_table)
    logger.info(f"--- End Final Script Summary ---")


def check_ios_xr_version(shell: paramiko.Channel, cli_output_file=None) -> str:
    logger.info(f"Retrieving IOS-XR Version...")
    version_output = execute_command_in_shell(shell, "show version", "show version", timeout=60,
                                              print_real_time_output=False, cli_output_file=cli_output_file)
    ios_xr_version = "N/A"
    match = re.search(r"Cisco IOS XR Software, Version (\d+\.\d+\.\d+(?:\.\w+)?)", version_output)
    if match:
        ios_xr_version = match.group(1)
        logger.info(f"IOS-XR Version detected: {ios_xr_version}")
    else:
        logger.warning("Could not parse IOS-XR version from 'show version' output.")
    version_table = PrettyTable()
    version_table.field_names = ["Information", "Value"]
    version_table.add_row(["IOS-XR Version", ios_xr_version])
    print(version_table)
    return ios_xr_version


def check_platform_and_serial_numbers(shell: paramiko.Channel,
                                      all_card_inventory_info: Dict[str, Dict[str, str]],
                                      all_cpu_locations_from_platform: List[str],
                                      ft_locations_from_platform: List[str],
                                      cli_output_file=None):  # Moved to end
    logger.info(f"Retrieving Platform Status and Serial Numbers...")
    platform_output = execute_command_in_shell(shell, "show platform", "show platform", timeout=60,
                                               print_real_time_output=False, cli_output_file=cli_output_file)
    fc_inventory_output = execute_command_in_shell(shell, "show inventory | utility egrep 0/FC -A1 -B1",
                                                   "show inventory for FCs", timeout=60,
                                                   print_real_time_output=False, cli_output_file=cli_output_file)
    cpu_inventory_output = execute_command_in_shell(shell, "show inventory | utility egrep /CPU0 -A1 -B1",
                                                    "show inventory for LCs/RPs", timeout=60,
                                                    print_real_time_output=False, cli_output_file=cli_output_file)
    ft_inventory_output = execute_command_in_shell(shell, "show inventory | utility egrep 0/FT -A1 -B1",
                                                   "show inventory for FTs", timeout=60,
                                                   print_real_time_output=False, cli_output_file=cli_output_file)
    all_card_inventory_info.update(parse_inventory_for_serial_numbers(fc_inventory_output))
    all_card_inventory_info.update(parse_inventory_for_serial_numbers(cpu_inventory_output))
    all_card_inventory_info.update(parse_inventory_for_serial_numbers(ft_inventory_output))
    all_cards_details = []
    platform_issues_found = False
    lines = platform_output.splitlines()
    card_pattern = re.compile(r"^\s*(\S+)\s+(\S+)\s+(.+?)\s{2,}(\S+).*$")
    for line in lines:
        match = card_pattern.match(line)
        if match:
            location, card_type, current_state_raw, config_state = match.groups()
            current_state = current_state_raw.strip()
            expected_state = None
            is_problematic = False
            if "CPU" in location:
                expected_state = "IOS XR RUN"
                all_cpu_locations_from_platform.append(location)
            elif "FC" in location:
                expected_state = "OPERATIONAL"
            elif "BMC" in location:
                expected_state = "OPERATIONAL"
            elif "FT" in location:
                expected_state = "OPERATIONAL"
                ft_locations_from_platform.append(location)
            elif "PT" in location:
                expected_state = "OPERATIONAL"
            if expected_state is not None:
                if current_state != expected_state:
                    is_problematic = True
                    platform_issues_found = True
                display_state = f"{current_state} (Expected: {expected_state})" if is_problematic else current_state
                inventory_data = all_card_inventory_info.get(location, {"SN": "N/A", "VID": "N/A"})
                serial_num = inventory_data["SN"]
                vid = inventory_data["VID"]
                all_cards_details.append({
                    "Location": location,
                    "State": display_state,
                    "Serial Number": serial_num,
                    "VID": vid
                })
    print(f"Platform Status:")
    platform_table = PrettyTable()
    platform_table.field_names = ["LC / FC / RP / FT Location", "State", "Serial Number", "VID"]
    if all_cards_details:
        for card in all_cards_details:
            platform_table.add_row([card["Location"], card["State"], card["Serial Number"], card["VID"]])
    else:
        platform_table.add_row(["N/A", "No relevant cards found in 'show platform' output", "N/A", "N/A"])
    print(platform_table)
    if platform_issues_found:
        logger.error(
            f"One or more Line Cards, Fabric Cards, or Route Processors are not in the expected state. Please review the table above.")
        raise PlatformStatusError("Platform status check failed.")
    else:
        logger.info(f"All Line Cards, Fabric Cards, and Route Processors are in their expected states.")


def _run_section_check(section_name: str, check_func: callable, section_statuses: Dict[str, str],
                       overall_script_failed_ref: List[bool], *args, **kwargs):
    try:
        logger.info(f"--- Running {section_name} ---")
        check_func(*args, **kwargs)
        logger.info(f"--- {section_name} Passed ---")
        section_statuses[section_name] = "Good"
    except (RouterCommandError, PlatformStatusError, FabricReachabilityError,
            FabricLinkDownError, NpuLinkError, NpuStatsError, NpuDriverError,
            FabricPlaneStatsError, AsicErrorsError, InterfaceStatusError,
            AlarmError, LcAsicErrorsError, FanTrayError, EnvironmentError) as e:
        logger.critical(f"{section_name} failed: {e}")
        overall_script_failed_ref[0] = True
        section_statuses[section_name] = "Bad"
    except Exception as e:
        logger.critical(f"An unexpected error occurred during {section_name}: {e}", exc_info=True)
        overall_script_failed_ref[0] = True
        section_statuses[section_name] = "Bad"
    finally:
        print()


# Continue from Part 2

# --- New functions for Interface Status Comparison ---
def find_latest_precheck_file(hostname: str, output_directory: str, current_file_path: str) -> Optional[
    str]:  # Changed return type
    """
    Finds the path to the most recent pre-check CLI output file for a given hostname,
    excluding the current file being generated.
    """
    pattern = re.compile(rf"^{re.escape(hostname)}_pre_check_cli_output_(\d{{8}}_\d{{6}})\.txt$")
    latest_file = None
    latest_timestamp = None

    if not os.path.isdir(output_directory):
        logger.debug(f"Output directory not found: {output_directory}")
        return None

    for filename in os.listdir(output_directory):
        full_path = os.path.join(output_directory, filename)
        if full_path == current_file_path:  # Skip the current file
            continue

        match = pattern.match(filename)
        if match:
            timestamp_str = match.group(1)
            try:
                current_timestamp = datetime.datetime.strptime(timestamp_str, '%Y%m%d_%H%M%S')
                if latest_timestamp is None or current_timestamp > latest_timestamp:
                    latest_timestamp = current_timestamp
                    latest_file = full_path
            except ValueError:
                logger.warning(f"Could not parse timestamp from filename: {filename}")
                continue
    return latest_file


def parse_interface_status_from_cli_output(file_path: str) -> Dict[str, Dict[str, str]]:
    """
    Parses 'show interface summary' and 'show interface brief' outputs from a CLI log file.
    Returns a dictionary mapping interface names to their status from both commands.
    Example:
    {
        "GigabitEthernet0/0/0/0": {"summary_status": "Up", "brief_status": "Up", "brief_protocol": "Up"},
        ...
    }
    """
    interface_statuses: Dict[str, Dict[str, str]] = {}
    content = ""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        logger.debug(f"Successfully read content from {file_path}, length: {len(content)}")
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        return {}
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return {}

    # Regex to find command sections, making it more robust
    command_section_pattern = re.compile(
        r"--- Command: (show interface (?:summary|brief)) ---\n(.*?)(?=\n--- Command:|\Z)", re.DOTALL)

    summary_output = ""
    brief_output = ""

    for match in command_section_pattern.finditer(content):
        command = match.group(1).strip()
        output_section = match.group(2).strip()
        if command == "show interface summary":
            summary_output = output_section
            logger.debug(f"Found 'show interface summary' section. Length: {len(summary_output)}")
        elif command == "show interface brief":
            brief_output = output_section
            logger.debug(f"Found 'show interface brief' section. Length: {len(brief_output)}")

    # Parse show interface summary (we will extract summary_status from brief output)
    # The debug logs show that the 'show interface summary' output is aggregate data, not per-interface.
    # Therefore, we will rely on 'show interface brief' for per-interface status.
    # The 'summary_status' will effectively be the Admin Status from 'show interface brief'.
    if summary_output:
        # This regex is for the "ALL TYPES" line in summary, not individual interfaces.
        # It's kept for the overall summary display, but not for per-interface parsing here.
        pass  # No per-interface parsing from summary_output needed for comparison

    # Parse show interface brief
    if brief_output:
        # Regex for 'show interface brief' lines: Interface, Admin Status, Protocol Status
        # This regex specifically targets the interface name, Admin Status, and Protocol Status.
        # It's made more flexible for variable whitespace and handles interface names with numbers/slashes.
        # Example lines from your debug:
        # Nu0          up          up
        # FH0/2/0/0  admin-down  admin-down
        # Hu0/3/0/0  admin-down  admin-down
        # Mg0/RP0/CPU0/0          up          up
        brief_line_pattern = re.compile(
            r"^\s*(\S+)\s+(up|down|admin-down|not connect|unknown|--)\s+(up|down|admin-down|not connect|unknown|--)\s+.*$",
            re.IGNORECASE  # Make it case-insensitive for "Up", "Down", etc.
        )

        # Skip header lines for brief
        # Added more patterns to skip based on your debug log
        brief_lines = [
            line for line in brief_output.splitlines()
            if not re.match(
                r"^\s*(Intf|Name|State|LineP|Encap|MTU|BW|---|\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+|RP/\d+/\S+#|show interface brief)\s*$",
                line.strip())
               and line.strip()
        ]

        logger.debug(f"Processing {len(brief_lines)} lines from 'show interface brief' after header filtering.")

        for line in brief_lines:
            match = brief_line_pattern.match(line)
            if match:
                intf_name = match.group(1).strip()
                brief_admin_status = match.group(2).strip()
                brief_protocol_status = match.group(3).strip()

                # Normalize status strings to lowercase for consistent comparison
                brief_admin_status = brief_admin_status.lower()
                brief_protocol_status = brief_protocol_status.lower()

                interface_statuses.setdefault(intf_name, {})[
                    "summary_status"] = brief_admin_status  # Using admin status from brief as summary
                interface_statuses.setdefault(intf_name, {})["brief_status"] = brief_admin_status
                interface_statuses.setdefault(intf_name, {})["brief_protocol"] = brief_protocol_status
                logger.debug(
                    f"Parsed brief line: {intf_name} -> Admin: {brief_admin_status}, Protocol: {brief_protocol_status}")
            else:
                logger.debug(f"Skipping brief line (no regex match): '{line}'")
    else:
        logger.debug("No 'show interface brief' output found in file.")

    logger.debug(f"Final parsed interface statuses from {file_path}: {interface_statuses}")
    return interface_statuses


def compare_interface_statuses(current_statuses: Dict[str, Dict[str, str]],
                               previous_statuses: Dict[str, Dict[str, str]]):
    """
    Compares current and previous interface statuses and prints differences.
    """
    differences_found = False
    comparison_table = PrettyTable()
    comparison_table.field_names = ["Interface", "Change Type", "Previous Status", "Current Status"]
    comparison_table.align = "l"  # Align left for better readability

    all_interfaces = sorted(list(set(current_statuses.keys()) | set(previous_statuses.keys())))

    for intf in all_interfaces:
        current_data = current_statuses.get(intf, {})
        previous_data = previous_statuses.get(intf, {})

        # Determine if interface is new or disappeared
        if intf not in previous_statuses and intf in current_statuses:
            summary_stat = current_data.get("summary_status", "N/A")
            brief_adm_stat = current_data.get("brief_status", "N/A")
            brief_prot_stat = current_data.get("brief_protocol", "N/A")
            comparison_table.add_row([intf, "Newly Appeared", "N/A",
                                      f"Summary: {summary_stat}, Brief: {brief_adm_stat}/{brief_prot_stat}"])
            differences_found = True
            continue  # Move to next interface

        if intf in previous_statuses and intf not in current_statuses:
            summary_stat = previous_data.get("summary_status", "N/A")
            brief_adm_stat = previous_data.get("brief_status", "N/A")
            brief_prot_stat = previous_data.get("brief_protocol", "N/A")
            comparison_table.add_row([intf, "Disappeared",
                                      f"Summary: {summary_stat}, Brief: {brief_adm_stat}/{brief_prot_stat}",
                                      "N/A"])
            differences_found = True
            continue  # Move to next interface

        # Compare statuses for common interfaces
        if intf in current_statuses and intf in previous_statuses:
            # Compare 'summary_status' (which is brief_admin_status in this logic)
            current_sum = current_data.get("summary_status", "N/A")
            prev_sum = previous_data.get("summary_status", "N/A")
            if current_sum != prev_sum:
                comparison_table.add_row([intf, "Summary Status Change", prev_sum, current_sum])
                differences_found = True

            # Compare 'brief_status' (admin status)
            current_brief_adm = current_data.get("brief_status", "N/A")
            prev_brief_adm = previous_data.get("brief_status", "N/A")
            if current_brief_adm != prev_brief_adm:
                comparison_table.add_row([intf, "Brief Admin Status Change", prev_brief_adm, current_brief_adm])
                differences_found = True

            # Compare 'brief_protocol'
            current_brief_prot = current_data.get("brief_protocol", "N/A")
            prev_brief_prot = previous_data.get("brief_protocol", "N/A")
            if current_brief_prot != prev_brief_prot:
                comparison_table.add_row([intf, "Brief Protocol Status Change", prev_brief_prot, current_brief_prot])
                differences_found = True

    if differences_found:
        logger.warning(f"!!! INTERFACE STATUS DIFFERENCES DETECTED BETWEEN CURRENT AND PREVIOUS RUN !!!")
        print("\n--- Interface Status Comparison Report ---")
        print(comparison_table)
        logger.warning("Please review the interface status changes above.")
    else:
        logger.info(f"No interface status differences detected between current and previous run.")


# --- End of New functions ---


def main():
    # Store the original stdout
    original_stdout = sys.stdout

    # Configure logger to print to the original stdout (console) initially
    # This handler will remain active and print to console.
    console_handler = logging.StreamHandler(original_stdout)
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    logger.info(f"--- Cisco IOS-XR Device Status Report ---")

    router_ip = input(f"Enter Router IP address or Hostname: ")
    username = input(f"Enter SSH Username: ")
    password = getpass.getpass(f"Enter SSH Password: ")

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    shell = None
    overall_script_failed = [False]
    all_cpu_locations_from_platform = []
    ft_locations_from_platform = []
    all_card_inventory_info = {}
    cli_output_file = None
    session_log_file_handle = None  # Variable to hold the file object for the session log
    section_statuses = {}
    hostname = "unknown_host"  # Initialize hostname for finally block

    try:
        logger.info(f"Attempting to connect to {router_ip}...")
        client.connect(router_ip, port=22, username=username, password=password, timeout=SSH_TIMEOUT_SECONDS,
                       look_for_keys=False)
        logger.info(f"Successfully connected to {router_ip}.")

        shell = client.invoke_shell()
        time.sleep(1)
        # This initial read_and_print_realtime will print to console only, before redirection
        read_and_print_realtime(shell, timeout_sec=2)

        execute_command_in_shell(shell, "terminal length 0", "set terminal length to 0", timeout=5,
                                 print_real_time_output=False)
        execute_command_in_shell(shell, "terminal width 511", "set terminal width to 511", timeout=5,
                                 print_real_time_output=False)

        hostname = get_hostname(shell)
        logger.info(f"Sanitized hostname for file paths: {hostname}")

        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        output_directory = os.path.join(os.getcwd(), hostname)
        os.makedirs(output_directory, exist_ok=True)
        logger.info(f"Created output directory: {output_directory}")

        session_log_path = os.path.join(output_directory, f"{hostname}_pre_check_CLI_session_log_{timestamp}.txt")

        # Open the session log file for writing
        session_log_file_handle = open(session_log_path, 'a', encoding='utf-8')

        # Add a FileHandler to the logger, so logger messages also go to the file
        file_handler = logging.FileHandler(session_log_path, encoding='utf-8')
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

        # Redirect sys.stdout to our custom Tee stream.
        # Now, all subsequent print() statements will go to both the console and the session log file.
        sys.stdout = Tee(original_stdout, session_log_file_handle)

        logger.info(f"Session log will be saved to: {session_log_path}")
        cli_output_path = os.path.join(output_directory, f"{hostname}_pre_check_cli_output_{timestamp}.txt")
        cli_output_file = open(cli_output_path, 'a')
        logger.info(f"CLI output will be saved to: {cli_output_path}")

        print(f"\n--- Device Information Report ---")  # This print will now be captured in the log file

        # Run all checks
        _run_section_check("IOS-XR Version Check", check_ios_xr_version, section_statuses, overall_script_failed, shell,
                           cli_output_file)
        _run_section_check("Platform Status & Serial Numbers", check_platform_and_serial_numbers, section_statuses,
                           overall_script_failed, shell, all_card_inventory_info, all_cpu_locations_from_platform,
                           ft_locations_from_platform, cli_output_file)
        _run_section_check("Fabric Reachability Check", check_fabric_reachability, section_statuses,
                           overall_script_failed, shell, cli_output_file)
        _run_section_check("Fabric Link Down Status Check", check_fabric_link_down_status, section_statuses,
                           overall_script_failed, shell, cli_output_file)
        _run_section_check("NPU Link Information Check", check_npu_link_info, section_statuses, overall_script_failed,
                           shell, cli_output_file)
        _run_section_check("NPU Stats Link Check (UCE/CRC)", check_npu_stats_link, section_statuses,
                           overall_script_failed, shell, cli_output_file)
        _run_section_check("NPU Driver Status Check", check_npu_driver_status, section_statuses, overall_script_failed,
                           shell, cli_output_file)
        _run_section_check("Fabric Plane Statistics Check", check_fabric_plane_stats, section_statuses,
                           overall_script_failed, shell, cli_output_file)
        _run_section_check("ASIC Errors Check (RP0)", check_asic_errors, section_statuses, overall_script_failed, shell,
                           cli_output_file)
        _run_section_check("Inventory Collection", run_show_inventory, section_statuses, overall_script_failed, shell,
                           cli_output_file)
        section_statuses["Inventory Collection"] = "Collection Only"
        _run_section_check("Interface Status Check", check_interface_status, section_statuses, overall_script_failed,
                           shell, cli_output_file)

        section_name_alarms = "Active Alarms Check"
        section_name_install_log = "Install Log Collection"
        try:
            _run_section_check(section_name_alarms, check_and_capture_alarms_and_logs, section_statuses,
                               overall_script_failed, shell, cli_output_file)
            section_statuses[section_name_install_log] = "Collection Only"
        except Exception:
            section_statuses[section_name_alarms] = "Bad"
            section_statuses[section_name_install_log] = "Collection Only"
            overall_script_failed[0] = True

        section_name = "LC ASIC Errors Check"
        lc_locations_for_asic_check = [loc for loc in all_cpu_locations_from_platform if "RP" not in loc]
        if lc_locations_for_asic_check:
            _run_section_check(section_name, check_lc_asic_errors, section_statuses, overall_script_failed, shell,
                               lc_locations_for_asic_check, cli_output_file)
        else:
            logger.warning(f"Skipping {section_name} as no non-RP LC locations were identified from 'show platform'.")
            section_statuses[section_name] = "Collection Only (Skipped - No LCs)"

        section_name = "Fan Tray Status Check"
        if ft_locations_from_platform:
            _run_section_check(section_name, check_fan_tray_status, section_statuses, overall_script_failed, shell,
                               ft_locations_from_platform, all_card_inventory_info, cli_output_file)
        else:
            logger.warning(f"Skipping {section_name} as no Fan Tray locations were identified from 'show platform'.")
            section_statuses[section_name] = "Collection Only (Skipped - No FTs)"

        _run_section_check("Overall Environment Status Check", check_environment_status, section_statuses,
                           overall_script_failed, shell, cli_output_file)

    except (SSHConnectionError, paramiko.SSHException, RouterCommandError) as e:
        logger.critical(f"Critical connection or initial command error: {e}")
        overall_script_failed[0] = True
    except Exception as e:
        logger.critical(f"An unexpected error occurred during script execution: {e}", exc_info=True)
        overall_script_failed[0] = True
    finally:
        # Perform SSH session cleanup
        if shell:
            logger.info("Exiting CLI session.")
            try:
                shell.send("exit\n")
                time.sleep(1)
                while shell.recv_ready():
                    shell.recv(65535).decode('utf-8', errors='ignore')
            except Exception:
                pass
            shell.close()
        if client:
            client.close()
        logger.info("SSH connection closed.")

        # Close the CLI output file BEFORE parsing it
        if cli_output_file:
            cli_output_file.close()
            logger.info(f"CLI output saved to {cli_output_path}")

        # --- Interface Status Comparison Logic ---
        logger.info(f"Starting interface status comparison...")
        latest_previous_file = find_latest_precheck_file(hostname, output_directory, cli_output_path)

        if latest_previous_file:
            logger.info(f"Found previous pre-check file: {latest_previous_file}")
            current_interface_statuses = parse_interface_status_from_cli_output(cli_output_path)
            previous_interface_statuses = parse_interface_status_from_cli_output(latest_previous_file)

            # Changed condition to allow comparison even if one file is empty
            if current_interface_statuses or previous_interface_statuses:
                compare_interface_statuses(current_interface_statuses, previous_interface_statuses)
            else:
                logger.warning("Could not parse interface statuses from one or both files. Skipping comparison.")
        else:
            logger.info(f"No previous pre-check CLI output file found for {hostname}. Skipping interface comparison.")
        logger.info(f"Finished interface status comparison.")
        # --- End Interface Status Comparison Logic ---

        # Print final summary table. This will also be captured by the Tee class.
        print_final_summary_table(section_statuses)

        # Log final script status
        if overall_script_failed[0]:
            logger.critical(f"--- Script Execution Finished with ERRORS ---")
        else:
            logger.info(f"--- Script Execution Finished Successfully ---")

        # Close the session log file handle
        if session_log_file_handle:
            session_log_file_handle.flush()
            session_log_file_handle.close()

        # Restore original stdout
        sys.stdout = original_stdout


if __name__ == "__main__":
    main()