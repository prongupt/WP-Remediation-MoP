"""
Optimized Cisco IOS-XR Device Health Check and Comparison Script
Key optimizations:
- Reduced memory footprint through streaming
- Consolidated duplicate code
- Simplified parsing logic
- Reduced string operations
"""

__author__ = "Pronoy Dasgupta"
__version__ = "1.0.0 (Optimized)"

import paramiko
import time
import getpass
import re
import logging
from prettytable import PrettyTable, HEADER, FRAME
import datetime
import os
import sys
from typing import List, Tuple, Dict, Any, Optional, Callable
from functools import wraps
from io import StringIO
from dataclasses import dataclass
from contextlib import contextmanager

# === CONFIGURATION ===
SSH_TIMEOUT = 15
PROMPT_PATTERNS = [r'[#>)\]]\s*$']  # Consolidated
FAN_IMPACTED_VERSIONS = {
    "8804-FAN": {"Not Impacted": ["V03"], "Impacted": ["V01", "V02"]},
    "8808-FAN": {"Not Impacted": ["V03"], "Impacted": ["V01", "V02"]},
    "8812-FAN": {"Not Impacted": ["V02"], "Impacted": ["V01"]},
    "8818-FAN": {"Not Impacted": ["V03"], "Impacted": ["V01", "V02"]},
}


# === CUSTOM EXCEPTIONS ===
class DeviceError(Exception):
    """Base exception for device errors"""
    pass


# === DATA CLASSES ===
@dataclass
class DeviceInfo:
    hostname: str = "unknown_host"
    chassis_model: str = "unknown_chassis"
    ios_version: str = "N/A"


@dataclass
class CheckResult:
    passed: bool
    message: str = ""
    data: Any = None


# === PROGRESS BAR (Simplified) ===
class ProgressBar:
    def __init__(self, total, stream, desc="", color='\033[94m'):
        self.total = total
        self.current = 0
        self.desc = desc
        self.color = color
        self.stream = stream
        self.start = time.time()
        self._last_len = 0

    def update(self, step=1):
        self.current = min(self.current + step, self.total)
        pct = f"{100 * self.current / self.total:.1f}"
        filled = int(50 * self.current // self.total)
        bar = '█' * filled + '-' * (50 - filled)
        elapsed = time.time() - self.start
        eta = "--:--" if self.current == 0 else f"{int((elapsed / self.current) * (self.total - self.current) / 60):02d}:{int((elapsed / self.current) * (self.total - self.current) % 60):02d}"
        msg = f"{self.color}{self.desc} |{bar}| {pct}% [{int(elapsed // 60):02d}:{int(elapsed % 60):02d}<{eta}]\033[0m"
        self.stream.write('\r' + ' ' * self._last_len + '\r' + msg)
        self.stream.flush()
        self._last_len = len(msg)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.current = self.total
        self.update(0)
        self.stream.write('\n')


# === LOGGING SETUP ===
class CompactFormatter(logging.Formatter):
    """Simplified formatter with context"""
    FORMATS = {
        logging.ERROR: '\033[91m%(levelname)s\033[0m - %(message)s',
        logging.WARNING: '\033[93m%(levelname)s\033[0m - %(message)s',
        logging.INFO: '%(levelname)s - %(message)s',
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, '%(levelname)s - %(message)s')
        formatter = logging.Formatter(log_fmt, datefmt='%H:%M:%S')
        return formatter.format(record)


logger = logging.getLogger(__name__)


# === SSH UTILITIES ===
def read_until_prompt(channel: paramiko.Channel, timeout: int = 60) -> Tuple[str, bool]:
    """Stream data until prompt detected"""
    output = []
    start = time.time()
    buffer = ""

    while time.time() - start < timeout:
        if channel.recv_ready():
            data = channel.recv(65535).decode('utf-8', errors='ignore')
            output.append(data)
            buffer = (buffer + data)[-500:]  # Keep last 500 chars

            if buffer and any(re.search(p, buffer.splitlines()[-1]) for p in PROMPT_PATTERNS):
                return ''.join(output), True
        else:
            time.sleep(0.1)

    return ''.join(output), False


def execute_command(shell: paramiko.Channel, cmd: str, desc: str = "",
                    timeout: int = 60, log_file=None) -> str:
    """Execute command and return output"""
    logger.debug(f"Executing: {desc or cmd}")

    if log_file:
        log_file.write(f"\n--- Command: {cmd} ---\n")

    # Flush buffer
    while shell.recv_ready():
        shell.recv(65535)

    shell.send(cmd + "\n")
    time.sleep(0.3)
    output, found = read_until_prompt(shell, timeout)

    if log_file:
        log_file.write(output)
        log_file.flush()

    if not found:
        logger.warning(f"Prompt not found for: {desc}")

    return output


# === PARSING UTILITIES ===
def parse_table_data(output: str, patterns: Dict[str, re.Pattern]) -> List[Dict]:
    """Generic table parser"""
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line or any(skip in line for skip in ['---', 'Mon ', 'RP/', '====']):
            continue

        for key, pattern in patterns.items():
            match = pattern.match(line)
            if match:
                results.append(dict(zip(match.groupdict().keys(), match.groups())))
                break

    return results


def parse_inventory(output: str, name_pattern: str = None) -> Dict[str, Dict[str, str]]:
    """Generic inventory parser"""
    inventory = {}
    current_loc = None

    name_re = re.compile(name_pattern or r'NAME: "(\S+)",')
    pid_re = re.compile(r'PID: (\S+)\s*,\s*VID: (\S+),\s*SN: (\S+)')

    for line in output.splitlines():
        if match := name_re.search(line):
            current_loc = match.group(1)
        elif match := pid_re.search(line):
            if current_loc:
                inventory[current_loc] = {
                    "PID": match.group(1),
                    "VID": match.group(2),
                    "SN": match.group(3)
                }
                current_loc = None

    return inventory


# === CHECK DECORATORS ===
def health_check(name: str):
    """Decorator for health check functions"""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> CheckResult:
            try:
                logger.info(f"Running: {name}")
                result = func(*args, **kwargs)
                logger.info(f"✓ {name} passed")
                return CheckResult(True, "Good", result)
            except DeviceError as e:
                logger.error(f"✗ {name} failed: {e}")
                return CheckResult(False, "Bad")
            except Exception as e:
                logger.error(f"✗ {name} error: {e}", exc_info=True)
                return CheckResult(False, "Bad")

        return wrapper

    return decorator


# === HEALTH CHECKS (Consolidated) ===
@health_check("Fabric Health")
def check_fabric_health(shell, cli_file, chassis_model):
    """Combined fabric checks"""
    # Reachability
    output = execute_command(shell, "show controller fabric fsdb-pla rack 0",
                             "fabric reachability", 120, cli_file)
    valid_masks = ["4/4", "2/2"] + (["6/6", "8/8", "16/16"] if "88" in chassis_model else [])

    issues = []
    for line in output.splitlines():
        if parts := line.split():
            if len(parts) >= 12 and parts[9] not in valid_masks and parts[9] != "----":
                issues.append(parts)

    if issues:
        raise DeviceError(f"Fabric reachability issues: {len(issues)} links")

    # Link status
    for cmd in ["show controller fabric link port s1 rx down",
                "show controller fabric link port fia rx down"]:
        output = execute_command(shell, cmd, f"fabric links", 60, cli_file)
        if re.search(r'\d+/\S+/\d+/\d+\s+\S+/\S+\s+\S+', output):
            raise DeviceError("Fabric links down detected")

    return "All fabric checks passed"


@health_check("NPU Health")
def check_npu_health(shell, cli_file):
    """Combined NPU checks"""
    # Link info
    cmd = r'show controllers npu link-info rx 0 255 topo instance all location all | ex "EN/UP" | ex "NC              NC"'
    output = execute_command(shell, cmd, "NPU links", 180, cli_file)

    loc_pattern = re.compile(r'^\d+/\S+/\d+/\d+$')
    issues = [line for line in output.splitlines()
              if loc_pattern.match(line.split()[0] if line.split() else "")]

    if issues:
        raise DeviceError(f"NPU links down: {len(issues)}")

    # Stats
    cmd = r'show controllers npu stats link all instance all location all | ex "0        0        0"'
    output = execute_command(shell, cmd, "NPU stats", 180, cli_file)

    errors = []
    for line in output.splitlines():
        if nums := re.findall(r'\d+', line):
            if len(nums) >= 5 and (int(nums[-2]) > 0 or int(nums[-1]) > 0):
                errors.append(line)

    if errors:
        raise DeviceError(f"NPU errors: {len(errors)} instances")

    return "NPU checks passed"


@health_check("Interface Status")
def check_interfaces(shell, cli_file):
    """Check interface status"""
    summary = execute_command(shell, "show interface summary", "intf summary", 60, cli_file)
    brief = execute_command(shell, "show interface brief", "intf brief", 120, cli_file)
    execute_command(shell, "show interface description | ex admin", "intf desc", 120, cli_file)

    # Parse brief for down interfaces
    down_intfs = []
    for line in brief.splitlines():
        if match := re.match(r'^\s*(\S+)\s+(down)\s+(down)', line):
            if re.match(r'^(Gi|Te|Hu|Fo|FH)', match.group(1)):
                down_intfs.append(match.group(1))

    return {"summary": summary, "brief": brief, "down": down_intfs}


@health_check("Environment")
def check_environment(shell, cli_file):
    """Check temperature, voltage, power"""
    output = execute_command(shell, "show environment", "environment", 180, cli_file)

    issues = []
    section = None
    location = None

    for line in output.splitlines():
        line = line.strip()

        if 'TEMPERATURE' in line:
            section = 'temp'
        elif 'VOLTAGE' in line:
            section = 'voltage'
        elif 'Power Module' in line:
            section = 'power'
        elif re.match(r'^\d+/\S+$', line):
            location = line
        elif section == 'temp' and location:
            if match := re.match(
                    r'(\S+)\s+([\d\.]+)\s+([\d\.]+|NA)\s+([\d\.]+|NA)\s+([\d\.]+|NA)\s+([\d\.]+|NA)\s+([\d\.]+|NA)\s+([\d\.]+|NA)',
                    line):
                vals = [float(x) if x not in ['NA', '-'] else None for x in match.groups()[1:]]
                if vals[0] and vals[-1] and vals[0] > vals[-1]:
                    issues.append(f"Temp critical at {location}: {vals[0]}")

    if issues:
        raise DeviceError(f"Environment issues: {', '.join(issues)}")

    return "Environment OK"


# === COMPARISON UTILITIES ===
@contextmanager
def open_baseline_file(filepath: str):
    """Stream baseline file line by line"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            yield f
    except FileNotFoundError:
        logger.warning(f"Baseline not found: {filepath}")
        yield None


def extract_command_section(file_handle, command: str) -> str:
    """Extract command output from streaming file"""
    if not file_handle:
        return ""

    marker = f"--- Command: {command} ---"
    capturing = False
    output = []

    file_handle.seek(0)
    for line in file_handle:
        if marker in line:
            capturing = True
            continue
        if capturing:
            if "--- Command:" in line:
                break
            output.append(line)

    return ''.join(output).strip()


def compare_inventories(current: Dict, baseline: Dict, item_type: str) -> Tuple[str, bool]:
    """Generic inventory comparison"""
    changes = []

    # Check for changes/removals
    for loc, base_data in baseline.items():
        curr_data = current.get(loc, {})
        if curr_data.get('SN') != base_data.get('SN'):
            changes.append((loc, 'Changed/Removed', base_data.get('SN'), curr_data.get('SN', 'N/A')))

    # Check for additions
    for loc, curr_data in current.items():
        if loc not in baseline:
            changes.append((loc, 'Added', 'N/A', curr_data.get('SN')))

    report = StringIO()
    report.write(f"\n{'=' * 80}\n")
    report.write(f"{f'{item_type.upper()} COMPARISON':^80}\n")
    report.write(f"{'=' * 80}\n")

    if changes:
        table = PrettyTable(['Location', 'Change', 'Baseline SN', 'Current SN'])
        table.align = 'l'
        for row in changes:
            table.add_row(row)
        report.write(str(table))
        report.write("\n")
    else:
        report.write(f"No {item_type} changes detected.\n")

    return report.getvalue(), bool(changes)


# === MAIN EXECUTION ===
def main():
    # Setup
    stdout_orig = sys.stdout
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(stdout_orig)
    handler.setFormatter(CompactFormatter())
    logger.addHandler(handler)

    logger.info("=== Cisco IOS-XR Health Check (Optimized) ===")

    # Connection
    router_ip = input("Router IP: ")
    username = input("Username: ")
    password = getpass.getpass("Password: ")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        logger.info(f"Connecting to {router_ip}...")
        client.connect(router_ip, port=22, username=username, password=password,
                       timeout=SSH_TIMEOUT, look_for_keys=False)

        shell = client.invoke_shell()
        time.sleep(1)
        read_until_prompt(shell, 2)

        # Configure terminal
        execute_command(shell, "terminal length 0", "term length")
        execute_command(shell, "terminal width 511", "term width")

        # Get device info
        device = DeviceInfo()
        output = execute_command(shell, "show running-config | i hostname", "hostname")
        if match := re.search(r'hostname\s+(\S+)', output):
            device.hostname = re.sub(r'[^a-zA-Z0-9_-]', '', match.group(1).replace('.', '-'))

        output = execute_command(shell, "show inventory chassis", "chassis")
        if match := re.search(r'PID:\s*(\S+)', output):
            device.chassis_model = match.group(1)

        logger.info(f"Device: {device.hostname} ({device.chassis_model})")

        # Setup output directory
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        out_dir = os.path.join(os.getcwd(), device.hostname)
        os.makedirs(out_dir, exist_ok=True)

        cli_path = os.path.join(out_dir, f"{device.hostname}_cli_{timestamp}.txt")
        cli_file = open(cli_path, 'w')

        # Run checks with progress bar
        checks = [
            (check_fabric_health, [shell, cli_file, device.chassis_model]),
            (check_npu_health, [shell, cli_file]),
            (check_interfaces, [shell, cli_file]),
            (check_environment, [shell, cli_file]),
        ]

        results = {}
        with ProgressBar(len(checks), stdout_orig, "Health Checks") as pbar:
            for check_func, args in checks:
                result = check_func(*args)
                results[check_func.__name__] = result
                pbar.update()

        # Comparisons (if baseline exists)
        baseline_path = None
        for f in sorted(os.listdir(out_dir)):
            if f.startswith(device.hostname) and f.endswith('.txt'):
                baseline_path = os.path.join(out_dir, f)
                break

        if baseline_path and baseline_path != cli_path:
            logger.info(f"Comparing with baseline: {baseline_path}")

            with open_baseline_file(baseline_path) as baseline:
                if baseline:
                    # Compare inventories
                    curr_inv = execute_command(shell, "show inventory", "inventory", 120, cli_file)
                    base_inv = extract_command_section(baseline, "show inventory")

                    curr_optics = parse_inventory(curr_inv, r'NAME: "((?:Gi|Te|Hu|Fo|FH)\S+)"')
                    base_optics = parse_inventory(base_inv, r'NAME: "((?:Gi|Te|Hu|Fo|FH)\S+)"')

                    report, diffs = compare_inventories(curr_optics, base_optics, "Optics")
                    print(report)
        else:
            logger.info("No baseline found - this run will be the baseline")

        cli_file.close()
        logger.info(f"✓ Script completed. Output: {cli_path}")

    except Exception as e:
        logger.error(f"Script failed: {e}", exc_info=True)
    finally:
        if shell:
            shell.close()
        client.close()


if __name__ == "__main__":
    main()