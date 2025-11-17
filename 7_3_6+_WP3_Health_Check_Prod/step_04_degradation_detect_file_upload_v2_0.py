#!/usr/bin/env python3
import sys
import os
import platform
import subprocess
from pathlib import Path


def ensure_compatible_environment():
    """Smart environment setup for file upload script - only paramiko needed."""

    # First, check if we already have working dependencies in the current environment
    def check_dependencies():
        """Check if required dependencies are available and working."""
        missing_deps = []
        try:
            import paramiko
            # Quick functionality test
            paramiko.SSHClient()  # Test if paramiko works
        except ImportError:
            missing_deps.append("paramiko")
        except Exception as e:
            # Paramiko available but might have issues
            print(f"⚠️  paramiko available but may have compatibility issues: {e}")

        # Part IV doesn't need prettytable, so don't check for it
        return missing_deps

    # Check current environment first
    missing_deps = check_dependencies()

    if not missing_deps:
        print("✅ All required dependencies are available in current environment")
        return  # Everything works, no need for venv

    print(f"📦 Missing dependencies: {', '.join(missing_deps)}")
    print("🔄 Attempting to set up isolated environment...")

    arch = platform.machine()
    script_dir = Path(__file__).parent
    venv_path = script_dir / f".venv_{arch}"
    venv_python = venv_path / "bin" / "python"

    # Check if we're already running in the correct venv
    if sys.prefix == str(venv_path):
        return  # Already in correct environment

    # Check if venv exists and has working dependencies
    if venv_python.exists():
        try:
            result = subprocess.run(
                [str(venv_python), "-c", "import paramiko; paramiko.SSHClient()"],
                capture_output=True,
                timeout=10
            )
            if result.returncode == 0:
                print("✅ Found existing compatible virtual environment")
                # Re-execute script with venv Python
                os.execv(str(venv_python), [str(venv_python)] + sys.argv)
        except Exception as e:
            print(f"⚠️  Existing venv test failed: {e}")

    # Only try to create venv if dependencies are missing and system supports it
    print(f"🔧 Creating virtual environment for {arch} architecture...")

    try:
        # Test if system supports venv creation
        import venv

        # Create venv with error handling
        venv.create(venv_path, with_pip=True)
        print("✅ Virtual environment created successfully")

        # Install dependencies (only paramiko for Part IV)
        pip_path = venv_path / "bin" / "pip"

        print("📦 Installing dependencies...")
        subprocess.run([str(pip_path), "install", "--upgrade", "pip"],
                       check=True, capture_output=True, timeout=60)
        subprocess.run([str(pip_path), "install", "paramiko"],  # Only paramiko needed
                       check=True, capture_output=True, timeout=120)

        print("✅ Dependencies installed successfully")
        print("🔄 Restarting script with virtual environment...\n")

        # Re-execute with new venv
        os.execv(str(venv_python), [str(venv_python)] + sys.argv)

    except ImportError:
        print("❌ Virtual environment module not available on this system")
        print("💡 Install with: sudo apt-get install python3-venv")
        print("🔄 Continuing with system Python...")
    except subprocess.CalledProcessError as e:
        print(f"❌ Virtual environment setup failed: {e}")
        print("💡 This might be due to missing system packages:")
        print("   - Ubuntu/Debian: sudo apt-get install python3-venv python3-pip")
        print("   - CentOS/RHEL: sudo yum install python3-venv python3-pip")
        print("🔄 Continuing with system Python...")
    except Exception as e:
        print(f"❌ Virtual environment setup failed: {e}")
        print("🔄 Continuing with system Python...")

    # Final dependency check before proceeding
    final_missing = check_dependencies()
    if final_missing:
        print(f"\n❌ Still missing dependencies: {', '.join(final_missing)}")
        print(f"📦 Install with: pip3 install {' '.join(final_missing)}")
        print(f"   or: python3 -m pip install {' '.join(final_missing)}")

        user_choice = input("Continue anyway? This may cause script failures. (y/N): ").lower()
        if user_choice not in ['y', 'yes']:
            print("Script execution cancelled.")
            sys.exit(1)
        print("⚠️  Proceeding with missing dependencies - expect potential failures...\n")
    else:
        print("✅ All dependencies now available. Continuing...\n")


# Run environment check before any other imports
ensure_compatible_environment()



import os
import glob
import getpass
import paramiko
import argparse


usage_text = '''\
usage: step_04_degradation_detect_file_upload_v2_0.py
  --hosts HOSTS [HOSTS ...]
  --username USERNAME
  --password PASSWORD
  [--timeout TIMEOUT]
  [--max_workers MAX_WORKERS]
'''

# Fixed remote path on the device
REMOTE_PATH = '/misc/disk1/'

# Static local file pattern to upload
LOCAL_FILE_PATTERN = os.path.expanduser('~/monitor*')


def sftp_upload_files(hosts, username, password=None, timeout=30, max_workers=5):
    for hostname in hosts:
        try:
            print(f"Connecting to {hostname}...")
            transport = paramiko.Transport((hostname, 22))  # Port fixed to 22
            transport.connect(username=username, password=password)
            sftp = paramiko.SFTPClient.from_transport(transport)

            # Change to fixed remote directory
            try:
                sftp.chdir(REMOTE_PATH)
            except IOError:
                print(f"Remote path {REMOTE_PATH} does not exist or is not accessible on {hostname}.")
                sftp.close()
                transport.close()
                continue

            # Find local files matching the pattern
            files_to_upload = glob.glob(LOCAL_FILE_PATTERN)
            if not files_to_upload:
                print(f"No files matching pattern '{LOCAL_FILE_PATTERN}' found locally.")
                sftp.close()
                transport.close()
                continue

            # Upload each file
            for file_path in files_to_upload:
                filename = os.path.basename(file_path)
                print(f"Uploading {filename} to {hostname}:{REMOTE_PATH} ...")
                sftp.put(file_path, filename)
                print(f"Uploaded {filename} successfully.")

            sftp.close()
            transport.close()
            print(f"All files uploaded successfully to {hostname}.")

        except paramiko.AuthenticationException:
            print(f"Authentication failed for {hostname}. Please check your username and password.")
        except paramiko.SSHException as ssh_err:
            print(f"SSH connection error for {hostname}: {ssh_err}")
        except Exception as e:
            print(f"An unexpected error occurred for {hostname}: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="SFTP upload script with fixed remote path and simplified parameters",
        usage=usage_text,
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument('--hosts', nargs='+', required=True, help='List of hostnames')
    parser.add_argument('--username', required=True, help='Username for login')
    parser.add_argument('--password', help='Password for login (will be prompted if not provided)')
    parser.add_argument('--timeout', type=int, default=30, help='Connection timeout in seconds (default: 30)')
    parser.add_argument('--max_workers', type=int, default=5, help='Max parallel uploads (default: 5)')

    args = parser.parse_args()

    # If password is not provided, prompt for password
    if not args.password:
        args.password = getpass.getpass("Enter SSH password: ")

    sftp_upload_files(
        hosts=args.hosts,
        username=args.username,
        password=args.password,
        timeout=args.timeout,
        max_workers=args.max_workers
    )


if __name__ == "__main__":
    main()