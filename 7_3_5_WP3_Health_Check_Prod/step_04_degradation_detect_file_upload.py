import os
import glob
import getpass
import paramiko
import argparse


usage_text = '''\
usage: step_04_degradation_detect_file_upload.py
  --hosts HOSTS [HOSTS ...]
  --username USERNAME
  --password PASSWORD
  [--timeout TIMEOUT]
  [--max_workers MAX_WORKERS]
'''

# Fixed remote path on the device
REMOTE_PATH = '/misc/disk1/'

# Static local file pattern to upload
LOCAL_FILE_PATTERN = os.path.expanduser('~/Downloads/monitor*')


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
    parser.add_argument('--password', required=True, help='Password for login')
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