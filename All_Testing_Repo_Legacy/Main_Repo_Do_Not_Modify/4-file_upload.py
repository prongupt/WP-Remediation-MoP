import os
import glob
import getpass
import paramiko

remote_path = '/misc/disk1/'
# Use the Downloads folder path with the file pattern
local_file_pattern = os.path.expanduser('~/Downloads/monitor*')


def sftp_upload_files():
    try:
        hostname = input("Enter the router hostname: ")
        username = input("Enter your username: ")
        password = getpass.getpass("Enter your password: ")

        transport = paramiko.Transport((hostname, 22))
        transport.connect(username=username, password=password)

        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.chdir(remote_path)

        files_to_upload = glob.glob(local_file_pattern)

        if not files_to_upload:
            print(f"No files matching pattern '{local_file_pattern}' found locally.")
            return

        for file in files_to_upload:
            filename = os.path.basename(file)
            print(f"Uploading {filename} to {remote_path} ...")
            sftp.put(file, filename)
            print(f"Uploaded {filename} successfully.")

        sftp.close()
        transport.close()
        print("All files uploaded successfully.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    sftp_upload_files()