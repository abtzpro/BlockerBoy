import subprocess
import time

BLOCKLIST_FILE = 'block.txt'  # The script and file are in the same directory
UPDATE_INTERVAL = 24 * 60 * 60  # Update interval in seconds (24 hours)

def fetch_blocklist(file_path):
    with open(file_path, 'r') as file:
        return file.read().splitlines()

def block_ip(ip):
    cmd = f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in action=block remoteip={ip}"
    subprocess.run(cmd, shell=True, check=True)

def main():
    while True:
        try:
            blocklist = fetch_blocklist(BLOCKLIST_FILE)
            for ip in blocklist:
                block_ip(ip)
            time.sleep(UPDATE_INTERVAL)  # Wait for the next update
        except Exception as e:
            print(f"An error occurred: {e}")
            time.sleep(UPDATE_INTERVAL)  # Wait for the next update

if __name__ == "__main__":
    main()
