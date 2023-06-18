import os
import shutil
import time
import logging
import threading
import joblib
from pathlib import Path
from scapy.all import *
from datetime import datetime
from schedule import Scheduler

# Set up logging
logging.basicConfig(filename='nids.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s: %(message)s')

log_file = "nids.log"

# Load the trained model
model = joblib.load('isolation_forest_model.pkl')

# Function to get all available drives
def get_drives():
    drives = []
    for drive_letter in range(ord("C"), ord("Z") + 1):
        drive = f"{chr(drive_letter)}:"
        if os.path.exists(drive):
            drives.append(drive)
    return drives

# Function to backup logs to all available drives
def backup_logs():
    drives = get_drives()
    for drive in drives:
        backup_folder = Path(drive) / "Daily_NIDS_Data"
        backup_folder.mkdir(exist_ok=True)
        shutil.copy2(log_file, backup_folder / os.path.basename(log_file))

# Backup logs every 24 hours using a separate thread
def schedule_log_backup():
    scheduler = Scheduler()
    scheduler.every(24).hours.do(backup_logs)
    while True:
        scheduler.run_pending()
        time.sleep(1)

backup_thread = threading.Thread(target=schedule_log_backup)
backup_thread.start()

# Prompt the user to set the network settings
network_type = input("Is this a business or home-based network? Enter 'B' for business or 'H' for home: ")
if network_type.lower() == "b":
    monitored_ports = [22, 25, 80, 443]
else:
    monitored_ports = [22, 25, 80, 110, 143, 443]

# Load the threat intelligence feed
threat_feed = set()
with open('threat_feed.txt', 'r') as f:
    for line in f:
        threat_feed.add(line.strip())

# Define the packet callback function
def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        payload = str(packet[TCP].payload)

        # Feature extraction for anomaly detection
        features = [src_port, dst_port, len(payload)]
        prediction = model.predict([features])

        if prediction[0] == -1:
            logging.warning(f"Anomaly detected: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, Payload: {payload}")

        # Check for plaintext credentials in mail traffic
        if dst_port in [110, 143, 25]:
            if "user" in payload.lower() or "pass" in payload.lower():
                logging.warning(f"Plaintext credentials detected: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, Payload: {payload}")

        # Check for SSH brute-force attacks
        elif dst_port == 22:
            if "ssh" in payload.lower() and "invalid user" in payload.lower():
                logging.warning(f"SSH brute-force detected: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, Payload: {payload}")

        # Check for HTTP/HTTPS attacks
        elif dst_port in [80, 443]:
            if "sql injection" in payload.lower() or "xss" in payload.lower() or "csrf" in payload.lower():
                logging.warning(f"Web attack detected: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, Payload: {payload}")

        # Check for known malicious IPs
        if src_ip in threat_feed or dst_ip in threat_feed:
            logging.warning(f"Traffic from/to known malicious IP detected: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

# Start packet capture
sniff(prn=packet_callback, filter="tcp", store=0)
