import os
import shutil
import time
import logging
from pathlib import Path
from scapy.all import *
from datetime import datetime

# Function to get all available drives
def get_drives():
    drives = []
    for drive_letter in range(ord("C"), ord("Z") + 1):
        drive = f"{chr(drive_letter)}:"
        if os.path.exists(drive):
            drives.append(drive)
    return drives

# Function to backup logs to all available drives
def backup_logs(log_file):
    drives = get_drives()
    for drive in drives:
        backup_folder = Path(f"{drive}/Daily_NIDS_Data")
        backup_folder.mkdir(exist_ok=True)
        shutil.copy2(log_file, backup_folder / log_file)

# Set up logging
logging.basicConfig(filename='nids.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s: %(message)s')

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
            if "sql injection" in payload.lower() or "xss" in payload.lower():
                logging.warning(f"HTTP/HTTPS attack detected: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, Payload: {payload}")

        # Check for outbound traffic
        if dst_port == 443 and packet[TCP].flags == 0x18:
            logging.warning(f"Outbound traffic detected: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, Payload: {payload}")

        # Implement deep packet inspection for SSH traffic
        if dst_port == 22:
            if "ssh" in payload.lower():
                if len(payload) > 500 and "invalid" not in payload.lower():
                    logging.warning(f"Potential SSH attack detected: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, Payload: {payload}")

                # Utilize threat intelligence feeds to detect known threats
        if dst_port == 80 and src_ip in threat_feed:
            logging.warning(f"Threat detected: {src_ip} -> {dst_ip}:{dst_port}, Payload: {payload}")

        # Implement correlation rules to detect patterns of behavior
        # Check for multiple connections to the same port in a short period of time
        connection_counts = {}
        current_time = datetime.now()
        for pkt in sniff(filter=f"tcp and dst port {dst_port}", timeout=10, store=1):
            pkt_dst_ip = pkt[IP].dst
            if pkt_dst_ip not in connection_counts:
                connection_counts[pkt_dst_ip] = 1
            else:
                connection_counts[pkt_dst_ip] += 1

        for ip, count in connection_counts.items():
            if count > 5:
                logging.warning(f"Multiple connections detected: {src_ip}:{src_port} -> {ip}:{dst_port}, Count: {count}")

# Start packet capture
sniff(prn=packet_callback, filter="tcp", store=0)

# Main loop to process network traffic and backup logs every 24 hours
while True:
    # Capture and process network traffic
    sniff(prn=packet_callback, filter="tcp", store=0)
    
    # Backup logs every 24 hours
    time.sleep(86400)
    backup_logs("nids.log")

       
