import re
import json
import requests
import subprocess
import os
import time
from datetime import datetime
from colorama import Fore, init

# Initialize colorama
init(autoreset=True)

OTX_API_KEY = 'YOUR_OTX_API_KEY'
OTX_URL = 'https://otx.alienvault.com:443/api/v1/indicators/IPv4/{}/general'
RULE_NAME_PREFIX = "Block_Malicious_IP_"
API_DELAY = 2  # delay between API calls in seconds

def extract_ips(log_file):
    with open(log_file, 'r') as file:
        log_data = file.read()
    ips = re.findall(r'[0-9]+(?:\.[0-9]+){3}', log_data)
    # Exclude private IPs
    ips = [ip for ip in ips if not (ip.startswith('10.') or ip.startswith('192.168.') or '172.' in ip.split('.')[0] and 16 <= int(ip.split('.')[1]) <= 31)]
    return ips

def check_otx(ip):
    try:
        headers = {'X-OTX-API-KEY': OTX_API_KEY}
        response = requests.get(OTX_URL.format(ip), headers=headers)
        time.sleep(API_DELAY)  # delay to avoid rate limiting
        return response.status_code == 200 and response.json().get('pulse_info', {}).get('count', 0) > 0
    except Exception as e:
        print(Fore.YELLOW + f"Error checking OTX for IP {ip}: {e}")
        return False

def block_ip(ip, rule_name):
    try:
        result = subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', f'name={rule_name}', 'dir=in', 'action=block', f'remoteip={ip}'], capture_output=True)
        print(result.stdout, result.stderr)
        return result.returncode == 0
    except Exception as e:
        print(Fore.YELLOW + f"Error blocking IP {ip}: {e}")
        return False

def main():
    blocked_ips = set()
    checked_ips = set()  # Set of IPs already checked against OTX
    while True:
        try:
            with open('threat_feed.txt', 'w') as out_file:  # Change output file to threat_feed.txt
                ips = extract_ips('nids.log')
                out_file.write('\n'.join(ips))

            with open('Confirmed-Threat-Network-Traffic.txt', 'a') as threat_file:
                for ip in ips:
                    if ip not in checked_ips:  # Only check IPs not already checked against OTX
                        checked_ips.add(ip)  # Add IP to checked_ips set
                        print(f"Checking IP: {ip}")
                        if check_otx(ip):  # Check OTX regardless of whether IP was blocked before
                            threat_file.write(f'{ip}\n')
                            if ip not in blocked_ips:  # Only block IPs not already blocked
                                rule_name = RULE_NAME_PREFIX + datetime.now().strftime("%Y%m%d%H%M%S")
                                if block_ip(ip, rule_name):
                                    blocked_ips.add(ip)
                                    print(f'{Fore.GREEN}Successfully blocked IP:{Fore.RED} {ip}')
        except Exception as e:
            print(Fore.YELLOW + f"Error in main loop: {e}")

        time.sleep(24*60*60)

if __name__ == "__main__":
    main()
