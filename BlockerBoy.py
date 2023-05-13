import re
import json
import requests
import subprocess
import os
import time
from datetime import datetime

OTX_API_KEY = 'YOUR_OTX_API_KEY'
OTX_URL = 'https://otx.alienvault.com:443/api/v1/indicators/IPv4/{}/general'
RULE_NAME_PREFIX = "Block_Malicious_IP_"

def extract_ips(log_file):
    with open(log_file, 'r') as file:
        log_data = file.read()
    ips = re.findall(r'[0-9]+(?:\.[0-9]+){3}', log_data)
    return ips

def check_otx(ip):
    headers = {'X-OTX-API-KEY': OTX_API_KEY}
    response = requests.get(OTX_URL.format(ip), headers=headers)
    return response.status_code == 200 and response.json().get('pulse_info', {}).get('count', 0) > 0

def block_ip(ip, rule_name):
    result = subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', f'name={rule_name}', 'dir=in', 'action=block', f'remoteip={ip}'], capture_output=True)
    return result.returncode == 0

def main():
    blocked_ips = set()
    while True:
        with open('blockthese2.txt', 'w') as out_file:
            ips = extract_ips('nids.log')
            out_file.write('\n'.join(ips))

        with open('Confirmed-Threat-Network-Traffic.txt', 'a') as threat_file:
            for ip in ips:
                if ip not in blocked_ips and check_otx(ip):
                    threat_file.write(f'{ip}\n')
                    rule_name = RULE_NAME_PREFIX + datetime.now().strftime("%Y%m%d%H%M%S")
                    if block_ip(ip, rule_name):
                        blocked_ips.add(ip)
                        print(f'Successfully blocked IP: {ip}')

        time.sleep(24*60*60)

if __name__ == "__main__":
    main()
