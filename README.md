## BlockerBoy

A work in progress, basic NIDS and nefarious traffic cross-referencer/blocker, for windows based machines

## Usage

You can use "NIDS2.py" as a basic network intrusion detection system to export live real time network logs as a logfile called "nids.log". (These logs can further be used for an SEIM)
you can then leave "NIDS2.py" running in the background as your NIDS.

The "BlockerBoy.py" script is designed to parse the "nids.log" for IP data, checks them against AlienVault's OTX (Open Threat Exchange), and blocks potentially harmful IPs using the Windows Firewall. It skips IPs that have already been blocked to save time, and runs the main script function every 24 hours as long as the script remains open and running in the background. 

## Getting Started

These instructions will guide you on how to deploy the script on your local windows machine.

### Prerequisites

- Python 3.7 or higher
- An active internet connection
- Windows 10 Home or higher
- Administrative rights to create Windows Firewall rules
- AlienVault OTX API key

### Dependencies

The BlockerBoy.py script depends on the `requests` library. Install it with:

```bash
pip install requests
```

## Deployment

1. Clone this repository or download the scripts.
2. Replace 'YOUR_OTX_API_KEY' in the "BlockerBoy.py" script with your AlienVault OTX API key.
3. Run the script as an administrator.

## Usage

Download the repo as a zip and unzip the files. The files should be in their own directory you can label it whatever just remember, this directory will be the output directory of your NIDS logs and thus must be the directory the scripts are run from to ensure BlockerBoy.py can find the nids.log file exported and updated real time by NIDS2.py file. The BlockerBoy.py script will run automatically every 24 hours. 

## Script Breakdown

NIDS2.py: 

Get Drives and Backup Logs- The script defines functions to get all available drives on the system and to backup a specified log file to each of these drives.

Logging Setup- The script sets up logging with a log file named nids.log. It logs information with a timestamp and the level of the logged information (INFO, WARNING, etc.).

Network Settings- The script prompts the user to specify whether the network is a business or home-based network. Depending on the answer, it sets the ports to be monitored.

Threat Intelligence Feed- The script loads a threat intelligence feed from a file named threat_feed.txt. This feed is a list of known malicious IP addresses.

Packet Callback Function- The script defines a function to process each captured packet. This function checks whether the packet has the TCP and IP layers. If it does, the function extracts information such as source and destination IP addresses, source and destination ports, and the payload of the TCP layer. It then checks this information against certain conditions (e.g., plaintext credentials in mail traffic, SSH brute-force attacks, HTTP/HTTPS attacks, outbound traffic, potential SSH attacks) and logs any suspicious activities. It also uses the threat intelligence feed to detect known threats and implements correlation rules to detect patterns of behavior, such as multiple connections to the same port in a short period of time.

Packet Capture- The script starts packet capture using the Scapy's sniff() function, with the defined packet callback function as the processing function for each captured packet. It filters only TCP packets and does not store them.

Main Loop- In the main loop, the script repeatedly performs the packet capture and processing, and backs up the logs to all available drives every 24 hours.

_____________________________________________________________________________________________________________________________________________________________________________________________________________________

BlockerBoy.py:

IP Extraction- The script reads a file named nids.log and extracts all IP addresses from it. The IP addresses are written into a new file named blockthese2.txt.

Threat Checking- Each IP address in blockthese2.txt is then checked against AlienVault's Open Threat Exchange (OTX), a threat intelligence service. This is done using AlienVault's OTX API. The script sends a request to the API for each IP address, checking whether there are any threat pulses associated with that IP.

Threat Logging- If an IP address is found to be associated with any threat pulses, it's considered malicious. All such malicious IPs are written into a new file named Confirmed-Threat-Network-Traffic.txt.

IP Blocking- The script then interacts with Windows Firewall to block all the malicious IPs logged in the Confirmed-Threat-Network-Traffic.txt file. It creates a new inbound rule for each malicious IP to block any incoming traffic from it. The script ensures it doesn't block an IP if it's already blocked.

Automated Run- The script is designed to execute the above steps every 24 hours. This means it will continuously update its list of malicious IPs, ensuring your system stays protected against any new threats.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

- Thanks to AlienVault OTX for providing the threat intelligence data.
- Thanks to Python Software Foundation for the Python programming language.
- Thanks to AI for debugging and function suggestion purposes.

## Developed By

Adam Rivers, Abtzpro, Hello Security LLC
