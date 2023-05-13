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

Download the repo as a zip and unzip the files. The files should be in their own directory you can label it whatever just remember, this directory will be the output directory of your NIDS logs and thus must be the directory the scripts are run from to ensure BlockerBoy.py can find the nids.log file exported and updated real time by NIDS2.py file. The BlockerBoy.py script will run automatically every 24 hours. BlockerBoy.py will:

- Parse the `nids.log` file for IP data and write it into a new file named `blockthese2.txt`.
- Use AlienVault's OTX API to verify these IPs.
- If any of the IPs are found to be potentially harmful, the script will record them in a file named `Confirmed-Threat-Network-Traffic.txt`.
- Finally, the script will use Windows Firewall to block these IPs.

Ensure that the scripts are run as an administrator.


## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

- Thanks to AlienVault OTX for providing the threat intelligence data.
- Thanks to Python Software Foundation for the Python programming language.
- Thanks to AI for debugging and function suggestion purposes.

## Developed By

Adam Rivers, Abtzpro, Hello Security LLC
