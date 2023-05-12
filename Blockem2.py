import os
import requests
import ipaddress
import time

# Your API key from AlienVault OTX
api_key = '505fcff9a52d1a8b43197054cb6ff939a7b0bc7abbe5176385a018639a3900dc'

# The directory of the currently running script
script_dir = os.path.dirname(os.path.abspath(__file__))

# The path to the 'nids.log' file
input_file_path = os.path.join(script_dir, 'nidsclean.log')

# The path to the 'blockthese.txt' file
output_file_path = os.path.join(script_dir, 'blockthese.txt')

# Open the 'nids.log' file and read the IP addresses
with open(input_file_path, 'r') as file:
    ip_addresses = [line.strip() for line in file]

# Open the 'blockthese.txt' file and prepare to write the IP addresses
with open(output_file_path, 'w') as output_file:

    # For each IP address
    for ip_address in ip_addresses:
        # Skip private IP addresses
        if ipaddress.ip_address(ip_address).is_private:
            continue

        print(f'Checking IP address {ip_address}...')
        
        try:
            # Define the API URL
            url = f'https://otx.alienvault.com:443/api/v1/indicators/IPv4/{ip_address}/general'

            # Define the headers
            headers = {
                'X-OTX-API-KEY': api_key,
            }

            # Send a GET request to the API
            response = requests.get(url, headers=headers)

            # If the GET request is successful
            if response.status_code == 200:
                # Parse the response as JSON
                data = response.json()

                # If the IP address is in the OTX database
                if data['pulse_info']['count'] > 0:
                    # Write the IP address to the 'blockthese.txt' file
                    output_file.write(ip_address + '\n')

            else:
                # Print an error message
                print(f'An error occurred while checking the IP address {ip_address}: {response.status_code}, {response.text}.')
        
        except Exception as e:
            print(f'An error occurred while processing the IP address {ip_address}: {str(e)}')
            
        # Wait for 1 second to avoid hitting the API rate limit
        time.sleep(1)
