import os
import re

# The directory of the currently running script
script_dir = os.path.dirname(os.path.abspath(__file__))

# The path to the 'nids.log' file
input_file_path = os.path.join(script_dir, 'nids.log')

# The path to the 'nidsclean.log' file
output_file_path = os.path.join(script_dir, 'nidsclean.log')

# The regex pattern for IP addresses
ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

# Open the 'nids.log' file and read the data
with open(input_file_path, 'r') as file:
    data = file.read()

# Find all IP addresses in the data
ip_addresses = re.findall(ip_pattern, data)

# Open the 'nidsclean.log' file and write the IP addresses
with open(output_file_path, 'w') as file:
    for ip_address in ip_addresses:
        file.write(ip_address + '\n')
