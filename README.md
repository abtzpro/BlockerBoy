## BlockerBoy

A work in progress, basic NIDS and nefarious traffic cross-referencer/blocker, for windows based machines

## Usage

You can use "NIDS2.py" as a basic network intrusion detection system to export live real time network logs as "nids.log". (these logs can further be used for an SEIM)

You can then use "NidsCleanData.py" to extract only the IPs from "nids.log".

You can then use "Blockem2".py to check the extracted IPs against OTX API (AlienVault) pulses. 
"Blockem2.py" will ignore private IP addresses for now and any IP returned as nefarious in an AlienVault pulse will be exported to the local script directory within a text file named "blockthese.txt". 

You can then rename "blockthese.txt" to "block.txt" and use "BlockerBoy.py" to block the IPs that came back in a Pulse found on Alienvault. 

## Developer Notes

I am currently working to update the scripts to create a functional program with these functions so that a user only needs to launch the NIDS2.py file and the rest will be automated on a 24 hour basis. ie: every 24 hours a scheduled loop of the above functions would occur. The future of NIDS2.py holds the ability to launch and keep NIDS2.py running in the background while the rest of the work is done for you. 

This system is designed for windows 10 home. I have not tested it on pro or any other OS and thus, it is using the stock windows firewall to perform blocking. 

(note you can leave BlockerBoy.py running and simply update the "block.txt" file with blockthese.txt data as it comes. Ie: BlockerBoy will block the newly added IPs) 

## Important first steps before running the script

Ensure you update "blockem2.py" where I have left comments ie "# Your API key from AlienVault OTX" with your Alienvault OTX API Key in order for this system to work correctly.

## Developed by 

Adam Rivers, abtzpro, Hello Security LLC, and help from AI performing the following: debugging/function suggestion/function addition
