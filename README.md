# Packet Analyzer

This project analyzes network packet capture (.pcap) files and reports basic statistics about captured network traffic.

The program reads packets from a capture file and identifies protocols such as TCP, UDP, and ICMP while also displaying packet source and destination IP addresses.

This project was inspired by my experience using Wireshark to capture and analyze network traffic. It helped me understand how packet analysis tools process and interpret network data on a smaller scale.

## Features

- Reads .pcap packet capture files
- Identifies TCP, UDP, and ICMP packets
- Displays packet source and destination IP addresses
- Reports protocol statistics
- Detects **Top Source IP Talkers** to identify hosts generating the most traffic

## Requirements

Python  
Scapy library

Install Scapy:

pip3 install scapy

## Usage

1. Capture traffic using Wireshark and save it as a `.pcap` file.

2. Place the capture file in the same directory as the script and name it:

sample_capture.pcap

3. Run the analyzer:

python3 packet_analyzer.py

## Example Output

Analyzing packets...

Packet: 192.168.1.12 -> 142.250.72.46  
Packet: 192.168.1.12 -> 142.250.72.46  
Packet: 142.250.72.46 -> 192.168.1.12  

Packet Statistics  
------------------  
Total packets: 120  
TCP packets: 90  
UDP packets: 20  
ICMP packets: 10  

Top Source IP Talkers  
----------------------  
192.168.1.12 → 54 packets  
142.250.72.46 → 33 packets  
10.0.0.5 → 21 packets  
