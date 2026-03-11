"""
Packet Analyzer
Author: Nicholas Fernandez

Analyzes a packet capture (.pcap) file and reports:
- protocol statistics
- packet source/destination addresses
- top source IP talkers
"""

from scapy.all import rdpcap


# -----------------------------------------------------
# Analyze packets inside the pcap file
# -----------------------------------------------------
def analyze_pcap(file):

    packets = rdpcap(file)

    total_packets = len(packets)

    tcp_count = 0
    udp_count = 0
    icmp_count = 0

    # dictionary to count source IP traffic
    source_ips = {}

    print("Analyzing packets...\n")

    for pkt in packets:

        # protocol detection
        if pkt.haslayer("TCP"):
            tcp_count += 1

        elif pkt.haslayer("UDP"):
            udp_count += 1

        elif pkt.haslayer("ICMP"):
            icmp_count += 1

        # check if packet contains IP layer
        if pkt.haslayer("IP"):

            src = pkt["IP"].src
            dst = pkt["IP"].dst

            print("Packet:", src, "->", dst)

            # count source IP occurrences
            if src in source_ips:
                source_ips[src] += 1
            else:
                source_ips[src] = 1

    # -------------------------------------------------
    # Print protocol statistics
    # -------------------------------------------------
    print("\nPacket Statistics")
    print("------------------")

    print("Total packets:", total_packets)
    print("TCP packets:", tcp_count)
    print("UDP packets:", udp_count)
    print("ICMP packets:", icmp_count)

    # -------------------------------------------------
    # Top talkers analysis
    # -------------------------------------------------
    print("\nTop Source IP Talkers")
    print("----------------------")

    # sort dictionary by packet count, sort by packet count then reverse for greatest firs
    sorted_ips = sorted(source_ips.items(), key=lambda x: x[1], reverse=True)

    for ip, count in sorted_ips[:5]:
        print(ip, "→", count, "packets")


# -----------------------------------------------------
# Main program
# -----------------------------------------------------
if __name__ == "__main__":

    file = "sample_capture.pcap"

    analyze_pcap(file)
