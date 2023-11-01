
import dpkt
import sys

def read_pcap(file_path):
    packets = []
    with open(file_path, 'rb') as pcap_file:
        pcap = dpkt.pcap.Reader(pcap_file)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.icmp.ICMP):
                packets.append((ts, eth))
    return packets

def compare_icmp_pcaps(pcap1, pcap2):
    differences = []
    for (ts1, eth1), (ts2, eth2) in zip(pcap1, pcap2):
        if eth1 != eth2:
            differences.append((ts1, eth1, eth2))
    return differences

if len(sys.argv) != 3:
    print("Usage: python analyze_and_compare_icmp_pcaps.py icmp_pcap1.pcap icmp_pcap2.pcap")
    sys.exit(1)

icmp_pcap_file1 = sys.argv[1]
icmp_pcap_file2 = sys.argv[2]

try:
    icmp_packets1 = read_pcap(icmp_pcap_file1)
    icmp_packets2 = read_pcap(icmp_pcap_file2)
except FileNotFoundError:
    print("File not found.")
    sys.exit(1)

differences = compare_icmp_pcaps(icmp_packets1, icmp_packets2)

if not differences:
    print("No differences found in ICMP packets.")
else:
    print("Differences found in ICMP packets:")
    for ts, eth1, eth2 in differences:
        print(f"Timestamp: {ts}")
        print(f"ICMP Packet 1: {eth1.data}")
        print(f"ICMP Packet 2: {eth2.data}")
        print()
