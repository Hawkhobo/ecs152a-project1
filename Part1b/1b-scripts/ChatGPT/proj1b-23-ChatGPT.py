
import dpkt
import sys
import socket
import datetime

def parse_pcap(pcap_file):
    try:
        with open(pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            n = 0
            for timestamp, data in pcap:
                n += 1
                eth = dpkt.ethernet.Ethernet(data)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                if isinstance(ip.data, dpkt.icmp.ICMP):
                    icmp = ip.data
                    print('-- Packet', n, '--')
                    print('Timestamp:', datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc))
                    print(f'IP: {socket.inet_ntop(socket.AF_INET, ip.src)} -> {socket.inet_ntop(socket.AF_INET, ip.dst)}')
                    print('-- ICMP properties --')
                    print(f'Type: {icmp.type}, Code: {icmp.code}, Checksum: {icmp.sum}')
                    print('Data:', repr(icmp.data))
    except FileNotFoundError:
        print(f"File '{pcap_file}' not found.")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python script.py ass1_2.pcap ass1_3.pcap")
    else:
        file1, file2 = sys.argv[1], sys.argv[2]
        print(f'Printout for {file1}:\n')
        parse_pcap(file1)
        print(f'Printout for {file2}:\n')
        parse_pcap(file2)

