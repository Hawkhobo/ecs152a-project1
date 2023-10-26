# Code has been sampled from Muhammad Haroon's code, with modifications for each 1a activity.
# Original code: https://github.com/Haroon96/ecs152a-fall-2023/blob/main/week1/code/dpkt-example.py

import dpkt
import sys

# Ping google.com for 20 packets.

def parse_pcap(pcap_file):

    # read the pcap file
    f = open(pcap_file, 'rb')
    pcap = dpkt.pcap.Reader(f)

    # iterate over packets
    for timestamp, data in pcap:

        eth = dpkt.ethernet.Ethernet(data)

        # do not proceed if there is no network layer data
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        
        ip = eth.data

        # do not proceed if there is no transport layer data
        # if not isinstance(ip.data, dpkt.tcp.TCP):
        #     continue

        # tcp = ip.data



if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("No pcap file specified!")
    else:
        parse_pcap(sys.argv[1])
