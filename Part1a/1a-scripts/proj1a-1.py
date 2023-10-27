# Code has been sampled from Muhammad Haroon's code, with modifications for each 1a activity.
# Original code: https://github.com/Haroon96/ecs152a-fall-2023/blob/main/week1/code/dpkt-example.py

# Code has been further repurposed from an ICMP example provided in the dpkt documentation, found at https://kbandla.github.io/dpkt/. Under the BSD-3 license
# Specific example: https://dpkt.readthedocs.io/en/latest/print_icmp.html

# Socket library comes from a print_packets example (in the dpkt documentation). See here: https://dpkt.readthedocs.io/en/latest/_modules/examples/print_packets.html

import dpkt
import sys

# Because MAC physical address is supported on the ICMPv6 layer, but not IP addresses, we use the socket library to display the MAC addresses of the source and destination machines.
import socket
import datetime

# Ping google.com for 20 packets.

def parse_pcap(pcap_file):

    # read the pcap file
    f = open(pcap_file, 'rb')
    pcap = dpkt.pcap.Reader(f)

    # iterate over packets
    n = 0
    for timestamp, data in pcap:

        # convert to link layer object
        eth = dpkt.ethernet.Ethernet(data)

        # do not proceed if there is no network layer data
        if not isinstance(eth.data, dpkt.ip6.IP6):
            continue
        
        # extract network layer data
        ip6 = eth.data

        # read network layer headers (ICMPv6)
        # using ICMP6, because our network traffic is ICMPv6 (as opposed to ICMPv4) 
        # note: the ICMP protocol does not have a registered port
        n += 1
        if isinstance(ip6.data, dpkt.icmp6.ICMP6):
            icmp6 = ip6.data
            print('-- Packet', n, '--')
            print('\tTimestamp: ', str(datetime.datetime.fromtimestamp(timestamp, datetime.UTC)))
            print('\tIP: %s -> %s ' % \
                 (socket.inet_ntop(socket.AF_INET6, ip6.src), socket.inet_ntop(socket.AF_INET6, ip6.dst)))
            print(f'\tData: {icmp6}')
            
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("No pcap file specified!")
    else:
        parse_pcap(sys.argv[1])
