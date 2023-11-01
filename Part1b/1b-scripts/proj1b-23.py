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

# Figure out activities in ass1_2.pcap and ass1_3.pcap, and determine their subtle differences 

def parse_pcap(pcap_file):

    # read the pcap file
    f = open(pcap_file, 'rb')
    pcap = dpkt.pcap.Reader(f)

    # iterate over packets
    n = 0
    for timestamp, data in pcap:
        n += 1
        # convert to link layer object
        eth = dpkt.ethernet.Ethernet(data)

        # do not proceed if there is no network layer data
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        
        # extract network layer data
        ip = eth.data

        # read network layer headers (ICMPv4)
        # note: the ICMP protocol does not have a registered port
        if isinstance(ip.data, dpkt.icmp.ICMP):
            icmp = ip.data
            print('-- Packet', n, '--')
            print('\tTimestamp: ', str(datetime.datetime.fromtimestamp(timestamp, datetime.UTC)))
            print('\tIP: %s -> %s ' % \
                 (socket.inet_ntop(socket.AF_INET, ip.src), socket.inet_ntop(socket.AF_INET, ip.dst)))
            print('\t-- ICMP properties --\n')
            print('\ttype:%d code:%d checksum:%d data: %s\n' %
                  (icmp.type, icmp.code, icmp.sum, repr(icmp.data)))
            
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("No pcap file specified!")
    else:
        print('Printout for ass1_2.pcap: \n')
        parse_pcap(sys.argv[1])
        print('Printout for ass1_3.pcap: \n')
        parse_pcap(sys.argv[2])
