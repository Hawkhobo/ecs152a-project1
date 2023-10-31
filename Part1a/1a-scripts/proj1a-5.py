# Code has been sampled from Muhammad Haroon's code, with modifications for each 1a activity.
# Original code: https://github.com/Haroon96/ecs152a-fall-2023/blob/main/week1/code/dpkt-example.py

import dpkt
import sys

# socket is used in the dpkt docs, and allows us to printout the IP (or MAC) source and destination addresses for each packet
import socket
import datetime

# Access SDF through SSH (tty.sdf.org is the host)

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
        if not isinstance(eth.data, dpkt.ip6.IP6) and not  isinstance(eth.data, dpkt.ip.IP):
            continue
        
        # extract network layer data
        ip = eth.data

        # do not proceed if there is no transport layer data
        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue

        # extract transport layer data
        tcp = ip.data

        # do not proceed if there is no application layer data
        if not len(tcp.data) > 0:
            continue

        # extract application layer data
        ## if destination port is 22, it is a SSH request
        if tcp.dport == 22:
            try:
                print('-- SSH Request Packet', n, '--')
                print('\tTimestamp: ', str(datetime.datetime.fromtimestamp(timestamp, datetime.UTC)))
                print('\tSource to Destination: %s -> %s ' % \
                     (socket.inet_ntop(socket.AF_INET, ip.src), socket.inet_ntop(socket.AF_INET, ip.dst)))
            except:
                print("Malformed SSH Request packet")
        ## if source port is 22, it is a SSH response
        elif tcp.sport == 22:
            try:
                print('-- SSH Response Packet', n, '--')
                print('\tTimestamp: ', str(datetime.datetime.fromtimestamp(timestamp, datetime.UTC)))
                print('\tSource to Destination: %s -> %s ' % \
                     (socket.inet_ntop(socket.AF_INET, ip.src), socket.inet_ntop(socket.AF_INET, ip.dst)))
            except:
                print("Malformed SSH Response packet")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("No pcap file specified!")
    else:
        parse_pcap(sys.argv[1])