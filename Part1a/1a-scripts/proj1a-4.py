# Code has been sampled from Muhammad Haroon's code, with modifications for each 1a activity.
# Original code: https://github.com/Haroon96/ecs152a-fall-2023/blob/main/week1/code/dpkt-example.py

import dpkt
import sys

# socket is used in the dpkt docs, and allows us to printout the IP (or MAC) source and destination addresses for each packet
import socket
import datetime

# Access a FTP server (Type “ftp ftp.gnu.org” in your terminal).

def parse_pcap(pcap_file):
    
    # read the pcap file
    f = open(pcap_file, 'rb')
    pcap = dpkt.pcap.Reader(f)

    # iterate over packets
    n = 0
    m = 0
    for timestamp, data in pcap:

        # convert to link layer object
        eth = dpkt.ethernet.Ethernet(data)

        # do not proceed if there is no network layer data
        if not isinstance(eth.data, dpkt.ip6.IP6):
            continue
        
        # extract network layer data
        ip6 = eth.data

        # do not proceed if there is no transport layer data
        if not isinstance(ip6.data, dpkt.tcp.TCP):
            continue

        # extract transport layer data
        tcp = ip6.data

        # do not proceed if there is no application layer data
        if not len(tcp.data) > 0:
            continue

        # extract application layer data
        ## if destination port is 21, it is a FTP request
        if tcp.dport == 21:
            try:
                n+=1
                print('-- Request Packet', n, '--')
                print('\tTimestamp: ', str(datetime.datetime.fromtimestamp(timestamp, datetime.UTC)))
                print('\tSource to Destination: %s -> %s ' % \
                     (socket.inet_ntop(socket.AF_INET6, ip6.src), socket.inet_ntop(socket.AF_INET6, ip6.dst)))
            except:
                print("Malformed FTP Request packet")
        ## if source port is 21, it is a FTP response
        elif tcp.sport == 21:
            try:
                m+=1
                print('-- Response Packet', m, '--')
                print('\tTimestamp: ', str(datetime.datetime.fromtimestamp(timestamp, datetime.UTC)))
                print('\tSource to Destination: %s -> %s ' % \
                     (socket.inet_ntop(socket.AF_INET6, ip6.src), socket.inet_ntop(socket.AF_INET6, ip6.dst)))
            except:
                print("Malformed FTP Response packet")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("No pcap file specified!")
    else:
        parse_pcap(sys.argv[1])