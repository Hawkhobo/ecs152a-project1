# Code has been sampled from Muhammad Haroon's code, with modifications for each 1a activity.
# Original code: https://github.com/Haroon96/ecs152a-fall-2023/blob/main/week1/code/dpkt-example.py

import dpkt
import sys

# socket is used in the dpkt docs, and allows us to printout the IP (or MAC) source and destination addresses for each packet
import socket
import datetime

# Visit http://httpforever.com in your browser.

def parse_pcap(pcap_file):

    # read the pcap file
    f = open(pcap_file, 'rb')
    pcap = dpkt.pcap.Reader(f)

    # iterate over packets
    for timestamp, data in pcap:

        # convert to link layer object
        eth = dpkt.ethernet.Ethernet(data)

        # do not proceed if there is no network layer data
        if not isinstance(eth.data, dpkt.ip6.IP6):
            continue
        
        ip6 = eth.data

        # do not proceed if there is no transport layer data
        if not isinstance(ip6.data, dpkt.udp.UDP):
            continue
        
        udp = ip6.data

        # do not proceed if there is no application layer data
        if not len(udp.data) > 0:
            continue

        # extract application layer data
        if udp.dport == 53: # dns port number = 53 (server-side)
            try:
                n += 1
                dns = dpkt.dns.DNS()
                # dns.unpack(udp.data)
                print('-- Destination Packet', n, '--')
                print('\tTimestamp: ', str(datetime.datetime.fromtimestamp(timestamp, datetime.UTC)))
                print('\tIP: %s -> %s ' % \
                     (socket.inet_ntop(socket.AF_INET6, ip6.src), socket.inet_ntop(socket.AF_INET6, ip6.dst)))
            except:
                print("Error parsing DNS")
        ## source port is 0-65535, random assignment from OS 
        elif udp.sport >= 0:
            try:
                m += 1
                dns = dpkt.dns.DNS()
                dns.unpack(udp.data)
                print('-- Source Packet', m, '--')
                print('\tTimestamp: ', str(datetime.datetime.fromtimestamp(timestamp, datetime.UTC)))
                print('\tIP: %s -> %s ' % \
                     (socket.inet_ntop(socket.AF_INET6, ip6.src), socket.inet_ntop(socket.AF_INET6, ip6.dst)))
            except:
                print("Error parsing DNS")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("No pcap file specified!")
    else:
        parse_pcap(sys.argv[1])