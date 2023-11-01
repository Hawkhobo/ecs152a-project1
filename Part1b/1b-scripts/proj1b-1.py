# Code is a modification of Muhammad Haroon's code, with modifications for each 1a activity.
# Original code: https://github.com/Haroon96/ecs152a-fall-2023/blob/main/week1/code/dpkt-example.py

import dpkt
import sys

# socket is used in the dpkt docs, and allows us to printout the IP (or MAC) source and destination addresses for each packet
import datetime
import socket

def parse_pcap(pcap_file):

    # read the pcap file
    f = open(pcap_file, 'rb')
    pcap = dpkt.pcap.Reader(f)

    n = 0
    # iterate over packets
    for timestamp, data in pcap:
        n += 1
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
        # here we check length because we don't know protocol yet
        if not len(tcp.data) > 0:
            continue

        # extract application layer data
        ## if destination port is 80, it is a http request
        # Secrets are sent to the server, and not received by the client (according to prompt). Just need to check dport 
        if tcp.dport == 80:
            try:
                print('-- HTTP Request, Packet', n, '--')
                print('\tTimestamp: ', str(datetime.datetime.fromtimestamp(timestamp, datetime.UTC)))
                print('\tSource to Destination: %s -> %s ' % \
                     (socket.inet_ntop(socket.AF_INET6, ip6.src), socket.inet_ntop(socket.AF_INET6, ip6.dst)))
                http = dpkt.http.Request(tcp.data)
                # repr() is a method of http.py, belonging to the dpkt library. We believe it prints out the Request parameters 
                print('\tHTTP request: ', repr(http))
            except:
                print("Malformed HTTP Request packet")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("No pcap file specified!")
    else:
        parse_pcap(sys.argv[1])
        