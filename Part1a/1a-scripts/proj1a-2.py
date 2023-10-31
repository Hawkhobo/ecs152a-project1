# Code has been sampled from Muhammad Haroon's code, with modifications for each 1a activity.
# Original code: https://github.com/Haroon96/ecs152a-fall-2023/blob/main/week1/code/dpkt-example.py

import dpkt
import sys

# socket is used in the dpkt docs, and allows us to printout the IP (or MAC) source and destination addresses for each packet
import socket
import datetime

# Visit http://example.com in your browser.

def parse_pcap(pcap_file):

    # read the pcap file
    f = open(pcap_file, 'rb')
    pcap = dpkt.pcap.Reader(f)

    # iterate over packets
    n = 0
    httpCount = 0
    httpsCount = 0
    for timestamp, data in pcap:
        n += 1
        # convert to link layer object
        eth = dpkt.ethernet.Ethernet(data)
        
        # do not proceed if there is no network layer data
        if not isinstance(eth.data, dpkt.ip6.IP6) and not  isinstance(eth.data, dpkt.ip.IP):
            continue
        
        ip = eth.data

        # do not proceed if there is no transport layer data
        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue
        
        tcp = ip.data

        # do not proceed if there is no application layer data
        #if not len(tcp.data) > 0:
         #   continue
        
        # extract application layer data
        if tcp.dport == 80:
            try:
                httpCount += 1
                print('-- HTTP Request, Packet', n, '--')
                print('\tTimestamp: ', str(datetime.datetime.fromtimestamp(timestamp, datetime.UTC)))
                print('\tSource to Destination: %s -> %s ' % \
                     (socket.inet_ntop(socket.AF_INET, ip.src), socket.inet_ntop(socket.AF_INET, ip.dst)))
            except:
                print("Malformed HTTP Request packet")
        ## if source port is 80, it is a http response
        elif tcp.sport == 80:
            try:
                httpCount += 1
                print('-- HTTP Response, Packet', n, '--')
                print('\tTimestamp: ', str(datetime.datetime.fromtimestamp(timestamp, datetime.UTC)))
                print('\tSource to Destination: %s -> %s ' % \
                     (socket.inet_ntop(socket.AF_INET, ip.src), socket.inet_ntop(socket.AF_INET, ip.dst)))
            except:
                print("Malformed HTTP Response packet")
        # Determine if there are any HTTPS protocol packets. HTTPS request/response is standardized to port 443
        elif tcp.dport == 443:
            try:
                httpsCount += 1
                print('-- HTTPS Request, Packet', n, '--')
                print('\tTimestamp: ', str(datetime.datetime.fromtimestamp(timestamp, datetime.UTC)))
                print('\tSource to Destination: %s -> %s ' % \
                     (socket.inet_ntop(socket.AF_INET, ip.src), socket.inet_ntop(socket.AF_INET, ip.dst)))
            except:
                print("Malformed HTTPS Request packet")
        elif tcp.sport == 443:
            try:
                httpsCount += 1
                print('-- HTTPS Response, Packet', n, '--')
                print('\tTimestamp: ', str(datetime.datetime.fromtimestamp(timestamp, datetime.UTC)))
                print('\tSource to Destination: %s -> %s ' % \
                     (socket.inet_ntop(socket.AF_INET, ip.src), socket.inet_ntop(socket.AF_INET, ip.dst)))
            except:
                print("Malformed HTTPS Response packet")
                
    print('-- HTTP Count: ', httpCount, '--')
    print('-- HTTPS Count: ', httpsCount, '--')

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("No pcap file specified!")
    else:
        parse_pcap(sys.argv[1])
        