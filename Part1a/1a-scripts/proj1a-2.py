
import dpkt
import sys

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
        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue

        tcp = ip.data

        # do not proceed if there is no application layer data
        if not len(tcp.data) > 0:
            continue

        # extract application layer data
        if tcp.dport == 80:
            try:
                http = dpkt.http.Request(tcp.data)
                print(http.headers)
            except:
                print("Malformed HTTP Request packet")
        ## if source port is 80, it is a http response
        elif tcp.sport == 80:
            try:
                http = dpkt.http.Response(tcp.data)
                print(http.headers)
            except:
                print("Malformed HTTP Response packet")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("No pcap file specified!")
    else:
        parse_pcap(sys.argv[1])