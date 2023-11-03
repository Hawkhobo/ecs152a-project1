# Use the requests library to record HTTP traffic
import requests

# Use dpkt to parse the packets
import dpkt 
import sys

# Prinout some information for the DNS packets. Code is modified from dpkt documentation
def printout(dns):
    # Print out the DNS info
    print('Queries: {:d}'.format(len(dns.qd)))
    for query in dns.qd:
        print('\t {:s} Type:{:d}'.format(query.name, query.type))

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
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        
        # extract network layer data
        ip = eth.data

        # do not proceed if there is no transport layer data
        if not isinstance(ip.data, dpkt.udp.UDP):
            continue

        # extract transport layer data
        udp = ip.data

        # do not proceed if there is no application layer data
        if not len(udp.data) > 0:
            continue

        # Wireshark shows request to URL results in 2 DNS packets. Grab their info
        if udp.dport == 53:
            try:
                print('-- DNS Request, Packet', n, '--')
                print('\tSource to Destination: %s -> %s ' % \
                     (ip.src, ip.dst))
                dns = dpkt.dns.DNS()
                dns.unpack(udp.data)
                printout(dns)
                
            except:
                print("Malformed DNS Request packet")
        ## source port is 0-65535, random assignment from OS
        elif udp.sport >= 0:
            try:
                print('-- DNS Response, Packet', n, '--')
                print('\tSource to Destination: %s -> %s ' % \
                     (ip.src, ip.dst))
                dns = dpkt.dns.DNS()
                dns.unpack(udp.data)
                printout(dns)
                
            except:
                print("Malformed DNS Response packet")
                
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("No pcap file specified!")
    else:

        # Add a request header which specifies our student-id, named `Student-Id:`
        SID = '921423591'

        # Grab the requested URL, pass in a custom request header "Student-Id:"
        response = requests.get('https://kartik-labeling-cvpr-0ed3099180c2.herokuapp.com/ecs152a_ass1', headers = {"Student-Id": SID}, verify=False)
        # Print out the headers from the HTTP response
        print(response.headers)
        
        parse_pcap(sys.argv[1])
        