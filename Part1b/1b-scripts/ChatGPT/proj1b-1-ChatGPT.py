
import dpkt
import sys
import socket
import datetime

def parse_pcap(pcap_file):
    try:
        with open(pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for n, (timestamp, data) in enumerate(pcap, start=1):
                eth = dpkt.ethernet.Ethernet(data)
                if isinstance(eth.data, dpkt.ip6.IP6):
                    ip6 = eth.data
                    if isinstance(ip6.data, dpkt.tcp.TCP) and len(ip6.data.data) > 0:
                        tcp = ip6.data
                        if tcp.dport == 80:
                            try:
                                print(f'-- HTTP Request, Packet {n} --')
                                print(f'\tTimestamp: {datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)}')
                                print(f'\tSource to Destination: {socket.inet_ntop(socket.AF_INET6, ip6.src)} -> {socket.inet_ntop(socket.AF_INET6, ip6.dst)}')
                                http_request = dpkt.http.Request(tcp.data)
                                print(f'\tHTTP request: {repr(http_request)}')
                            except dpkt.dpkt.NeedData:
                                print('Malformed HTTP Request packet')
    except FileNotFoundError:
        print(f"File '{pcap_file}' not found!")
    except dpkt.dpkt.UnpackError:
        print("Error unpacking data from the pcap file.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("No pcap file specified!")
    else:
        parse_pcap(sys.argv[1])


