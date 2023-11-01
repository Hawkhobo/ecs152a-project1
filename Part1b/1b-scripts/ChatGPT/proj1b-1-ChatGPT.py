
import sys
import dpkt
import socket

def extract_secrets(pcap_file):
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if isinstance(eth.data, dpkt.ip6.IP6) and isinstance(eth.data.data, dpkt.tcp.TCP):
                    ip6 = eth.data
                    tcp = ip6.data
                    if tcp.dport == 80 or tcp.dport == 443:  # HTTP or HTTPS
                        packet_repr = repr(tcp.data)

                        # Look for secrets in the string representation (customize this part)
                        if 'password' in packet_repr or 'secret' in packet_repr:
                            src_ip = ip6.src
                            src_port = tcp.sport
                            dst_ip = ip6.dst
                            dst_port = tcp.dport
                            print(f"Secret sent from {src_ip}:{src_port} to {dst_ip}:{dst_port} - {packet_repr}")

            except Exception as e:
                # Handle exceptions if packet parsing fails
                pass

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("No pcap file specified!")
    else:
        extract_secrets(sys.argv[1])
