
import dpkt
import sys

# Ping google.com for 20 packets.
# 2. Visit https://example.com in your browser.
# 3. Visit http://httpforever.com in your browser
# 4. Access a FTP server (Type “ftp ftp.gnu.org” in your terminal)
# 5. ssh into a CSIF machine ( )

def parse_pcap(pcap_file):

    # read the pcap file
    f = open(pcap_file, 'rb')
    pcap = dpkt.pcap.Reader(f)

    # iterate over packets
    for timestamp, data in pcap:

        wifi = dpkt.wifi.Wifi(data)

        # do not proceed if there is no network layer data
        if not isinstance(wifi.data, dpkt.ip.IP):
            continue
        
        ip = wifi.data

        # do not proceed if there is no transport layer data
        # if not isinstance(ip.data, dpkt.tcp.TCP):
        #     continue

        # tcp = ip.data



if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("No pcap file specified!")
    else:
        parse_pcap(sys.argv[1])
