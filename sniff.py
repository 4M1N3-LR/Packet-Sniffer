from scapy.all import *
import sys
import os 
import argparse
import matplotlib.pyplot as plt


def process_pcap(file_name):
    print('Opening {}...'.format(file_name))

if __name__ == '__main__':

    print('')

    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('-f', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    parser.add_argument('-p', metavar='<protocol>',
                        help='specific protocol to analyze', required=False)
    args = parser.parse_args()
    
    file_name = args.f
    proto = args.p
    if not os.path.isfile(file_name):
        print('The file "{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    process_pcap(file_name)

    count = 0
    print(proto)
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        count += 1

    print('The file {} contains {} packets'.format(file_name, count))

    packets = PcapReader(file_name)
    for packet in packets:
        if packet.haslayer(proto):
            print(packet.show())

    sys.exit(0)


