from scapy.all import *
import sys
import os 
import argparse
import matplotlib.pyplot as plt
import pyfiglet


def read_pcap():
    file_name=str(input("enter pcap file location: "))
    if not os.path.isfile(file_name):
        print('The file "{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)
    print('Opening {}...'.format(file_name))
    return file_name

def show_protocol_details(X,Y):
        packets = PcapReader(X)
        print("+ Full Analysis : 1 \n+ Brief Analysis : 2")
        D=int(input("Enter 1 or 2 : "))
        for packet in packets:
            if packet.haslayer(Y):
                if D==1:
                    print(packet.show())
                if D==2:
                    print(packet.summary())


def main():
    print(pyfiglet.figlet_format("Packet Sniffer V1", font = "epic" ))
    
    file_name = read_pcap()

    N=0
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        N += 1
    print('The file {} contains {} packets'.format(file_name, N))


    print("What you want to do :\n1) Analyze specific protocol\n2) xx")
    choice=int(input("Choose a number : "))

    if choice == 1:
        proto=str(input("Enter protocol name:"))
        show_protocol_details(file_name,proto)


    



main()