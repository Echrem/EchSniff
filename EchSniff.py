#!/usr/bin/env python3
from scapy.all import *
from optparse import OptionParser

print('''
      
 ______          _       ____            _    __    __ 
 | ____|   ___  | |__   / ___|   _ __   (_)  / _|  / _|
 |  _|    / __| | '_ \  \___ \  | '_ \  | | | |_  | |_ 
 | |___  | (__  | | | |  ___) | | | | | | | |  _| |  _|
 |_____|  \___| |_| |_| |____/  |_| |_| |_| |_|   |_|  
                                                           
''')

def packet_handler(packet):
    print(packet.summary())

def main():
    parser = OptionParser(usage='usage: EchSniff.py -i interface -c count ')
    parser.add_option("-i", "--interface", dest="interface",
                      help="Specify the network interface to use")
    parser.add_option("-c", "--count", dest="count", type="int", default=10,
                      help="Number of packets to capture")

    (options, args) = parser.parse_args()

    if not options.interface:
        parser.error("You must specify an interface using -i option")

    print(f"Sniffing on interface {options.interface} for {options.count} packets...")
    sniff(prn=packet_handler, iface=options.interface, count=options.count)

if __name__ == "__main__":
    main()
