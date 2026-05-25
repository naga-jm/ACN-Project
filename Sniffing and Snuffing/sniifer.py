#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
    pkt.show()


pkt = sniff(iface="br-1d902ca0c748", filter="icmp", prn=print_pkt)
 
