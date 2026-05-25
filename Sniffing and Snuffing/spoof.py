#!/usr/bin/env python3
from scapy.all import *

a = IP()
a.dst = "10.9.0.6"     # target 

b = ICMP()
p = a/b

send(p)
