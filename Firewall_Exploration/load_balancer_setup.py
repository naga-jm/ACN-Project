#!/usr/bin/env python3
"""
load_balancer_setup.py
----------------------
Configure iptables NAT rules to distribute UDP traffic across three
internal servers — SEED Lab Task 5 (Load Balancing).

Supports two modes:
  nth    — Round-robin (deterministic, even distribution)
  random — Probabilistic (statistical distribution)

Usage:
    python3 load_balancer_setup.py --mode nth    --port 8080
    python3 load_balancer_setup.py --mode random --port 8080
    python3 load_balancer_setup.py --clear
    python3 load_balancer_setup.py --status

Requirements:
  - Run on the router container as root (or with sudo).
  - iptables with 'statistic' extension support.
  - UDP listeners running on each backend host:
        nc -luk 8080   (on each of .5, .6, .7)
"""

import subprocess
import argparse
import sys


# ── Configuration ─────────────────────────────────────────────────────────────

BACKENDS = [
    "192.168.60.5",
    "192.168.60.6",
    "192.168.60.7",
]

DEFAULT_PORT = 8080


# ── Helpers ───────────────────────────────────────────────────────────────────

def run(cmd: str, check: bool = True) -> int:
    """Run a shell command, print it, return exit code."""
    full = f"sudo {cmd}"
    print(f"  $ {full}")
    result = subprocess.run(full, shell=True, capture_output=True, text=True)
    if result.stdout.strip():
        print(f"    {result.stdout.strip()}")
    if result.stderr.strip():
        print(f"    [stderr] {result.stderr.strip()}", file=sys.stderr)
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed (rc={result.returncode}): {full}")
    return result.returncode


def clear_nat():
    """Flush NAT PREROUTING rules and remove the MASQUERADE rule."""
    print("\n[*] Clearing NAT PREROUTING rules...")
    run("iptables -t nat -F PREROUTING", check=False)
    run("iptables -t nat -F POSTROUTING", check=False)
    print("[+] NAT rules cleared.\n")


def add_masquerade():
    """Add MASQUERADE so that reply packets are routed back correctly."""
    run("iptables -t nat -A POSTROUTING -j MASQUERADE")


# ── Round-robin (nth) mode ────────────────────────────────────────────────────

def setup_nth(port: int, backends: list[str]):
    """
    Distribute packets in strict round-robin using the 'nth' statistic mode.

    Logic:
      Rule 1: every 3rd packet starting at packet 0  → backend[0]
      Rule 2: every 2nd of the remaining             → backend[1]
      Rule 3: all remaining                          → backend[2]

    This gives an exact 1/3 split.
    """
    print(f"\n[*] Setting up ROUND-ROBIN (nth) load balancing on UDP port {port}...")
    n = len(backends)

    for i, backend in enumerate(backends):
        remaining = n - i          # packets still un-matched at this rule
        if remaining == 1:
            # Last rule: catch everything left
            rule = (
                f"iptables -t nat -A PREROUTING "
                f"-p udp --dport {port} "
                f"-j DNAT --to-destination {backend}:{port}"
            )
        else:
            rule = (
                f"iptables -t nat -A PREROUTING "
                f"-p udp --dport {port} "
                f"-m statistic --mode nth --every {remaining} --packet 0 "
                f"-j DNAT --to-destination {backend}:{port}"
            )
        run(rule)

    add_masquerade()
    print(f"\n[+] Round-robin rules applied across: {', '.join(backends)}")
    print( "    Expected distribution: equal (1/N per host)")
    print(f"\n    Test: send packets from external host (10.9.0.5):")
    print(f"    $ for i in $(seq 1 12); do echo \"msg$i\" | nc -u -w1 <router_ip> {port}; done\n")


# ── Random mode ───────────────────────────────────────────────────────────────

def setup_random(port: int, backends: list[str]):
    """
    Distribute packets randomly using the 'random' statistic mode.

    Each rule independently accepts a packet with a given probability:
      backend[0]: p = 1/3  ≈ 0.333
      backend[1]: p = 1/2  (of the remaining 2/3)  → net 1/3
      backend[2]: catch-all                         → net 1/3
    """
    print(f"\n[*] Setting up RANDOM load balancing on UDP port {port}...")
    n = len(backends)

    for i, backend in enumerate(backends):
        remaining = n - i
        if remaining == 1:
            rule = (
                f"iptables -t nat -A PREROUTING "
                f"-p udp --dport {port} "
                f"-j DNAT --to-destination {backend}:{port}"
            )
        else:
            prob = round(1.0 / remaining, 6)
            rule = (
                f"iptables -t nat -A PREROUTING "
                f"-p udp --dport {port} "
                f"-m statistic --mode random --probability {prob} "
                f"-j DNAT --to-destination {backend}:{port}"
            )
        run(rule)

    add_masquerade()
    print(f"\n[+] Random rules applied across: {', '.join(backends)}")
    print( "    Expected distribution: ~1/3 each (statistical, not deterministic)")
    print(f"\n    Test: send packets from external host (10.9.0.5):")
    print(f"    $ for i in $(seq 1 30); do echo \"msg$i\" | nc -u -w1 <router_ip> {port}; done\n")


# ── Status ────────────────────────────────────────────────────────────────────

def show_status():
    print("\n[*] Current NAT rules:")
    run("iptables -t nat -L PREROUTING -v -n --line-numbers", check=False)
    print()
    run("iptables -t nat -L POSTROUTING -v -n --line-numbers", check=False)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Configure iptables load balancing for SEED Lab Task 5."
    )
    parser.add_argument(
        "--mode", choices=["nth", "random"],
        help="Load balancing mode: nth (round-robin) or random."
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help=f"UDP port to load-balance (default: {DEFAULT_PORT})."
    )
    parser.add_argument(
        "--backends", nargs="+", default=BACKENDS,
        metavar="IP",
        help=f"Backend IPs (default: {' '.join(BACKENDS)})."
    )
    parser.add_argument(
        "--clear", action="store_true",
        help="Clear all NAT rules and exit."
    )
    parser.add_argument(
        "--status", action="store_true",
        help="Show current NAT rules and exit."
    )
    args = parser.parse_args()

    if args.clear:
        clear_nat()
        return

    if args.status:
        show_status()
        return

    if not args.mode:
        parser.error("--mode is required (nth or random)")

    clear_nat()

    if args.mode == "nth":
        setup_nth(args.port, args.backends)
    else:
        setup_random(args.port, args.backends)

    show_status()


if __name__ == "__main__":
    main()
