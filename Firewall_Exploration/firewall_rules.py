#!/usr/bin/env python3
"""
firewall_rules.py
-----------------
Helper script to apply, list, and clear iptables firewall rules
for each task in the Firewall Exploration SEED Lab.

Usage:
    python3 firewall_rules.py --task 2a --action apply
    python3 firewall_rules.py --task 2b --action apply
    python3 firewall_rules.py --task 2c --action apply
    python3 firewall_rules.py --task 3b --action apply
    python3 firewall_rules.py --task 4  --action apply
    python3 firewall_rules.py --action clear
    python3 firewall_rules.py --action list
"""

import subprocess
import argparse
import sys


def run(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command with sudo, print it, and return the result."""
    full_cmd = f"sudo {cmd}"
    print(f"  $ {full_cmd}")
    result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout.strip())
    if result.stderr:
        print(result.stderr.strip(), file=sys.stderr)
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed (exit {result.returncode}): {full_cmd}")
    return result


def clear_rules():
    """Flush all iptables rules and reset default policies to ACCEPT."""
    print("\n[*] Clearing all iptables rules...")
    run("iptables -F")
    run("iptables -t nat -F")
    run("iptables -P INPUT ACCEPT")
    run("iptables -P FORWARD ACCEPT")
    run("iptables -P OUTPUT ACCEPT")
    print("[+] Rules cleared.\n")


def list_rules():
    """Display current iptables rules."""
    print("\n[*] Current iptables rules (filter table):")
    run("iptables -L -v -n --line-numbers", check=False)
    print("\n[*] NAT table rules:")
    run("iptables -t nat -L -v -n --line-numbers", check=False)


def apply_task_2a():
    """
    Task 2.A: Protect the Router
    - Allow ICMP ping in and out.
    - Default INPUT policy: DROP.
    """
    print("\n[*] Applying Task 2.A — Protect the Router...")
    run("iptables -A INPUT  -p icmp --icmp-type echo-request -j ACCEPT")
    run("iptables -A OUTPUT -p icmp --icmp-type echo-reply   -j ACCEPT")
    run("iptables -P INPUT DROP")
    print("[+] Task 2.A rules applied.\n")


def apply_task_2b():
    """
    Task 2.B: Protect the Internal Network
    - Internal hosts can ping external, but not the reverse.
    - Default FORWARD policy: DROP.
    """
    print("\n[*] Applying Task 2.B — Protect the Internal Network...")
    # Allow internal → external ping (request out)
    run("iptables -A FORWARD -i eth1 -o eth0 -p icmp --icmp-type echo-request -j ACCEPT")
    # Allow external → internal ping reply (response back)
    run("iptables -A FORWARD -i eth0 -o eth1 -p icmp --icmp-type echo-reply   -j ACCEPT")
    # Block external → internal ping (request in)
    run("iptables -A FORWARD -i eth0 -o eth1 -p icmp --icmp-type echo-request -j DROP")
    # Default drop all forwarded traffic
    run("iptables -P FORWARD DROP")
    print("[+] Task 2.B rules applied.\n")


def apply_task_2c():
    """
    Task 2.C: Protect Internal Servers
    - Allow telnet only to 192.168.60.5 from outside.
    - Allow all internal-to-internal traffic.
    - Default FORWARD policy: DROP.
    """
    print("\n[*] Applying Task 2.C — Protect Internal Servers...")
    # Outside → 192.168.60.5 telnet (port 23) allowed
    run("iptables -A FORWARD -i eth0 -o eth1 -p tcp --dport 23 -d 192.168.60.5 -j ACCEPT")
    # Response from 192.168.60.5 back to outside allowed
    run("iptables -A FORWARD -i eth1 -o eth0 -p tcp --sport 23 -s 192.168.60.5 -j ACCEPT")
    # All internal-to-internal traffic allowed
    run("iptables -A FORWARD -i eth1 -o eth1 -j ACCEPT")
    # Default drop
    run("iptables -P FORWARD DROP")
    print("[+] Task 2.C rules applied.\n")


def apply_task_3b():
    """
    Task 3.B: Stateful Firewall
    - Allow external telnet only to 192.168.60.5.
    - Allow ESTABLISHED/RELATED return traffic (stateful).
    - Allow all internal → external traffic.
    - Default FORWARD policy: DROP.
    """
    print("\n[*] Applying Task 3.B — Stateful Firewall...")
    # Allow new connections to the permitted internal server
    run("iptables -A FORWARD -i eth0 -o eth1 -p tcp --dport 23 -d 192.168.60.5 -j ACCEPT")
    # Allow return traffic for established/related connections
    run("iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT")
    # Allow internal hosts to initiate any outbound connection
    run("iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT")
    # Default drop all other forwarded traffic
    run("iptables -P FORWARD DROP")
    print("[+] Task 3.B rules applied.\n")


def apply_task_4():
    """
    Task 4: Rate Limiting
    - Limit ICMP from 10.9.0.5 to 10 packets/min with burst of 5.
    - Drop packets exceeding the limit (essential second rule).
    """
    print("\n[*] Applying Task 4 — Rate Limiting...")
    # Accept up to 10 ICMP packets/minute with burst of 5
    run(
        "iptables -A FORWARD -i eth0 -o eth1 -p icmp --icmp-type echo-request "
        "-m limit --limit 10/min --limit-burst 5 -j ACCEPT"
    )
    # Drop all ICMP that exceed the rate limit
    run(
        "iptables -A FORWARD -i eth0 -o eth1 -p icmp --icmp-type echo-request "
        "-j DROP"
    )
    print("[+] Task 4 rules applied.\n")
    print("    Test with: ping -i 0.2 192.168.60.5  (from 10.9.0.5)")


TASK_MAP = {
    "2a": apply_task_2a,
    "2b": apply_task_2b,
    "2c": apply_task_2c,
    "3b": apply_task_3b,
    "4":  apply_task_4,
}


def main():
    parser = argparse.ArgumentParser(
        description="Apply iptables rules for Firewall Exploration SEED Lab tasks."
    )
    parser.add_argument(
        "--task",
        choices=list(TASK_MAP.keys()),
        help="Which task's rules to apply (e.g. 2a, 2b, 2c, 3b, 4).",
    )
    parser.add_argument(
        "--action",
        choices=["apply", "clear", "list"],
        required=True,
        help="Action to perform.",
    )
    args = parser.parse_args()

    if args.action == "clear":
        clear_rules()
    elif args.action == "list":
        list_rules()
    elif args.action == "apply":
        if not args.task:
            parser.error("--task is required when --action is apply")
        clear_rules()
        TASK_MAP[args.task]()
        list_rules()


if __name__ == "__main__":
    main()
