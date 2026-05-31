#!/usr/bin/env python3
"""
conntrack_monitor.py
--------------------
Monitor and parse Linux connection tracking (conntrack) output for
the Firewall Exploration SEED Lab — Task 3.A.

Requires: conntrack-tools   (apt install conntrack)
Run as root or with sudo.

Usage:
    python3 conntrack_monitor.py              # watch live, refresh every 2s
    python3 conntrack_monitor.py --flush      # flush table first, then watch
    python3 conntrack_monitor.py --once       # dump table once and exit
    python3 conntrack_monitor.py --proto tcp  # filter by protocol
"""

import subprocess
import argparse
import time
import re
import sys
from dataclasses import dataclass, field
from typing import Optional


# ── Data model ───────────────────────────────────────────────────────────────

@dataclass
class ConntrackEntry:
    proto: str
    timeout: Optional[int]
    state: Optional[str]
    src: str
    dst: str
    sport: Optional[str]
    dport: Optional[str]
    flags: list[str] = field(default_factory=list)
    raw: str = ""

    def __str__(self) -> str:
        sport_s = f":{self.sport}" if self.sport else ""
        dport_s = f":{self.dport}" if self.dport else ""
        state_s = f" [{self.state}]" if self.state else ""
        timeout_s = f" ttl={self.timeout}s" if self.timeout is not None else ""
        flags_s = f" {' '.join(self.flags)}" if self.flags else ""
        return (
            f"{self.proto.upper():5}{state_s:15}{timeout_s:12} "
            f"{self.src}{sport_s} → {self.dst}{dport_s}{flags_s}"
        )


# ── Parsing ───────────────────────────────────────────────────────────────────

# Example conntrack -L lines:
# tcp      6 431974 ESTABLISHED src=192.168.60.6 dst=192.168.60.5 sport=... [ASSURED]
# icmp     1 29 src=10.9.0.5 dst=192.168.60.5 type=8 code=0 ...
# udp      17 15 src=10.9.0.5 dst=192.168.60.5 sport=... [UNREPLIED]

_FLAG_RE = re.compile(r'\[(ASSURED|UNREPLIED|FIXED_TIMEOUT|EXPECTED)\]')


def parse_line(line: str) -> Optional[ConntrackEntry]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    parts = line.split()
    if len(parts) < 4:
        return None

    proto = parts[0]
    timeout = None
    state = None
    idx = 2  # skip proto + proto_number

    # Optional numeric timeout
    if idx < len(parts) and parts[idx].isdigit():
        timeout = int(parts[idx])
        idx += 1

    # Optional TCP state word (ESTABLISHED, TIME_WAIT, etc.)
    tcp_states = {"ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT",
                  "SYN_RECV", "FIN_WAIT", "CLOSE", "LISTEN", "NONE"}
    if idx < len(parts) and parts[idx] in tcp_states:
        state = parts[idx]
        idx += 1

    # Parse key=value pairs
    kv: dict[str, str] = {}
    flags: list[str] = []
    for token in parts[idx:]:
        m = _FLAG_RE.match(token)
        if m:
            flags.append(m.group(1))
            continue
        if "=" in token:
            k, _, v = token.partition("=")
            kv[k] = v

    src = kv.get("src", "?")
    dst = kv.get("dst", "?")
    sport = kv.get("sport")
    dport = kv.get("dport")

    return ConntrackEntry(
        proto=proto,
        timeout=timeout,
        state=state,
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        flags=flags,
        raw=line,
    )


# ── conntrack calls ───────────────────────────────────────────────────────────

def flush_table():
    result = subprocess.run(
        ["sudo", "conntrack", "-F"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print("[*] Connection tracking table flushed.\n")
    else:
        print(f"[!] Failed to flush: {result.stderr.strip()}", file=sys.stderr)


def fetch_entries(proto_filter: Optional[str] = None) -> list[ConntrackEntry]:
    cmd = ["sudo", "conntrack", "-L"]
    if proto_filter:
        cmd += ["-p", proto_filter]

    result = subprocess.run(cmd, capture_output=True, text=True)
    entries = []
    for line in result.stdout.splitlines():
        entry = parse_line(line)
        if entry:
            entries.append(entry)
    return entries


def print_entries(entries: list[ConntrackEntry]):
    if not entries:
        print("  (table is empty)")
        return
    print(f"  {'PROTO':<5} {'STATE':<15} {'TTL':<12} CONNECTION")
    print("  " + "-" * 70)
    for e in entries:
        print("  " + str(e))
    print(f"\n  Total: {len(entries)} connection(s)")


def summarise(entries: list[ConntrackEntry]):
    """Print per-protocol timeout summary (mirrors lab observations)."""
    from collections import defaultdict
    timeouts: dict[str, list[int]] = defaultdict(list)
    for e in entries:
        if e.timeout is not None:
            timeouts[e.proto.lower()].append(e.timeout)

    if not timeouts:
        return
    print("\n  ── Timeout summary ─────────────────────────────────")
    for proto, vals in sorted(timeouts.items()):
        avg = sum(vals) / len(vals)
        print(f"  {proto.upper():<6} entries={len(vals)}  "
              f"min={min(vals)}s  max={max(vals)}s  avg={avg:.0f}s")
    print()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Monitor Linux conntrack table (SEED Lab Task 3.A)."
    )
    parser.add_argument("--flush",  action="store_true",
                        help="Flush the conntrack table before monitoring.")
    parser.add_argument("--once",   action="store_true",
                        help="Dump the table once and exit.")
    parser.add_argument("--proto",  metavar="PROTO",
                        help="Filter by protocol (tcp, udp, icmp).")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="Refresh interval in seconds (default: 2).")
    args = parser.parse_args()

    if args.flush:
        flush_table()

    if args.once:
        entries = fetch_entries(args.proto)
        print_entries(entries)
        summarise(entries)
        return

    # Live watch loop
    print(f"[*] Watching conntrack table (Ctrl-C to stop, "
          f"refresh every {args.interval}s)…\n")
    try:
        while True:
            entries = fetch_entries(args.proto)
            # Clear screen
            print("\033[H\033[J", end="")
            print(f"conntrack live — {time.strftime('%H:%M:%S')}"
                  + (f"  [proto={args.proto}]" if args.proto else ""))
            print("=" * 72)
            print_entries(entries)
            summarise(entries)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] Stopped.")


if __name__ == "__main__":
    main()
