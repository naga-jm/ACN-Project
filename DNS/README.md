# DNS Local Attack Lab
**Author:** Naga Jyothi Mahankali  
**Lab:** SEED Labs — DNS Local Attack

---

## Overview

This lab explores DNS attack techniques in a local network environment using SEED Lab Docker containers. It covers direct DNS spoofing, DNS cache poisoning, NS record manipulation, and the DNS bailiwick protection mechanism.

---

## Lab Environment Setup

1. Boot the SEED VM and open Firefox.
2. Navigate to SEED Labs → Network Security → **DNS Local Attack**.
3. Download and unzip `labsetup.zip` into a local folder (e.g., `~/Documents/DNS/`).
4. Open a terminal in the unzipped folder and start Docker containers.

```bash
docker-compose up --detach
docker ps    # verify containers are running
```

### Network Topology

| Container | IP Address | Role |
|-----------|------------|------|
| User machine | 10.9.0.1 | DNS client |
| Local DNS server | 10.9.0.53 | BIND 9 resolver |
| Attacker machine | 10.9.0.100 | Attack origin |
| Attacker nameserver | 10.9.0.153 | Hosts fake zones (attacker32.com, example.com) |

### Pre-Attack Setup

**On User machine** — check DNS resolver config:
```bash
cat /etc/resolv.conf
dig www.example.com
```

**On Local DNS Server** — verify BIND 9 is running:
```bash
service named status
cat /etc/bind/named.conf
```

**Flush DNS cache before every attack:**
```bash
rndc flush
rndc dumpdb -cache
cat /var/cache/bind/dump.db | grep example
```

---

## Task 1: Directly Spoofing Response to the User

**Goal:** Sniff a DNS query from the user machine and send a fake DNS response directly to the user (not poisoning the DNS server cache).

**Script:** `task1_spoof_user.py`

**Steps:**
1. On the attacker machine, run: `sudo python3 task1_spoof_user.py`
2. On the user machine: `dig www.example.com`

**Result:** User receives fake IP `10.9.0.153`. DNS server cache is NOT affected.

**Key concept:** Works because the attacker is on the same LAN and can sniff the query, then race the real response with a spoofed one.

---

## Task 2: DNS Cache Poisoning — Spoofing Answers

**Goal:** Poison the local DNS server's cache so ALL users receive the fake IP for `www.example.com`.

**Script:** `task2_cache_poison.py`

**Steps:**
1. Flush DNS cache: `rndc flush`
2. On attacker: `sudo python3 task2_cache_poison.py`
3. On user: `dig www.example.com`
4. Verify: `rndc dumpdb -cache`

**Result:** Fake IP `10.9.0.1` cached and served to all users until TTL expires.

---

## Task 3: Spoofing NS Records (Authority Section — Same Domain)

**Goal:** Poison the cache with both a fake A record and a spoofed NS record pointing `example.com` to the attacker's nameserver.

**Script:** `task3_spoof_ns_samedomain.py`

**Steps:**
1. On attacker: `sudo python3 task3_spoof_ns_samedomain.py`
2. On user: `dig www.example.com`

**Result:**
- `www.example.com A 1.2.3.5` — cached ✅
- `example.com NS ns.attacker32.com` — cached ✅

**Key concept:** Same-domain NS poisoning bypasses bailiwick checks, redirecting ALL subdomain queries to the attacker's nameserver.

---

## Task 4: Spoofing NS Records for Another Domain (Cross-Domain)

**Goal:** Attempt to poison the cache with a cross-domain NS record (redirect `google.com` NS via an `example.com` response).

**Script:** `task4_spoof_ns_crossdomain.py`

**Steps:**
1. On attacker: `sudo python3 task4_spoof_ns_crossdomain.py`
2. On user: `dig www.example.com`

**Result:**
- `example.com A 1.2.3.4` — cached ✅
- `google.com NS ns.attacker32.com` — rejected ❌ (not cached)

**Key concept:** DNS Bailiwick Checking blocks this. A resolver only caches authority records within the same zone as the query.

---

## Task 5: Spoofing Records in the Additional Section

**Goal:** Test what DNS resolvers cache from the Additional section.

**Script:** `task5_spoof_additional.py`

**Steps:**
1. On attacker: `sudo python3 task5_spoof_additional.py`
2. On user: `dig www.example.com`
3. Check: `rndc dumpdb -cache`

**Results:**

| Record | Section | Cached? |
|--------|---------|---------|
| `www.example.com A 10.9.0.1` | Answer | ✅ Yes |
| `example.com NS ns.attacker32.com` | Authority | ✅ Yes |
| `ns.example.net A 5.6.7.8` | Additional | ❌ No |
| `www.facebook.com A 3.4.5.6` | Additional | ❌ No |

**Key concept:** Resolvers discard unrelated additional section records as a defense against cache poisoning.

---

## Scripts Summary

| Script | Task | Description |
|--------|------|-------------|
| `task1_spoof_user.py` | Task 1 | Sniff DNS query, send spoofed reply to user |
| `task2_cache_poison.py` | Task 2 | Poison DNS server cache with fake A record |
| `task3_spoof_ns_samedomain.py` | Task 3 | Spoof A + NS records for same domain |
| `task4_spoof_ns_crossdomain.py` | Task 4 | Attempt cross-domain NS poisoning |
| `task5_spoof_additional.py` | Task 5 | Spoof records across all response sections |

All scripts require [Scapy](https://scapy.net/) and must run as **root** on the attacker container.

---

## Key Concepts

**DNS Bailiwick Checking** — A resolver only caches records that fall within the zone of authority of the responding server. Cross-domain NS records are silently discarded.

**Cache Poisoning vs Direct Spoofing** — Direct spoofing (Task 1) only affects the querying user. Cache poisoning (Tasks 2–5) affects the DNS server and all its clients.

**Additional Section Security** — Modern resolvers are selective about additional section records; unrelated records are discarded.

---

## Cleanup

```bash
rndc flush             # flush DNS cache on DNS server
docker-compose down    # stop all containers
docker-compose up -d   # restart fresh
```

---

## References

- [SEED Labs — DNS Local Attack](https://seedsecuritylabs.org/Labs_20.04/Networking/DNS/DNS_Local/)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [RFC 5452 — DNS Bailiwick Checking](https://datatracker.ietf.org/doc/html/rfc5452)
- [BIND 9 Administrator Reference](https://bind9.readthedocs.io/)
