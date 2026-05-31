# Firewall Exploration Lab


## Overview

This lab explores how Linux firewalls work at multiple levels — from writing custom kernel modules using Netfilter hooks, to configuring stateless and stateful rules with `iptables`, to implementing rate limiting and load balancing. The environment uses SEED Lab Docker containers.

---

## Lab Environment Setup

1. Boot the SEED VM and open Firefox.
2. Navigate to SEED Labs → Network Security → **Firewall Exploration**.
3. Download and unzip `labsetup.zip` into a local folder (e.g., `~/Documents/Firewall/`).
4. From the unzipped folder, open a terminal and start Docker containers.

```bash
docker ps          # verify containers are running
docker-compose up  # start the lab containers if not running
```

**Network topology:**
- External host: `10.9.0.5` (Host-A / attacker)
- Router: `10.9.0.11` (eth0 = external, eth1 = internal `192.168.60.11`)
- Internal hosts: `192.168.60.5`, `192.168.60.6`, `192.168.60.7`

---

## Task 1: Implementing a Simple Firewall (Kernel Module)

### Task 1.A — Hello World Kernel Module

Located at `Labsetup/Files/packet_filter/hello.c`.

```bash
cat hello.c        # view the module source
cat Makefile       # view build instructions
make               # compile the module
ls hello.ko        # confirm output
sudo insmod hello.ko   # load the module
lsmod | grep hello     # list loaded modules
sudo rmmod hello       # remove the module
modinfo hello.ko       # show module info
```

### Task 1.B — Netfilter-based Firewall (`seedFilter.c`)

#### 1.B.1 — Block DNS to 8.8.8.8

```bash
cat seedfilter.c           # review the source
make                       # compile
sudo insmod seedFilter.ko  # load the firewall module
# In another terminal:
dig @8.8.8.8 example.com  # should hang/timeout
dmesg | tail               # confirm "Dropping 8.8.8.8" messages
sudo rmmod seedFilter      # unload before next subtask
```

**Result:** DNS query to `8.8.8.8` times out — firewall is working.

#### 1.B.2 — Experiment with All Netfilter Hooks

Edit `seedFilter.c` to register all hooks:
- `NF_INET_LOCAL_OUT`
- `NF_INET_POST_ROUTING`
- `NF_INET_PRE_ROUTING`
- `NF_INET_LOCAL_IN`
- `NF_INET_FORWARD`

Observed packet flow: `LOCAL_OUT → POST_ROUTING → PRE_ROUTING → LOCAL_IN`  
`FORWARD` was not triggered (packets not routed through the machine).

#### 1.B.3 — Block ICMP (Ping) and Telnet

- **Ping blocking:** ICMP Echo Requests from `10.9.0.5 → 10.9.0.1` caught at `LOCAL_IN` and dropped.
- **Telnet blocking:** TCP port 23 packets from `10.9.0.5 → 10.9.0.1` caught at `LOCAL_IN` and blocked.

---

## Task 2: Stateless Firewall Rules (iptables)

### Task 2.A — Protecting the Router

```bash
# On the seed-router container:
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
iptables -P INPUT DROP
```

**Results:**
- Ping to router (`10.9.0.11`) from Host-A: ✅ Works
- Telnet to router from Host-A: ❌ Blocked (no rule for TCP/23, default DROP)

### Task 2.B — Protecting the Internal Network

```bash
# On the router container:
iptables -A FORWARD -i eth1 -o eth0 -p icmp --icmp-type echo-request -j ACCEPT
iptables -A FORWARD -i eth0 -o eth1 -p icmp --icmp-type echo-reply -j ACCEPT
iptables -A FORWARD -i eth0 -o eth1 -p icmp --icmp-type echo-request -j DROP
iptables -P FORWARD DROP
```

**Results:**
1. Internal → External ping: ✅ Works
2. External → Internal ping: ❌ Blocked
3. External → Router ping: ✅ Works
4. Telnet between networks: ❌ Blocked

### Task 2.C — Protecting Internal Servers

```bash
# On the router container:
iptables -A FORWARD -i eth0 -o eth1 -p tcp --dport 23 -d 192.168.60.5 -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -p tcp --sport 23 -s 192.168.60.5 -j ACCEPT
iptables -A FORWARD -i eth1 -o eth1 -j ACCEPT
iptables -P FORWARD DROP
```

**Results:**
1. Outside → `192.168.60.5` telnet: ✅ Allowed
2. Outside → other internal hosts (`.6`, `.7`): ❌ Blocked
3. Internal → internal telnet: ✅ Allowed
4. Internal → external telnet: ❌ Blocked

---

## Task 3: Connection Tracking and Stateful Firewall

### Task 3.A — Connection Tracking Experiments

```bash
# On router container:
conntrack -F    # flush table
conntrack -L    # list current tracked connections
```

| Protocol | State Timeout |
|----------|--------------|
| ICMP     | 29 seconds   |
| UDP (unreplied) | 15 seconds |
| TCP ESTABLISHED | ~431,974 seconds (~5 days) |

**Key observations:**
- ICMP: timer resets with each ping packet.
- UDP: `[UNREPLIED]` for unidirectional traffic.
- TCP: `[ASSURED]` after 3-way handshake — long timeout.

### Task 3.B — Stateful Firewall Rules

```bash
# On router container:
iptables -A FORWARD -i eth0 -o eth1 -p tcp --dport 23 -d 192.168.60.5 -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
iptables -P FORWARD DROP
```

**Stateful vs Stateless comparison:**

| Feature | Stateful | Stateless |
|---------|----------|-----------|
| Rule complexity | Simple | Complex |
| Memory/CPU usage | Higher | Lower |
| Return traffic handling | Automatic | Manual rules needed |
| Security | Superior | Basic |

---

## Task 4: Rate Limiting Network Traffic

### Configuration A — With Drop Rule (Recommended)

```bash
# On router container:
iptables -A FORWARD -i eth0 -o eth1 -p icmp \
  --icmp-type echo-request \
  -m limit --limit 10/min --limit-burst 5 -j ACCEPT
iptables -A FORWARD -i eth0 -o eth1 -p icmp \
  --icmp-type echo-request -j DROP
```

**Result:** First 5 packets pass (burst). After that, ~1 packet every 6 seconds. Packet loss observed.

### Configuration B — Without Drop Rule

Without the second DROP rule, packets exceeding the rate limit fall through to the default ACCEPT policy — **rate limiting has no effect (0% packet loss)**.

> **Lesson:** In iptables, rules only affect packets that match them. The DROP rule is essential.

---

## Task 5: Load Balancing

### Round-Robin (nth mode)

```bash
# Start UDP listeners on each internal host:
nc -luk 8080   # on 192.168.60.5, .6, and .7

# On router container:
iptables -t nat -A PREROUTING -p udp --dport 8080 \
  -m statistic --mode nth --every 3 --packet 0 \
  -j DNAT --to-destination 192.168.60.5:8080
iptables -t nat -A PREROUTING -p udp --dport 8080 \
  -m statistic --mode nth --every 2 --packet 0 \
  -j DNAT --to-destination 192.168.60.6:8080
iptables -t nat -A PREROUTING -p udp --dport 8080 \
  -j DNAT --to-destination 192.168.60.7:8080
```

**Result:** Every 3rd packet goes to host1, then host2, then host3 — equal distribution.

### Random Mode

```bash
iptables -t nat -A PREROUTING -p udp --dport 8080 \
  -m statistic --mode random --probability 0.33 \
  -j DNAT --to-destination 192.168.60.5:8080
iptables -t nat -A PREROUTING -p udp --dport 8080 \
  -m statistic --mode random --probability 0.50 \
  -j DNAT --to-destination 192.168.60.6:8080
iptables -t nat -A PREROUTING -p udp --dport 8080 \
  -j DNAT --to-destination 192.168.60.7:8080
```

**Result:** Packets distributed randomly; host3 received more in testing due to statistical variance.

---

## Files

| File | Description |
|------|-------------|
| `README.md` | This document |
| `firewall_rules.py` | Helper script to apply/clear iptables rules for each task |
| `conntrack_monitor.py` | Script to monitor and parse connection tracking output |
| `load_balancer_setup.py` | Script to configure round-robin and random load balancing |

---

## References

- [SEED Labs — Firewall Exploration](https://seedsecuritylabs.org/Labs_20.04/Networking/Firewall/)
- [Linux Netfilter Documentation](https://netfilter.org/documentation/)
- [iptables man page](https://linux.die.net/man/8/iptables)
- [conntrack-tools](https://conntrack-tools.netfilter.org/)
