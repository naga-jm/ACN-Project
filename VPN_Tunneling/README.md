# VPN Tunneling Lab
**Author:** Naga Jyothi Mahankali  
**Course:** Network Security — SEED Labs  
**Topic:** Building a VPN Tunnel from Scratch using TUN/TAP Interfaces

---

## 📋 Table of Contents
- [Lab Overview](#lab-overview)
- [Lab Setup Environment](#lab-setup-environment)
- [Network Topology](#network-topology)
- [Task 1: Network Setup & Connectivity Tests](#task-1-network-setup--connectivity-tests)
- [Task 2: Create and Configure TUN Interface](#task-2-create-and-configure-tun-interface)
  - [Task 2.a: Custom Interface Name](#task-2a-custom-interface-name)
  - [Task 2.b: Set Up the TUN Interface](#task-2b-set-up-the-tun-interface)
  - [Task 2.c: Read from the TUN Interface](#task-2c-read-from-the-tun-interface)
  - [Task 2.d: Write to the TUN Interface](#task-2d-write-to-the-tun-interface)
- [Task 3: Send IP Packet to VPN Server Through Tunnel](#task-3-send-ip-packet-to-vpn-server-through-tunnel)
- [Task 4: Set Up VPN Server-Side TUN and Forwarding](#task-4-set-up-vpn-server-side-tun-and-forwarding)
- [Task 5: Handling Traffic in Both Directions](#task-5-handling-traffic-in-both-directions)
- [Task 6: Tunnel-Breaking Experiment](#task-6-tunnel-breaking-experiment)
- [Task 7: Routing Experiment on Host V](#task-7-routing-experiment-on-host-v)
- [Task 8: VPN Between Private Networks](#task-8-vpn-between-private-networks)
- [Task 9: Experiment with the TAP Interface](#task-9-experiment-with-the-tap-interface)
- [Key Observations](#key-observations)

---

## Lab Overview

This lab focuses on **building a VPN tunnel from scratch** using Linux TUN/TAP virtual interfaces. Rather than using existing VPN software, we implement the core tunneling logic ourselves using Python and Scapy. The lab covers:

- Creating and configuring TUN (Layer 3) and TAP (Layer 2) virtual interfaces
- Reading and writing raw IP packets through the TUN interface
- Encapsulating inner IP packets inside UDP for transport across the "Internet"
- Building a complete client-server VPN that connects isolated private networks
- Understanding how routing, forwarding, and tunnel recovery work

---

## Lab Setup Environment

### Step 1 — Download the Lab Setup
1. Open the SEED VM and launch **Firefox**
2. Go to: **SEED Labs → Network Security → VPN Tunneling Lab**
3. Download the **labsetup.zip** file

### Step 2 — Prepare the Lab Directory
```bash
# Move to Documents > VPN folder and unzip
unzip labsetup.zip

# Right-click inside the Labsetup folder → Open Terminal
```

### Step 3 — Build and Start Docker Containers
```bash
cd ~/VPN/Labsetup

dcbuild    # Build all container images
dcup       # Start all containers
```

### Step 4 — List Running Containers
```bash
dockps

# Output:
# 5b4f4e3bc035  server-router
# 6f0ed5854dd3  host-192.168.60.5
# 2b3a13321ab3  client-10.9.0.5
# 8815d8f28a87  host-192.168.60.6
```

### Step 5 — Connect to Containers
```bash
docksh 5b4    # VPN Server (server-router)
docksh 6f0    # Host V (192.168.60.5)
docksh 2b3    # Host U / Client (10.9.0.5)
```

---

## Network Topology

| Container | IP Address(es) | Role |
|-----------|---------------|------|
| Host U (Client) | 10.9.0.5 | VPN Client — on "Internet" side |
| VPN Server (Router) | 192.168.60.11 (Internet), 10.9.0.11 (Private) | Bridges Internet ↔ Private network |
| Host V | 192.168.60.5 | Private network host |
| Host V2 | 192.168.60.6 | Private network host |

**Normal routing (without VPN):**
```
Host U (10.9.0.5) ──── Internet ──── VPN Server ──── Private Network (192.168.60.x)
```
Host U cannot directly reach the private network — the VPN tunnel bridges this gap.

---

## Task 1: Network Setup & Connectivity Tests

### Verify VPN Server Has Two Interfaces
```bash
# On VPN Server container
ip address
```
Expected interfaces:
- `eth0` → IP `10.9.0.11/24` (facing Internet)
- `eth1` → IP `192.168.60.11/24` (facing private network)

### Connectivity Tests

**Test 1 — Host U → VPN Server (WORKED):**
```bash
# On Host U
ping 192.168.60.11
```
✅ Ping replies received — basic Internet connectivity confirmed.

**Test 2 — VPN Server → Host V (WORKED):**
```bash
# On VPN Server
ping 10.9.0.5
```
✅ Ping replies received — private network is working.

**Test 3 — Host U → Host V (FAILED):**
```bash
# On Host U
ping 10.9.0.5
# Result: no reply
```
❌ Failed — there is no direct route between the Internet network and the private network. **This is the problem the VPN tunnel will solve.**

### Capture Traffic on Both Interfaces

**Sniff on Internet interface (eth1):**
```bash
# On VPN Server
tcpdump -i eth1 -n
# Then ping from Host U — ICMP packets appear on eth1
```

**Sniff on Private interface (eth0):**
```bash
# On VPN Server
tcpdump -i eth0 -n
# Then ping from VPN Server to private hosts — ICMP packets appear on eth0
```

✅ Packet sniffing works correctly on both network interfaces.

---

## Task 2: Create and Configure TUN Interface

**Goal:** Create a TUN virtual interface on Host U that will serve as the VPN tunnel endpoint.

### Task 2.a: Custom Interface Name

Edit `tun.py` to use last name as the interface prefix instead of `tun`:

```python
#!/usr/bin/env python3
import fcntl
import struct
import os
import time
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'Mahankali%d', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes[:16].strip(b'\x00').decode('utf-8')
print("Interface Name: {}".format(ifname))

while True:
    time.sleep(10)
```

```bash
chmod a+x tun.py
./tun.py
# Output: Interface Name: Mahankali0
```

### Task 2.b: Set Up the TUN Interface

After creating the interface, it starts in **DOWN** state with no IP. Configure it:

```python
# Add to tun.py after creating the interface:
os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
print("TUN interface {} configured and brought up".format(ifname))
```

```bash
./tun.py
# Output: TUN interface Mahankali1 configured and brought up
```

**Verify:**
```bash
ip addr
# Shows: Mahankali1 with inet 192.168.53.99/24, state UP
```

✅ Before these commands: interface was **DOWN** with no IP. After: interface is **UP** with `192.168.53.99`.

### Task 2.c: Read from the TUN Interface

Add packet reading to `tun_task2.c.py`:

```python
while True:
    # Get a packet from the tun interface
    packet = os.read(tun, 2048)
    if packet:
        ip = IP(packet)
        print(ip.summary())
```

**Question 1 — Ping a host in the 192.168.53.0/24 network:**
```bash
# On Host U (another terminal)
ping 192.168.53.1
```

**tun.py output:**
```
IP / ICMP 192.168.53.99 > 192.168.53.1 echo-request 0 / Raw
IP / ICMP 192.168.53.99 > 192.168.53.1 echo-request 0 / Raw
...
```
✅ ICMP packets appear in the TUN interface — the OS routes packets destined for `192.168.53.0/24` through the TUN interface.

**Question 2 — Ping a host in the internal network 192.168.60.0/24:**
```bash
ping 192.168.60.1
```

**tun.py output:** (nothing printed)

> **Observation:** Pinging `192.168.60.1` (internal network) printed **NOTHING** because internal network traffic doesn't go through the TUN interface — the OS routes it directly via `eth0`. VPN is only needed for traffic that has no other route.

### Task 2.d: Write to the TUN Interface

Modify `tun.py` to read a packet and write a spoofed reply back:

```python
while True:
    packet = os.read(tun, 2048)
    if packet:
        ip = IP(packet)
        print(ip.summary())

        # Create a fake reply: swap src and dst
        newip = IP(src=ip.dst, dst=ip.src)
        newicmp = ICMP(type=0)   # echo-reply
        newpkt = newip / newicmp
        os.write(tun, bytes(newpkt))
```

```bash
# Ping from Host U
ping 192.168.53.1
```

**Result:** Ping replies received! Even though no real machine exists at `192.168.53.1`, our program intercepts the request and fabricates a reply. The ping command believes it communicated with a real host.

**Writing arbitrary data instead of IP packets:**
```
Result: 100% packet loss — 89 packets transmitted, 0 received
```
> **Observation:** Writing arbitrary (non-IP) data to the TUN interface generates **malformed packets** that tcpdump cannot decode. The TUN interface operates at the **IP layer** and requires valid IP packet formatting for proper network communication.

---

## Task 3: Send IP Packet to VPN Server Through Tunnel

**Goal:** Build a real tunnel — encapsulate packets from the TUN interface in UDP and send to VPN Server.

### tun_client.py (on Host U)

```python
#!/usr/bin/env python3
# Key logic:
# 1. Read IP packet from TUN interface
# 2. Wrap it in UDP and send to VPN Server at 10.9.0.11:9090

SERVER_IP = "10.9.0.11"
SERVER_PORT = 9090

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while True:
    ready, _, _ = select.select([sock, tun], [], [])
    for fd in ready:
        if fd is tun:
            packet = os.read(tun, 2048)
            sock.sendto(packet, (SERVER_IP, SERVER_PORT))
```

### tun_server.py (on VPN Server)

```python
#!/usr/bin/env python3
# Key logic:
# 1. Receive UDP packet from client
# 2. Extract inner IP packet
# 3. Write to server's TUN interface (inject into private network)

sock.bind(("0.0.0.0", 9090))

while True:
    data, addr = sock.recvfrom(2048)
    pkt = IP(data)
    print("{}:{} --> 0.0.0.0:{}".format(addr[0], addr[1], 9090))
    print("  Inside: {} --> {}".format(pkt.src, pkt.dst))
    os.write(tun, data)
```

**Run and test:**
```bash
# On VPN Server
python3 tun_server.py

# On Host U
python3 tun_client.py

# On Host U (another terminal)
ping 192.168.53.50
```

**VPN Server output:**
```
10.9.0.5:49483 --> 0.0.0.0:9090
  Inside: 192.168.53.99 --> 192.168.53.50
10.9.0.5:49483 --> 0.0.0.0:9090
  Inside: 192.168.53.99 --> 192.168.53.50
```

✅ The tunnel is working — IP packets are successfully encapsulated inside UDP and transported between client and server.

**Accessing private network hosts through tunnel:**
```bash
# Add route on Host U to send private network traffic through TUN
ip route add 192.168.60.0/24 dev Naga0

# Then ping private host
ping 192.168.60.10
```

**tun_server.py shows:**
```
10.9.0.5:47558 --> 0.0.0.0:9090
  Inside: 192.168.53.99 --> 192.168.60.10
```

✅ Packets destined for private network now travel through the VPN tunnel.

---

## Task 4: Set Up VPN Server-Side TUN and Forwarding

**Goal:** Configure the VPN server to forward decapsulated packets into the private network and route replies back.

The `docker-compose.yml` router container already has:
```yaml
devices:
  - "/dev/net/tun:/dev/net/tun"
sysctls:
  - net.ipv4.ip_forward=1
```

**Run both scripts and test:**
```bash
# VPN Server
python3 tun_server.py

# Host U
python3 tun_client.py

# Host U — ping Host V
ping 192.168.60.5 -c 6
```

**Result:**
```
64 bytes from 192.168.60.5: icmp_seq=1 ttl=63 time=5.30 ms
64 bytes from 192.168.60.5: icmp_seq=2 ttl=63 time=4.48 ms
...
6 packets transmitted, 6 received, 0% packet loss
```

**tun_server.py shows bidirectional traffic:**
```
From socket <==: 192.168.53.99 --> 192.168.60.5
From tun ==>: 192.168.60.5 --> 192.168.53.99
From socket <==: 192.168.53.99 --> 192.168.60.5
From tun ==>: 192.168.60.5 --> 192.168.53.99
```

**Telnet through tunnel:**
```bash
# On Host U
telnet 192.168.60.5
# Connected to 192.168.60.5 — login: seed
# Welcome to Ubuntu 20.04.1 LTS
```

✅ Full VPN connection established — Telnet successfully tunneled through to private network Host V!

---

## Task 5: Handling Traffic in Both Directions

**Goal:** Make the VPN handle both outgoing and incoming traffic simultaneously.

Both `tun_client.py` and `tun_server.py` use `select()` to monitor both the TUN interface and the UDP socket simultaneously:

```python
while True:
    ready, _, _ = select.select([sock, tun], [], [])
    for fd in ready:
        if fd is tun:
            # Read from TUN → send via UDP socket
            data = os.read(tun, 2048)
            sock.sendto(data, (SERVER_IP, SERVER_PORT))
        if fd is sock:
            # Read from UDP socket → write to TUN
            data, addr = sock.recvfrom(2048)
            os.write(tun, data)
```

**tcpdump confirms full Telnet session through tunnel:**

TCP 3-way handshake observed:
1. `192.168.53.99:51992 → 192.168.60.5:23 [SYN]` — Connection initiation
2. `192.168.60.5:23 → 192.168.53.99:51992 [SYN-ACK]` — Server acknowledges
3. `192.168.53.99:51992 → 192.168.60.5:23 [ACK]` — Connection established

✅ Bidirectional traffic (Telnet, ping) flows correctly through the VPN tunnel in both directions.

---

## Task 6: Tunnel-Breaking Experiment

**Goal:** Observe what happens when the VPN tunnel breaks while a Telnet session is active.

**Steps:**
1. Establish a Telnet session from Host U to Host V through the tunnel
2. While Telnet is active, stop `tun_client.py` (Ctrl+C)
3. Try typing in the Telnet window

**Observation:**
- After breaking the tunnel, typing in the Telnet window produced **no output** — the connection appeared frozen
- After restarting `tun_client.py`, the Telnet session **recovered** and typed text appeared

**tcpdump shows the outage duration:**
```
tcpdump: pcap_loop: The interface went down
45 packets captured
```
> The interface was down for approximately **56 seconds**. This demonstrates that while the TUN interface can be unstable, it has self-recovery capabilities suitable for VPN applications — the TCP session survived and resumed when the tunnel was restored.

---

## Task 7: Routing Experiment on Host V

**Goal:** Ensure Host V routes return packets back through the VPN Server so replies travel through the tunnel.

**Check Host V's default route:**
```bash
# On Host V
ip route
# default via 192.168.60.11 dev eth0
# 192.168.60.0/24 dev eth0 proto kernel scope link src 192.168.60.5
```

**Problem:** The default route sends all traffic through `192.168.60.11`, but replies to the VPN client need to go back via the VPN Server's TUN interface.

**Fix — Add specific route for VPN tunnel subnet:**
```bash
# Delete default route
ip route del default

# Add specific route: VPN tunnel subnet goes via VPN Server
ip route add 192.168.53.0/24 via 192.168.60.11
```

**After fix — ping from Host U to Host V works through tunnel:**
```bash
ping 192.168.60.5
# 64 bytes from 192.168.60.5: icmp_seq=1 ttl=63 time=4.63 ms ✅
```

**tcpdump on Host U's TUN interface confirms bidirectional flow:**
```
IP 192.168.53.11 > 192.168.60.5: ICMP echo request
IP 192.168.60.5 > 192.168.53.11: ICMP echo reply
```

---

## Task 8: VPN Between Private Networks

**Goal:** Connect two separate private networks (`192.168.50.0/24` and `192.168.60.0/24`) through a VPN tunnel over the Internet (`10.9.0.0/24`).

### Docker Setup
```bash
docker-compose -f docker-compose2.yml up
```

**Containers created:**
```
dfcf1c0fe807  server-router
f800042fcfa5  host-192.168.50.5  (Network 1 — client side)
375e56d4815e  client-10.9.0.5
e46d9e77f79a  host-192.168.50.6
ce1c0af272e1  host-192.168.60.5  (Network 2 — server side)
bdfe3af67871  host-192.168.60.6
```

### Test Cross-Network Ping
```bash
# From host-192.168.50.5 → ping host-192.168.60.5
ping 192.168.60.5 -c 5
# 5 packets transmitted, 5 received, 0% packet loss ✅
```

**tun_client.py output:**
```
From tun ==>: 192.168.50.5 --> 192.168.60.5
From socket <==: 192.168.60.5 --> 192.168.50.5
```

**tun_server.py output:**
```
From socket <==: 192.168.50.5 --> 192.168.60.5
From tun ==>: 192.168.60.5 --> 192.168.50.5
```

**Telnet from Network 1 to Network 2:**
```bash
telnet 192.168.60.5
# Connected to 192.168.60.5 ✅
# Ubuntu 20.04.1 LTS — login: seed
```

**After breaking and reconnecting — tunnel self-recovers and Telnet resumes.**

✅ VPN between two private networks fully operational!

---

## Task 9: Experiment with the TAP Interface

**Goal:** Explore the TAP interface, which operates at **Layer 2 (Ethernet)** instead of Layer 3 (IP).

### Key Difference: TUN vs TAP

| Feature | TUN Interface | TAP Interface |
|---------|--------------|---------------|
| Layer | Layer 3 (IP) | Layer 2 (Ethernet) |
| Packets | IP packets | Ethernet frames (with MAC headers) |
| Use case | IP-based VPN | Bridge-mode VPN |
| ARP support | No | Yes |

### Test 1 — Ping (fails without arping)
```bash
# From Host U
ping 192.168.53.50
# Result: 100% packet loss — Destination Host Unreachable
```
TAP requires ARP resolution first — plain ping doesn't work directly.

### Test 2 — ARP ping (arping)
```bash
arping -I Naga1 192.168.53.1
# Timeout — no response (no MAC reply yet)
```

**tap_client.py intercepts and shows:**
```
Ether / ARP who has 192.168.53.1 says 192.168.53.99 / Padding
Ether / ARP who has 192.168.53.1 says 192.168.53.99 / Padding
```

### Test 3 — arping 192.168.53.33 (TAP script replies)
```bash
arping -I Naga1 192.168.53.33
# 42 bytes from aa:bb:cc:dd:ee:ff (192.168.53.33): index=0 time=8.928 usec ✅
# 42 bytes from aa:bb:cc:dd:ee:ff (192.168.53.33): index=1 time=9.462 usec ✅
```

**tap_client.py shows:**
```
Ether / ARP who has 192.168.53.33 says 192.168.53.99 / Padding
***** Fake response: Ether / ARP is at aa:bb:cc:dd:ee:ff says 192.168.53.33
```

### Test 4 — arping 1.2.3.4
```bash
arping -I Naga1 1.2.3.4
# 42 bytes from aa:bb:cc:dd:ee:ff (1.2.3.4): index=0 time=1.074 msec ✅
```

**tap_client.py intercepts and sends fake ARP reply:**
```
Ether / ARP who has 1.2.3.4 says 192.168.53.99 / Padding
***** Fake response: Ether / ARP is at aa:bb:cc:dd:ee:ff says 1.2.3.4
```

> **Observation:** The TAP interface operates at Layer 2 and receives full Ethernet frames including ARP packets. Our `tap_client.py` intercepts ARP requests and crafts fake ARP replies, making the system believe any IP address is reachable. This demonstrates that the TAP interface can handle **any Ethernet-level protocol**, not just IP.

---

## Key Observations

| Task | Key Finding |
|------|-------------|
| Task 1 | Host U → Host V fails without VPN (no direct route) |
| Task 2.a | TUN interface name customized to `Mahankali0` using last name prefix |
| Task 2.b | TUN interface starts DOWN with no IP — must configure manually |
| Task 2.c | Pinging `192.168.53.x` → packets enter TUN. Pinging `192.168.60.x` → bypasses TUN |
| Task 2.d | Writing valid IP packets to TUN creates working fake ping replies; arbitrary data fails |
| Task 3 | Packets encapsulated in UDP travel through "Internet" to VPN Server successfully |
| Task 4 | Full end-to-end VPN with Telnet to private host confirmed |
| Task 5 | Bidirectional traffic handled with `select()` — TCP 3-way handshake observed via tcpdump |
| Task 6 | Tunnel breakage freezes Telnet for ~56 seconds; self-recovers on reconnect |
| Task 7 | Host V needs explicit route for VPN tunnel subnet to send replies back through tunnel |
| Task 8 | Two separate private networks successfully bridged via VPN tunnel |
| Task 9 | TAP (Layer 2) handles ARP frames; TUN (Layer 3) handles only IP packets |

> **Security Takeaway:** A VPN tunnel works by encapsulating private network traffic inside another protocol (UDP here) for transport over an untrusted network. Real-world VPNs add **encryption** (TLS/IPSec) to this encapsulation. Without encryption, the tunnel provides connectivity but not confidentiality — a network observer can still read the inner packets.

---

*Lab completed as part of the SEED Labs Network Security curriculum.*
