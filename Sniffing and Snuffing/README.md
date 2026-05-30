# Packet Sniffing and Spoofing Lab
**Course:** Network Security — SEED Labs  
**Topic:** Packet Sniffing and Spoofing using Scapy

---

## 📋 Table of Contents
- [Lab Overview](#lab-overview)
- [Lab Setup Environment](#lab-setup-environment)
- [Task Set 1: Using Scapy to Sniff and Spoof Packets](#task-set-1-using-scapy-to-sniff-and-spoof-packets)
  - [Task 1.1: Sniffing Packets](#task-11-sniffing-packets)
  - [Task 1.1B: Capture Only ICMP Packets](#task-11b-capture-only-icmp-packets)
  - [Task 1.1C: Capture TCP Packets from a Specific IP and Port](#task-11c-capture-tcp-packets-from-a-specific-ip-and-port)
  - [Task 1.1D: Capture Packets from a Subnet](#task-11d-capture-packets-from-a-subnet)
  - [Task 1.2: Spoofing ICMP Packets](#task-12-spoofing-icmp-packets)
- [Key Observations](#key-observations)

---

## Lab Overview

This lab focuses on **Packet Sniffing and Spoofing** — two fundamental techniques in network security. Using the **Scapy** Python library within a SEED Lab Docker environment, we explore:

- How attackers can capture (sniff) packets on a network
- How attackers can forge (spoof) packets with fake source IPs
- Why root privileges are required for raw socket operations
- How packet filters work (ICMP, TCP, subnet-based)

---

## Lab Setup Environment

### Step 1 — Start the SEED VM
1. Launch the **SEED VM**
2. Open **Firefox** and navigate to the SEED Labs website
3. Go to: **Network Security → Packet Sniffing and Spoofing**
4. Download the **lab setup ZIP file**

### Step 2 — Prepare the Lab Directory
```bash
# Move the zip to your Documents folder (or any preferred folder)
# Example path: Documents/sniff_lab/

# Unzip the lab setup file
unzip labsetup.zip
```
Right-click inside the extracted folder and select **"Open Terminal Here"** to get a terminal pointed at the lab directory.

### Step 3 — Set Up Docker Containers
```bash
# Check running containers
dockps

# You will see the seed-attacker container with ID starting with d0
# Connect to the attacker container
docksh d0
```

### Step 4 — Verify Network Interface
Once inside the container (as root), check your IP address:
```bash
ifconfig
```
> **Note:** Note the interface name (e.g., `eth0`, `br-xxxxx`) — you will need it for the sniffer scripts.

---

## Task Set 1: Using Scapy to Sniff and Spoof Packets

### Initial Setup — Create and Run a Python File
```bash
# Create a new Python file
touch mycode.py

# Double-click mycode.py to open it, write your Scapy code, save and close

# Make it executable and run
chmod a+x mycode.py
python3 mycode.py
```

---

### Task 1.1: Sniffing Packets

**Goal:** Capture all packets on the network interface using Scapy.

**Step 1 — Create the sniffer script:**
```bash
nano sniffer.py
```

**Step 2 — Write the sniffer code:**
```python
#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
    pkt.show()

# Replace 'br-xxxxx' with your actual interface name from ifconfig
pkt = sniff(iface='br-xxxxx', filter='icmp', prn=print_pkt)
```

**Step 3 — Run as root:**
```bash
chmod a+x sniffer.py
python3 sniffer.py
```

**Step 4 — Test by pinging Host B from another terminal:**
```bash
ping 10.9.0.6   # IP of Host B
```

**Step 5 — Run WITHOUT root privileges (to observe the error):**
```bash
su seed
python3 sniffer.py
```

#### ✅ Output / Observation
- **With root:** The sniffer captures and displays packet details (IP headers, protocol info, etc.)
- **Without root:** The program throws a **Permission Error — "Operation not permitted"**

> **My Observation:** Sniffing tasks require root privileges because they need direct access to raw network packets. Regular users are restricted from performing such operations for security reasons — raw socket access could expose all traffic on the network to an unauthorized user.

---

### Task 1.1B: Capture Only ICMP Packets

**Goal:** Filter and capture only ICMP packets.

**Step 1 — Update the filter in `sniffer.py`:**
```python
pkt = sniff(iface='br-xxxxx', filter='icmp', prn=print_pkt)
```

**Step 2 — Run the sniffer and send test ICMP packets (ping):**
```bash
# In another terminal, ping a host
ping 10.9.0.6
```

#### ✅ Output / Observation
Only **ICMP packets** are captured and displayed. TCP, UDP, and other traffic is ignored. (Tested by sending two ICMP packets — only those two appeared in the sniffer output.)

---

### Task 1.1C: Capture TCP Packets from a Specific IP and Port

**Goal:** Capture only TCP packets originating from IP `10.9.0.5` and destined for **port 23 (Telnet)**.

**Step 1 — Edit the filter in `sniffer.py`:**
```python
pkt = sniff(iface='br-xxxxx',
            filter='tcp and src host 10.9.0.5 and dst port 23',
            prn=print_pkt)
```

**Step 2 — Start a Telnet connection to trigger traffic:**
```bash
telnet 10.9.0.5
```

#### ✅ Output / Observation
- The Telnet connection was **successfully established** (confirming **port 23 is open**)
- The sniffer captured **only TCP packets** matching the source IP and destination port 23
- Login to seed was confirmed through the captured packets

---

### Task 1.1D: Capture Packets from a Subnet

**Goal:** Capture packets to/from a specific subnet (not your VM's own subnet).

**Step 1 — Edit the filter:**
```python
pkt = sniff(iface='br-xxxxx',
            filter='net 128.230.0.0/16',
            prn=print_pkt)
```

> ⚠️ Do NOT use your VM's own subnet — choose an external one like `128.230.0.0/16`.

#### ✅ Output / Observation
Packets matching the specified subnet range were captured and displayed from the **attacker VM terminal**.

---

### Task 1.2: Spoofing ICMP Packets

**Goal:** Forge (spoof) ICMP packets with a fake source IP address using Scapy.

**Step 1 — Create the spoof script:**
```bash
nano spoof.py
```

**Step 2 — Write the spoofing code:**
```python
#!/usr/bin/env python3
from scapy.all import *

# Craft a spoofed ICMP packet with a fake source IP
a = IP()
a.dst = '10.9.0.6'          # Destination: Host B
a.src = '1.2.3.4'           # Spoofed source IP (fake)
b = ICMP()
p = a / b

send(p)
print("Packet sent!")
```

**Step 3 — Make executable and run:**
```bash
chmod a+x spoof.py
python3 spoof.py
```

**Step 4 — Verify in Wireshark:**
- Open **Wireshark**
- Set the filter to: `icmp`
- Select your network interface
- Observe the captured ICMP packet — the **source IP will show `1.2.3.4`** (the spoofed address)

#### ✅ Output / Observation
- The packet was successfully sent
- Wireshark confirmed the packet arrived at the destination with the **spoofed source IP**
- This demonstrates that **IP source addresses can be forged** — which is why network security measures like ingress/egress filtering exist

---

## Key Observations

| Task | Key Finding |
|------|-------------|
| Sniffing without root | **Permission denied** — raw sockets require root privileges |
| ICMP filter | Only ICMP packets captured; all other traffic ignored |
| TCP + IP + Port filter | Precise filtering possible; port 23 confirmed open via Telnet |
| Subnet filter | Subnet-level filtering works correctly with CIDR notation |
| ICMP Spoofing | Source IP can be forged; Wireshark confirms spoofed address |

> **Security Takeaway:** Packet sniffing and spoofing are powerful attack techniques. Networks should use **encrypted protocols (TLS/SSH)**, **ingress filtering**, and **network monitoring tools** to detect and prevent such attacks.

---

*Lab completed as part of the SEED Labs Network Security curriculum.*

FIND THE ENTIRE LAB IN THE PDF FILE IN THIS SNIFFING AND SPOOFING FOLDER ALONG WITH SCREENSHOTS
