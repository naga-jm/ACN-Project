#!/usr/bin/env python3
import fcntl
import struct
import os
import time
from scapy.all import *

# These constants MUST be defined
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002  
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'Naga%d', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)  # ← This line should now work

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
print(" interface Name:{} ".format(ifname))


"""while True:
    # Get a packet from the tun interface
    packet = os.read(tun, 2048)
    if packet:
        ip = IP(packet)
        print(ip.summary())
"""
"""while True:
    #time.sleep(10)
    packet = os.read(tun, 2048)
    if packet:
        ip = IP(packet)
        print(ip.summary())

        # Send out a spoof packet using the tun interface
        newip = IP(src="192.168.53.1", dst=ip.src)
        newpkt = newip/ip.payload
        os.write(tun, bytes(newpkt))
"""
while True:
    #time.sleep(10)
    packet = os.read(tun, 2048)
    if packet:
        ip = IP(packet)
        print(ip.summary())

        # Send out a spoof packet using the tun interface
        newip = IP(src="192.168.53.50", dst=ip.src)
        newpkt = newip/ip.payload
        arb_data = b'Arbitary data'
        os.write(tun, arb_data)

