#!/usr/bin/env python3
import fcntl
import struct
import os
import fcntl
import struct
import socket
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

SERVER_IP = '192.168.1.100'  # Replace with actual server IP
SERVER_PORT = 5000           # Replace with desired server port

# Create the TUN interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'Naga0', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)
ifname = ifname_bytes.decode('utf-8')[:16].strip("\x00")
print("Interface Name:", ifname)

# Assign IP and bring interface up
os.system(f"ip addr add 192.168.53.11/24 dev {ifname}")
os.system(f"ip link set dev {ifname} up")

SERVER_PORT = 9090
SERVER_IP = "10.9.0.11"

os.system(f"ip route add 192.168.60.0/24 dev {ifname}")

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

ip = "10.9.0.11"
port = 1010

while True:
	# this will block until at least one interface is ready
	ready, _, _ = select.select([sock, tun], [], [])
	for fd in ready:
		if fd is sock:
			data, (ip, port) = sock.recvfrom(2048)
			pkt = IP(data)
			print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
			#... (code needs to be added by students) ...
			os.write(tun, bytes(pkt))

		if fd is tun:
			packet = os.read(tun, 2048)
			pkt = IP(packet)
			print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
			#... (code needs to be added by students) ...
			sock.sendto(packet, (SERVER_IP, SERVER_PORT))

"""

while True:
    # Get a packet from the tun interface
    packet = os.read(tun, 2048)
    if packet:
        ip = IP(packet)
        print(ip.summary())"""
"""
# Main loop: send TUN packets over UDP
while True:
    packet = os.read(tun, 2048)
    if packet:
        sock.sendto(packet, (SERVER_IP, SERVER_PORT))
"""
