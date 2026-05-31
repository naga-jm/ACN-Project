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
IFF_TAP   = 0x0002

# Create the TUN interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'Naga0', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('utf-8')[:16].strip("\x00")
print("Interface Name:", ifname)

os.system(f"ip addr add 192.168.53.1/24 dev {ifname}")
os.system(f"ip link set dev {ifname} up")

os.system(f"ip route add 192.168.50.0/24 dev {ifname}")

IP_A = "0.0.0.0"
PORT = 9090
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_A, PORT))
ip = "10.9.0.5"
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
			sock.sendto(packet, (ip, port))

"""
while True:
	data, (ip, port) = sock.recvfrom(2048)
	print("{}:{} --> {}:{}".format(ip, port, IP_A, PORT))
	pkt = IP(data)
	print(" Inside: {} --> {}".format(pkt.src, pkt.dst))
	os.write(tun, bytes(pkt))
"""
