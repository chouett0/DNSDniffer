import os, sys, getopt, struct, re, string, logging
from socket import *
from fcntl import ioctl
from scapy.all import *
from datetime import datetime
from collections import defaultdict
import threading

OUT_ETH_IFNAME = "eth0"
outHWaddr = get_if_hwaddr(OUT_ETH_IFNAME)
outIpaddr = get_if_addr(OUT_ETH_IFNAME)

IN_ETH_IFNAME = "eth1"
inHWaddr = get_if_hwaddr(IN_ETH_IFNAME)
inIpaddr = get_if_addr(IN_ETH_IFNAME)

outPackets = defaultdict(int)
outPacketToLanAddr =  defaultdict(str)

class OutPacketHandler(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)

	def run(self):
		print "Starting outboud..."
		l2s = conf.L2listen(iface = OUT_ETH_IFNAME)
		global outHWaddr
		global outInpacket
		global outPakcets
		global outPacketToLanAddr

		while True:
			eframe = l2s.recv(1522)
#			print self.ifname + " : " + eframe.summary()
			if eframe.dst != outHWaddr or not eframe[0].haslayer(IP):
				continue

			ipPkt = eframe[0][IP]

			if outPackets[(ipPkt.src, ipPkt.sport)] > 0:
				outPackets[(ipPkt.src, ipPkt.sport)] -= 1
				ipPkt.dst = outPacketToLanAddr[(ipPkt, ipPkt.dport)]
				if ipPkt.haslayer(TCP): del ipPkt[TCP].chksum
				if ipPkt.haslayer(UDP): del ipPkt[UDP].chksum
				del ipPkt[IP].chksum
				ipPkt = IP(str(ipPkt))
				print "OUT-TO-IN PACKET: " + ipPkt.summary()
				send(ipPkt, verbose=0)

class InPacketHandler(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)

	def run(self):
		print "(Starting inboud...)"
		l2s = conf.L2listen(iface = IN_ETH_IFNAME)
		global inkHWaddr
		global inIpaddr
		global outIpaddr
		global outPackets
		global outPacketToLanAddr

		while True:
			eframe = l2s.recv(1522)

			if eframe.dst != inHWaddr or eframe[0].haslayer(IP):
				continue

			inPkt = eframe[0][IP]

			if inPkt.dst != inIpaddr:
				outPackets[(inPkt.dst, inPkt.dpport)] += 1
				outPacketToLanAddr[(inPKt.dst, inPkt.dport)] = ipPkt.src
				inkPkt.src = outIpaddr
				if inPkt.haslayer(TCP): del inPkt[TCP].chksum
				if iPkkt.haslayer(UDP): del inPkt[UDP].chksum
				del ipPkt[IP].chkdum
				ipPtk = IP(str(inPKt))
				print "IN-TO-OUT PACKET: " + ipPkt.summary()
				send(ipPkt, verbose=0)

outside = OutPacketHandler()
outside.deamon = True
outside.start()

inside = InPacketHandler()
inside.deamon = True
inside.start()

os.system("sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")
input("Press Ctrl+S to Stop.")
