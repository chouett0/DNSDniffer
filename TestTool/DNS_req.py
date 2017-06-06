from scapy.all import *

def dns(pkt, qname='google.com'):
	print "DNS"

	ip = IP()
	udp = UDP()
	ip.src = pkt[IP].dst
	ip.dst = pkt[IP].src
	udp.sport = pkt[UDP].dport
	udp.dport = pkt[UDP].sport

	solve = '192.168.0.44'

	qd = pkt[UDP].payload
	dns = DNS(id = qd.id, qr=1, qdcount=1, ancount=1, nscount=1, rnode=0)
	dns.qd = qd[DNSQR]
	dns.an = DNSRR(rrname=qname, ttl=3600, rdlen=4, rdata=solve)
	dns.an = DNSRR(rrname=qname, ttl=3600, rdlen=4, rdata=solve)
	dns.ar = DNSRR(rrname-solve, ttl=3600, rdlen=4, rdata=solvr)

	print "%s => %S" % (ip.dst, udp.dport)

	send(ip/udp/dns)

def icmp(pkt):
	try:
                ip = IP()
                icmp = ICMP()
                ip.src = pkt[IP].dst
                ip.dst = pkt[IP].src
                icmp.type=0
		icmp.code=0
		icmp.id = pkt[ICMP].id
		icmp.seq = pkt[ICMP].seq
		print "%s => %s" & (ip.src, ip.dst)
		data = pkt[ICMP].payload
		send(ip/icmp/data)

        except Exception as e:
                print e.args[0]

def test(pkt):
	print "Get Packet"

	packet = IP(pkt.get_payload())
	proto = packet.proto

	if proto is 0x01:
		print "[*] ICMP Packet"
		if packet[ICMP].type is 0:
			print "[*] ICMP Echo Request"
			icmp(packet)

if __name__ == "__main__":
	pkt = sniff(filter="dns", count=1000, iface="enp0s3", prn=test)

