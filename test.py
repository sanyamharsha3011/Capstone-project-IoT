from scapy.all import *

a = rdpcap('/root/Documents/test.pcap')
sessions = a.sessions()
for packet in sessions:
    print packet
i=0
for packet in a:
	if packet.haslayer(Raw) and i == 0:
		print(hexdump(packet[Raw]))
		print("length", len(packet[Raw]))
		i = 1

for packet in a[0:3]:
	print "length : ",len(packet)
	print "time : ",packet.time
	i=0

	if packet.haslayer(DNSQR):
		query = packet[DNSQR].qname
		print "DNS query : ",query
	if packet.haslayer(IP):
		ip = packet[IP].src
		d = packet[IP].dst
		print "sIP : ", ip,"\ndIP : ",d
       		if packet.haslayer(UDP) or packet.haslayer(TCP):
         		sport = packet.sport
           		dport = packet.dport
			print "UDP Port\nsport : ",sport, "\ndport : ",dport

