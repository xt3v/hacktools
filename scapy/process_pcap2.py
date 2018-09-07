import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

#get packets from pcap file
packets = rdpcap("dns.cap")

#loop through all packets
for packet in packets:
	#get src and dst ip
	src = packet[IP].src
	dst = packet[IP].ds  t
     
    #if TCP packet 
	if TCP in packet:
		tcp = packet[TCP]
		print("TCP: {0}:{1} -> {2}:{3}".format(src,tcp.sport,dst,tcp.dport))
	
	#if udp packet
	if UDP in packet:
		udp = packet[UDP]
		print("UDP: {0}:{1} -> {2}:{3}".format(src,udp.sport,dst,udp.dport))

 
