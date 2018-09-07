import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

#get packet from pcap file 
packets = rdpcap("dns.cap")

#loop through all
for packet in packets:
	print(".................\n")
	print()
	print("src_mac: {0}".format(packet.src))
	print("dst_mac: {0}".format(packet.dst))
    
    #get ip layer getails
	ip = packet.payload
	print("src_ip: {0}".format(ip.src))
	print("dst_ip: {0}".format(ip.dst))
	
	#check if is tcp
	if ip.proto == 6:
		tcp = ip.payload
		print("tcp_sport: {0}".format(tcp.sport))
		print("tcp_dport: {0}".format(tcp.dport))
	#check if is udp
	if ip.proto == 17:
                udp = ip.payload
                print("udp_sport: {0}".format(udp.sport))
                print("udp_dport: {0}".format(udp.dport))
