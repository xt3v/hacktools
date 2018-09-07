from scapy.all import *

#set the filter 
filter = "tcp"

#what to do when packets are gotten
def display(packet):
	print("ip src {0}:{1} .. ip dest {2}:{3}".format(packet[IP].src,packet[TCP].sport,packet[IP].dst,packet[TCP].dport))

#sniff packets and execute function
sniff(filter=filter,prn=display)
