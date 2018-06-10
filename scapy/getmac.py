import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

conf.verb = 0

ip = input("Enter ip to get mac :")

#create ARP request packet
packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)

#send request nd get first response
resp = srp1(packet)

#get mac address from ARP 
mac = resp[ARP].hwsrc

print("Mac : "+mac)
