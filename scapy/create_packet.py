import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

server = 'google.com'

#set ethernet layer (mac address)
packet = Ether(src='00:00:00:11:11:11')
print('Ethernet {0}\n'.format(repr(packet)))

#append ip layer and set destination
ip = packet/IP(dst=server)
print('IP: {0}\n'.format(repr(ip)))

#append tcp layer and speciify dest port
tcp = ip/TCP(dport=80)
print('TCP: {0}\n'.format(repr(tcp)))

#set http payload and append
http = tcp/"GET /index.html HTTP/1.0\r\n\r\n"
print('Http: {0}\n'.format(repr(http)))




