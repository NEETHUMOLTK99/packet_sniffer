import sys
from scapy.all import *

net_iface = sys.argv[1] #Taking interface name
print(net_iface)

#promisceous mode transfer the interface data packets to cpu to processs and you capture from there
subprocess.call(["ifconfig",net_iface,"promisc"]) #creating another process to run command

num_of_pkt = int(sys.argv[2])#Taking number of packets

time_sec = int(sys.argv[3]) #Taking time

proto = sys.argv[4] #Taking protocol name
print(proto	)

def logs(packet):
	packet.show()
	print(f"SRC_MAC: {str(packet[0].src)} DEST_MAC: {str(packet[0].dst)}")


if proto == "all":
	sniff(iface = net_iface ,count = num_of_pkt, timeout = time_sec, prn=logs ) 
elif proto == "arp" or proto == "icmp":
	sniff(iface = net_iface, count = num_of_pkt,timout = time_sec , prn = logs , filter = proto) 
else:
	print("Wrong protocol")
