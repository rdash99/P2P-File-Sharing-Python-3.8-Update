from Link_Maintain.udplistener import UDPListener
from Downloading.dlistener import Downloader
from Link_Maintain.packets import LinkPacket
from Link_Maintain.config import Config
import time,atexit

def sendAddresses(v):
	#sends ip-address for each node
	#to connect next
	 lst = [g for g,j in v.nodes.iteritems()]
	 l = len(lst)
	 print ("Closing...")
	 for i in range(0,l):
	 	tmp_pac = LinkPacket()
	 	tmp_pac.setMessageByFields(
	 		11, Config.NODE_IP_ADDRESS, lst[(i+1)%l])
	 	v.soc.sendto( tmp_pac.getRawMessage(),
	 						(lst[i], Config.UDP_LISTEN_PORT))


a = UDPListener()
b= Downloader(a)
atexit.register(sendAddresses, a)

while 1:
	#waits for user's commands
	comm = raw_input()
	if comm=="n":
		#display neigbhours and 2-hop neighbours
		for n in a.nodes:
			print ('Via:',n)
			for i in a.nodes[n].neighbours:
				print (i),
			print

	elif comm=="s":
		q = raw_input("Search Query:")
		b.searchNetwork(q)

	elif comm=="c":
		n = raw_input("Choose your choice:")
		n = int(n)
		b.downloadRequest(n)


