import thread,socket,time
from packets import LinkPacket
from config import Config

'''
Node class defines the functionalities related to the 
link check with the adjacent nodes.
'''

class Node:
	def __init__(self,user_ip,main_obj):
		self.main_list = main_obj#<--reference to the main queue---
		self.ip = user_ip
		self.soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.soc.bind(('0.0.0.0', 0))
		self.soc.settimeout(Config.LINK_TIMEOUT)
		self.neighbours=[]
		#now start a thread for pinging the 'ip'
		# thread.start_new_thread(self.ping_user , ())

	def ping_user(self):
		#pings the node after some timeout...
		pac = LinkPacket()
		pac.setMessageByFields(7,self.ip,'')#7 => link check packet...
		while 1:
			self.soc.sendto(pac.getRawMessage(), (self.ip, Config.UDP_LISTEN_PORT))
			
			try:
				dat = self.soc.recvfrom(1024)	#wait for the reply...
			
			except socket.timeout:
				#the node at the other end is dead..
				pac = LinkPacket()
				print 'Node '+self.ip+' went away!'
				#for each neigbhour which is not neigh
				#of current node
				#start a new thread,
				#for sending the hop-count query
				has_node = 0
				for nde in self.neighbours:
					if nde not in self.main_list.nodes:
						#start a new thread
						tmppac = LinkPacket()
						tmppac.setMessageByFields(3, 
								Config.NODE_IP_ADDRESS,
									nde+chr(0))
						for nde2 in self.main_list.nodes:
							if nde2 != self.ip:
								#send the path_q to every node
								self.main_list.soc.sendto( 
									tmppac.getRawMessage(),
										(nde2,Config.UDP_LISTEN_PORT) )
						has_node =1

				if has_node==0:
					#evry thing is fine now
					#kill itself
					#remove the reference in the main_list
					print 'Deleting the Reference..'
					
					del self.ip,self.main_list.nodes[self.ip]
					self.main_list.nodes.remove(self.ip)
					
					return
				break

			time.sleep(Config.PATH_Q_TIMEOUT)


	def path_query(self, ip):
		#sends a path-query request to the 'ip'
		

		#now wait for about PATH_Q_TIMEOUT
		time.sleep(Config.PATH_Q_TIMEOUT)

		
	def add_neighbour(self, ip, flg):
		print "ip to remove/add:",ip
		if flg==1:#add the current neighbour...
			self.neighbours.append(ip)
		else:
			if ip in self.neighbours:
				self.neighbours.remove(ip)

	def getNeighbours(self):
		res = ''
		for ip in self.neighbours:
			res += ip+"|"
		return res[:-1]

	

