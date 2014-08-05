from entity import Node
from packets import LinkPacket,Converter
from config import Config
from resolve import Resolve
import socket, time, thread, atexit


class UDPListener:
	def __init__(self):
		#Constructor for this object
		#Initialize various parameters
		#and open listening sockets


		#set the nodes IP-Address
		Resolve.resolve_ip_address(Config.NODE_INTF)
		#stores ip-addr => entity-reference
		self.nodes={} 

		#store ip of this machine
		#this variable is useful in the 
		#download module
		self.ip_address = Config.NODE_IP_ADDRESS
		#create the UDP Socket
		self.soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.soc.bind((Config.ANY_INTF, Config.UDP_LISTEN_PORT))
		
		#path info updated here dynamically
		self.path_cache={}
		self.query_cache={}
		
		#object to store path-query replies
		self.path_q_reply={}

		print 'Host IP:',Config.NODE_IP_ADDRESS
		print 'Waiting for other hosts...'
		#first get atleast two hosts
		self.getFirstTwoHosts()

		#there is no need of bcast bit from here.
		self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 0)

		#there is no need of timeout on this socket.
		#should wait indefinitely
		self.soc.settimeout(None)

		#spawn a new listening thread
		print 'Spawned listening thread...'
		thread.start_new_thread(self.listen,())

		print 'First two hosts:'
		print "\n".join(str(x) for x in self.nodes)
		print 'Neighbours:'
		for i in self.nodes:
			print 'via',i,":"
			for j in self.nodes[i].neighbours:
				print j,
			print

	def getFirstTwoHosts(self):
		#this method listens for broadcast requests
		#and sends timely broadcast requests to accommodate
		#new hosts and also replies for connection requests

		#set time-out for incoming broadcast requests
		self.soc.settimeout(Config.BROADCAST_TIMEOUT)

		#set the option for sending bcast packet
		self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

		b_pac = LinkPacket()
		
		b_pac.setMessageByFields(1,Config.NODE_IP_ADDRESS,'')
		replyList = [] 
		while len(self.nodes) < 2:
			#stores all the replies for 
			#the broadcasts by the current node
			#(in-degree,ip-address) 
			
			replyList = []
			#send a bcast packet
			self.soc.sendto(b_pac.getRawMessage(), 
				(Config.BROADCAST_IP_ADDRESS, 
					Config.UDP_LISTEN_PORT))
			print 'Sent broadcast request'
			while 1:
				if len(self.nodes) >= 2:
					return
				try:
					pac,addr = self.soc.recvfrom(1024)
					print '**** ***** ***** ****** ****'
					r_pac = LinkPacket(pac)
				except socket.timeout:
					#no requests or replies in the last few seconds
					#check if there are already two neighbours
					if len(self.nodes) >= 2:
						#return from the function
						#since the purpose is fulfilled
						return

					if len(replyList)==0:
						#no node replies for bcasts
						#so repeat it again
						break

					print 'Reply list not empty'
					print replyList
					#get the list, sort them, choose one 
					#with least degree, send a conn. req.
					replyList.sort()
					for tup in replyList:
						#check if its already a neighbour
						if tup[1] not in self.nodes:
							conn_pac = LinkPacket()
							conn_pac.setMessageByFields(2 , 
								Config.NODE_IP_ADDRESS, str(tup[0]))
							self.soc.sendto(conn_pac.getRawMessage(), (tup[1], Config.UDP_LISTEN_PORT))
							break
					break
				
				if addr[0]==Config.NODE_IP_ADDRESS:
					#print 'loopback packet'
					continue

				

				if not r_pac.isValid():
					#print 'Is Invalid'
					continue

				print 'src:',addr

				r_pac.printSegmentedMessage()
				
				rep_pac = LinkPacket()

				if r_pac.getIPAddress() not in self.nodes and \
					r_pac.getRequestType()==10:
					#someone replied for our bcast

					replyList.append([
						int(r_pac.getPayload()), r_pac.getIPAddress()
									])
				elif r_pac.getRequestType()==2:
					#connection request to this machine
					rep_pac = self.confirmConnectionRequest(r_pac)
					self.soc.sendto(rep_pac.getRawMessage(), addr)

				elif r_pac.getRequestType()==1:
					#someone is bcasting for a new
					#connection,reply them with current degree
					rep_pac.setMessageByFields(10, Config.NODE_IP_ADDRESS, str(len(self.nodes)))
					self.soc.sendto(rep_pac.getRawMessage(), addr)

				elif r_pac.getRequestType()==6:
					#got a reply to build a new connection
					#for a conn. req sent previously
					self.secondConfirmReq(r_pac)

				elif r_pac.getRequestType()==4:
					#neighbour updates
					self.addorRemoveNeighbourToEntity(r_pac.getIPAddress(), r_pac.getPayload())

				elif r_pac.getRequestType()==7:
					tp = LinkPacket()
					tp.setMessageByFields(8,self.ip_address,'')
					self.soc.sendto(tp.getRawMessage(), addr)	


	def update_cache(cache, target):
		time.sleep(Config.CACHE_TIME)
		cache.pop(target)

	def addnewNode(self,pac):
		
		print 'Adding Host:', pac.getIPAddress()
		self.nodes[pac.getIPAddress()] = Node(pac.getIPAddress(),self)
			
		#now send a neighbour update to all the adjacent nodes...
		tmp_pac = LinkPacket()
		tmp_pac.setMessageByFields(4,Config.NODE_IP_ADDRESS,pac.getIPAddress()+"+")

		for node in self.nodes:
			if node!=pac.getIPAddress():#don't send to the current node...
				self.soc.sendto(tmp_pac.getRawMessage(), (node, Config.UDP_LISTEN_PORT))

	def getAllNeighbours(self,ip):
		try:
			ans = self.nodes[ip].getNeighbours()
		except KeyError:
			return ''

		return ans

	def confirmConnectionRequest(self, pac):
		prev_degree = int(pac.getPayload())

		reply_pac = LinkPacket()

		if (prev_degree == len(self.nodes) or prev_degree <0 )and \
				pac.getIPAddress() not in self.nodes:
			#get the current neighbours
			neigh = ''
			for nde in self.nodes:
				neigh += nde+"|"
			print '^^'+neigh+'^^'+str(len(self.nodes))
			#create a new connection...
			self.addnewNode(pac)
			#neigh = self.getAllNeighbours(pac.getIPAddress())
			reply_pac.setMessageByFields(6, Config.NODE_IP_ADDRESS, "y"+neigh[:-1])
		else:
			#then sent degree and the current one are not equal...
			reply_pac.setMessageByFields(6, Config.NODE_IP_ADDRESS, "n")

		return reply_pac

	def secondConfirmReq(self,r_pac):
		if r_pac.getPayload()[0]=="y":
			
			#first send self's neighbours and then
			#add the other end's neighbours if any
			tmp_n_pac = LinkPacket()

			for neigh in self.nodes:
				tmp_n_pac.setMessageByFields(4,
				 Config.NODE_IP_ADDRESS, neigh+"+")
				self.soc.sendto(tmp_n_pac.getRawMessage(), 
					(r_pac.getIPAddress(), Config.UDP_LISTEN_PORT))
			self.addnewNode(r_pac)
			print '*'+r_pac.getPayload()[1:]+'*'
			#add all the neighbours sent in this request
			for neigh in r_pac.getPayload()[1:].split("|"):
				if neigh:
						self.nodes[r_pac.getIPAddress()].add_neighbour(neigh, 1)

	def listen(self):
		
		#initially send a broadcast for joining the network...
		
		while 1:
			
			dat,addr = self.soc.recvfrom(1024)
			#time.sleep(3)
			#handling all possible cases...
			pac = LinkPacket(dat)
			if not pac.isValid():
				print 'Corrupted packet from',addr
				continue

			to_be_replied=0
			r_type = pac.getRequestType()
			reply_pac = LinkPacket()
			print "src:",addr,"type:",r_type 
			if r_type==1:
				# brdcast for conn. request.. so reply with details..
				to_be_replied=1
				reply_pac.setMessageByFields(10, Config.NODE_IP_ADDRESS, str(len(self.nodes)))

			elif r_type==2:
				#conn req for this machine
				to_be_replied=1
				reply_pac = self.confirmConnectionRequest(pac)

			elif r_type==3:
				# a path query...
				to_be_replied=0 #first unset the reply flag...
				target_ip = Converter.get_decoded_ip(pac.getPayload()[:4])
				if target_ip==Config.NODE_IP_ADDRESS:
					#which means the target node has reached...
					reply_pac.setMessageByFields(5, target_ip, target_ip+pac.getPayload()[4:])

				else:
					#check if this has already been seen...
					if pac.getIPAddress()+target_ip in self.query_cache:
						continue
					#increment the hop count by '1'...	
					dat = ord(pac.getPayload()[4:]) + 1
					#form a packet to forward it...
					reply_pac.setMessageByFields(3, pac.getIPAddress() , target_ip+chr(dat))
					path_length = 0
					try:
						path_length = self.path_cache[target_ip]
					except KeyError:
						path_length = 0

					if path_length==0: #which means we dont have it in the query...
						#just forward the packet to all the adjacent nodes...
						#cache the query and path length...
						self.path_cache[pac.getIPAddress()] = dat #store the hop count b/w src and this node..
						self.query_cache[pac.getIPAddress()+target_ip] = ''
						
						#start the threads .. so that they delete the content after a time-out...

						thread.start_new_thread(self.path_cache, (pac.getIPAddress(),))
						thread.start_new_thread(self.query_cache, (pac.getIPAddress()+target_ip,))

						for node in self.nodes:
							self.soc.sendto(reply_pac.getRawMessage(), (node, Config.UDP_LISTEN_PORT))

					else:
						#we have the data from the cache.. so use it!..
						reply_pac.setMessageByFields(9, 
							Config.NODE_IP_ADDRESS,
							target_ip+chr(path_length))
			elif r_type==4:
				pac.printSegmentedMessage()
				#neighbour update ...
				to_be_replied=0
				self.addorRemoveNeighbourToEntity(pac.getIPAddress(), pac.getPayload())

			elif r_type==7:
				to_be_replied=1
				reply_pac.setMessageByFields(8, self.ip_address,'')

			elif r_type==9 or r_type==5:
				print 'Path Query Reply:'
				print pac.getPayload()

			elif r_type==11:
				#its a voluntary disconnect req
				print 'Disconnect request to',pac.getPayload()
				to_be_replied =0
				ip_to_conn = pac.getPayload()
				#del the reference from the entries
				try:
					del self.nodes[pac.getIPAddress()]
				except KeyError:
					#do nothing
					fg=1
				if ip_to_conn in self.nodes:
					#don't send the req. if its already
					#connected
					continue


				reply_pac = LinkPacket()
				reply_pac.setMessageByFields( 2, 
					Config.NODE_IP_ADDRESS,
					str(-1))
				self.soc.sendto(reply_pac.getRawMessage(), (ip_to_conn, 
											Config.UDP_LISTEN_PORT))
			if to_be_replied==1:#reply only if needed...
				self.soc.sendto(reply_pac.getRawMessage(), addr)



	def addorRemoveNeighbourToEntity(self, ip, payload):
		new_neigh = payload[:-1]
		add_or_remove = (0,1)[payload[-1]=='+']
		self.nodes[ip].add_neighbour(new_neigh, add_or_remove)