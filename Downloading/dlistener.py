from packets import SearchPacket
from Keys.RSA import RSAKeys
from Keys.AES import AESCipher
from config import Config
import socket,time,thread,os,random
from random import randint

class Downloader:
	def __init__(self,l_obj):
		#object reference from Link_Maintain module
		self.linkObj = l_obj
		#rsa key object
		self.Rsa_key = RSAKeys()
		#aes object for enc and dec files
		self.Aes_key = AESCipher()

		for i in self.Aes_key.aes_key:
			print ord(i),
		print
		#start a udp listener here with
		#port configured in the config file
		#create the UDP Socket
		self.soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.soc.bind((Config.ANY_INTF, Config.D_UDP_LISTEN_PORT))
		
		#stores the query caches
		#format: src_ip|search_query
		self.query_cache = []

		#object for storing search results
		#format: [query,size,origin-ip,aes-key]
		self.search_results=[]

		#object for user's choice from
		#search results
		self.user_choice=-1
		thread.start_new_thread(self.listen, ())

		#variable to store req. file
		self.req_file=''
		#stores the aes key of the receipient
		self.recv_key=''


	def updateQueryCache(self, val):
		#wait for some time
		time.sleep(Config.QUERY_CACHE_TIME)
		self.query_cache.remove(val)

	def decryptPacket(self,data):
		#leave away the first 4 bytes
		#its ip
		#check the fifth byte
		if ord(data[4])==1:
			#its a search query
			#not encrypted at all so don't proceed 
			#furthur
			return data
		elif ord(data[4])==2:
			#they are search results
			#directed to us
			#decrypt them with the RSA Key
			#decryption starts from the 6th byte
			res = self.Rsa_key.decrypt(data[5:])
			return data[:5]+res
		elif ord(data[4])==3:
			#its a download request
			#encrypted with AES
			#last 16-bytes is the IV
			iv = data[-16:]
			#decrypt from 6th byte to last but 17th byte
			p_txt = self.Aes_key.n_decrypt(data[5:-16], iv)
			return data[:5]+p_txt
		else:
			#all other types are plain-texts
			#so return as-it-is
			return data

	def listen(self):
		#listens to:
		# forwarding search queries,
		# relay node requests
		# aggregates search-results

		while 1:
			dat, addr = self.soc.recvfrom(1024)
			#print 'Got a packet'
			#print 'From:',addr
			#print 'Data:',dat
			#decrypt the packet if necessary

			pac = self.decryptPacket(dat)
			#print 'DData:',dat
			# for i in dat:
			# 	print ord(i),
			# print
			#now proceed for fragmenting 
			# for i in pac:
			# 	print ord(i),
			# print
			pac = SearchPacket(pac)
			is_invalid = 0
			if not pac.isValid():
				print 'Corrupted Packet',pac.getRequestType()
				is_invalid=1

			if pac.getRequestType()==1:
				# its a search request
				
				print 'Search Req from',addr[0]
				#if its invalid just discard
				if is_invalid:
					print 'invalid Packet'
					continue
				#check if its already in the cache
				if pac.getData() in self.query_cache:
					#if it is, then ignore the packet
					print 'duplicate query'
					continue

				print 'Searching the system..'
				#forward this search query to all the neighbours
				#we get the neighbours from the link object
				for neig in self.linkObj.nodes:
					if neig != addr[0]:
						self.soc.sendto(pac.getRawMessage(),
							(neig, Config.D_UDP_LISTEN_PORT))

				self.query_cache.append(pac.getData())
				#now start a thread to remove this after some time
				thread.start_new_thread( self.updateQueryCache, (pac.getData(),))
				#search in our file-system and get the results
				res = self.searchFiles(pac.getData())
				if len(res):
					#if the result is non-empty
					#first encrypt the results using
					#the pulic-key sent in the packet
					#print 'Results:'
					#print res
					#print 'RSA Key:',pac.getKey()
					tmprsa = RSAKeys(pac.getKey())
					
					#get the length of results
					l_res = len(res)

					#get the length of keys
					l_keys = len(self.Aes_key.aes_key)


					#form the packet
					dat = chr(l_res/256) + chr(l_res%256) + res\
							+ chr(l_keys/256) + chr(l_keys%256) +\
					self.Aes_key.aes_key
					

					print 'Got Some results!'
				#	print '***',dat,'***'
					# for i in dat:
					# 	print ord(i),
					# print 
					#encrypt it
					cipher = tmprsa.encrypt(dat)

					#print 'Len:',len(cipher)
				#	print '********',cipher,'******',len(cipher)
					#now, make a packet with these results
					tmppac = SearchPacket()

					#type:2, 
					#src-ip -> src of the query issuer
					#send aes-key of this machine
					tmppac.setPacketByFields(2,pac.getIP(),
								cipher)

					#print 'Req IP:',pac.getIP()
					#print tmppac.getRawMessage(),'|||||'
					# for i in tmppac.getRawMessage():
					# 	print ord(i),
					# print 
					#get a random first hop from the
					#neighours
					nxt_ip=''
					#check if its the same node 
					#that is requesting
					#
					for i in self.linkObj.nodes:
						if i!=addr[0]:
							nxt_ip=i
							break

					print 'Sending to:',nxt_ip

					self.soc.sendto(tmppac.getRawMessage(),
									(nxt_ip, Config.D_UDP_LISTEN_PORT))
				else:
					print 'No results'


			elif pac.getRequestType()==2:
				#this is a search-results packet
				#check if the IP matches with us

				#print pac.getIP(),'===',self.linkObj.ip_address

				if pac.getIP()==self.linkObj.ip_address:
					#display the results
					res = pac.getData()
					# print 'Got the Key:'
					# for i in pac.getKey():
					# 	print ord(i),
					# print
					for r in res.split("||"):
						f = r.split()
						if len(f)==2:
							self.search_results.append(
								[f[0],f[1],addr[0],pac.getKey()]
								)
							print str(len(self.search_results)).ljust(4)+ f[1].ljust(16)+f[0].ljust(8)+addr[0].ljust(10)
				else:
					#this should be forwarded to
					#the intended ip-address
					#in this case, 'dat'
					print 'forwarding to ',pac.getIP()
					self.soc.sendto(dat, (pac.getIP(),
									Config.D_UDP_LISTEN_PORT
									))
			elif pac.getRequestType()==3:
				#a download request
				#if is_invalid is set=>not intended for us
				#forwarding to neighbours depends on the
				#dest-address

				if not is_invalid:
					#intended for us
					print 'Got a download request'
					self.setupSourceRelayNode(pac)
				elif is_invalid and \
					pac.getIP()==self.linkObj.ip_address:
					#its an interim node
					#should forward to neighbours
					print 'Forwarding to adjacent nodes'
					for ip in self.linkObj.nodes:
						self.soc.sendto(dat, 
							(ip, Config.D_UDP_LISTEN_PORT) 
							)
			elif pac.getRequestType()==4:
				#requesting this machine to act as
				#relay node
				#check the type bit first
				print 'Got a relay-node request'
				#print 'Data:',pac.getRawMessage()
				if pac.getData()[0]=='0':
					#forward data to src-ip
					#create listening socket for src-ip to connect
					print 'On receiving end'
					tcpsoc1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					tcpsoc1.bind(('',0))

					#for the other node to connect
					tcpsoc2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					tcpsoc2.bind(('',0))

					tmppac = SearchPacket()
					tmppac.setPacketByFields(
						5, self.linkObj.ip_address,
						str(tcpsoc1.getsockname()[1])+"|"+
						str(tcpsoc2.getsockname()[1])
						)
					self.soc.sendto(tmppac.getRawMessage(), addr)
					#now create a thread which listens on these ports
					thread.start_new_thread(
						self.receiveEndThread,
						(tcpsoc1, tcpsoc2))
				elif pac.getData()[0]=='1':
					#get data from src-ip
					#and forward it to some other node
					#we will have the details of src-ip:port to
					#connect
					print 'r-req for sending end'
					ip = pac.getData().split("|")[1]
					ip,port = ip.split(":")[0],ip.split(":")[1]

					tcpsoc1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					tcpsoc1.bind(('',0))

					tmppac = SearchPacket()
					tmppac.setPacketByFields(
						5, self.linkObj.ip_address,
						str(tcpsoc1.getsockname()[1])
						)
					thread.start_new_thread(
						self.sendEndThread,
						(ip,port, tcpsoc1))
					time.sleep(2)
					print 'Sending port to',addr[0]
					self.soc.sendto(tmppac.getRawMessage(), 
								addr)
			elif pac.getRequestType()==5:
				#reply from the relay node
				print 'Got a reply from relay-node'
				#split by '|'
				print pac.getData(),'**'
				vals = pac.getData().split('|')
				if len(vals)==2:
					#means this is on receiving end
					#connect to the port and get the data.

					thread.start_new_thread(self.downloadFile,
						(addr[0], int(vals[0]))
						)
					time.sleep(1)
					#send the other port details
					#to the interim node
					#format: file_name|ip:port
					dat = self.search_results[self.user_choice-1][1]+"|"
					dat += addr[0] +':'+vals[1]
					dat = chr(len(dat)/256)+chr(len(dat)%256)+dat

					key_aes = self.search_results[self.user_choice-1][3]
					our_key = self.Aes_key.aes_key
					#encrypt the request with the other user's key
					our_key = chr(len(our_key)/256)+\
								chr(len(our_key)%256)+our_key

					# print 'Ptxt:',int(len(dat+our_key))
					# for q in dat+our_key:
					# 	print ord(q),
					# print
					# print 'Encrypt-Key:'
					# for h in key_aes:
					# 	print ord(h),
					# print

					aesVar = AESCipher(key_aes)
					rand_iv = aesVar.generateIV()
					cipher = aesVar.n_encrypt(dat + our_key)

					# print 'cipher:',int(len(cipher))
					#destination is our intermediate node
					dest_ip = self.search_results[self.user_choice-1][2]
					d_pac = SearchPacket()
					d_pac.setPacketByFields( 3, 
						dest_ip,
						cipher
						)
					tmps = d_pac.getRawMessage()+rand_iv
					# for c in tmps:
					# 	print ord(c),
					# print
					print 'Sending dwnld req to',dest_ip
					self.soc.sendto(d_pac.getRawMessage()+rand_iv, 
								(dest_ip,  Config.D_UDP_LISTEN_PORT))
				else:
					#the vals[0] is where we need to connect
					#and then start uploading the file..
					#so start a thread directly
					print 'Starting the upload thread'
					thread.start_new_thread(self.uploadFile,
										(addr[0], int(vals[0])))




	def uploadFile(self,ip,port):
		#connect to the ip:port and start sending the data
		#first open the file
		fd = open(self.req_file, 'r')
		tcps = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		print 'Started upload thread'
		tcps.connect((ip, port))
		tmpAes = AESCipher(self.recv_key)
		iv = tmpAes.generateIV()

		#first send the iv in plain
		tcps.send(iv)

		while 1:
			st = fd.read(15)#read 16-bytes. encrypt them & send
			print 'Got',len(st),'bytes'
			cip = tmpAes.n_encrypt(st)
			tcps.send(cip)
			if len(st)<15:
				break
		print 'Done Uploading..'
		tcps.close()

	def downloadFile(self,ip,port):
		#connect to the ip:port and wait for the data.
		#get the file-name

		print 'Started download-file thread'
		f_name = self.search_results[self.user_choice-1][1]
		fd = open(f_name, 'w')
		tcps = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		print 'Connecting to',ip+":"+str(port)

		tcps.connect((ip, port))

		print 'Connected'
		#first 16-bytes are the IV
		self.Aes_key.iv = tcps.recv(16)
		print 'Got the IV'
		while 1:
			st = tcps.recv(16)
			print 'Got',len(st),'bytes..'
			if st=='':
				#connection closed
				print 'Download Finished'
				tcps.close()
				fd.close()
				break
			pln = self.Aes_key.n_decrypt(st,self.Aes_key.iv)
			print 'wrote..',pln
			fd.write(pln)
		print 'File-Contents:'
		fr = open(f_name, 'r')
		while 1:
			st = fr.read(1024)
			if st=='':
				break
			print st
		

	def sendEndThread(self, ip,port,tcp1):
		#tcp1 -> listen for connection from src_node
		#connect itself to ip:port
		print 'Starting send-end thread..'
		tcp2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		tcp2.connect((ip, int(port)))

		tcp1.listen(10) 
		print 'Listening on '+ip+':'+port
		fd,addr = tcp1.accept()
		print 'Got a connection'
		while 1:
			#transfer data from tcp1 to tcp2
			#until connection is closed
			st = fd.recv(16)
			if st=='':
				#closed connection
				fd.close()
				return
			print 'Got',len(st),'bytes'
			tcp2.send(st)
		print 'Closing connection..'

	def receiveEndThread(self, tcp1, tcp2):
		#wait for the incoming connection
		#from the src_node
		print 'Started recevive-end thread'
		tcp1.listen(10)
		fd1, addr = tcp1.accept()
		print 'Connected to source-node'
		#now wait for the other node to connect
		tcp2.listen(10)
		fd2, addr = tcp2.accept()
		print 'Connected to other-end relay node'
		while 1:
			#write whatever data comes to tcp2
			#into tcp1
			st = fd2.recv(16)
			if st=='':
				#connection has been closed
				#close this one also and kill this thread
				fd1.close()
				return
			print 'Got',len(st),'bytes'
			fd1.send(st)
		print 'Closing Connection...'


	def searchNetwork(self,query):
		#creates a search packet
		#and sends it to adjacent nodes
		qpac = SearchPacket()
		qpac.setRequestType(1)#'1' for searching
		qpac.setKey(self.Rsa_key.getPEMPublic())
		qpac.setData(query)
		qpac.setIP(self.linkObj.ip_address)
		qpac.makePacket()
		#first empty the search-results list
		self.search_results=[]

		print 'Sending:',qpac.getRawMessage()
		print self.Rsa_key.getPEMPublic(),self.linkObj.ip_address
		#fire the query into the network
		#via the adjacent nodes
		for nds in self.linkObj.nodes:
			self.soc.sendto(qpac.getRawMessage(),
								(nds, Config.D_UDP_LISTEN_PORT))
			print 'Sent to:',nds+":"+str(Config.D_UDP_LISTEN_PORT)
		
		print 'Search Query sent!\nWaiting for results'
		print 'S.No'.ljust(4)+'File-Name'.ljust(16)+'Size'.ljust(8),'Source'.ljust(10)

	def searchFiles(self,query):
		#this searches our file file-system
		#assumed that 'shared' is a directory 
		#with in the pwd of the program
		command = 'wc -c * 2>/dev/null | grep '+query+\
					' | awk \'{printf "%s||",$0}\''

		print command
		#execute the command
		f = os.popen(command)

		#get the results
		res = f.read()

		return res

	def downloadRequest(self,choice):
		#this function starts the dwnld process
		#for a specific file
		#choice is an integer corresponding to the entry in 
		#the search results list

		self.user_choice = choice
		#first create a packet for relay-node 
		rpac = SearchPacket()

		#pick one of the r_node from the adj ones
		r_node = ''
		tmpnode = ''#in case r_node is empty
		for i in self.linkObj.nodes:
			tmpnode = i
			if randint(1,3)==2:
				r_node = i
				break

		if r_node=='':
			r_node = tmpnode

		#'0'=> wants to get data from relay-node
		rpac.setPacketByFields(4, self.linkObj.ip_address,
								'0')
		print 'Sending relay-request to',r_node
		self.soc.sendto( rpac.getRawMessage(),
			  				(r_node, Config.D_UDP_LISTEN_PORT))

	#def setupDestRelayNode(self):

	def setupSourceRelayNode(self,pac):
		#this fn. requests for a relay nodes
		#to open a socket and transfer
		#data from this machine
		#return ip-address:port pair
		#where the relay node is listening
		self.req_file = pac.getData().split("|")[0]
		self.recv_key = pac.getKey()

		ipport = pac.getData().split("|")[1]
		msg = '1|'+ipport
		pac = SearchPacket()

		pac.setPacketByFields(4, 
				self.linkObj.ip_address,
				msg)

		#pick one of the r_node from the adj ones
		r_node = ''
		tmpnode = ''#in case r_node is non-empty
		for i in self.linkObj.nodes:
			tmpnode = i
			if randint(1,3)==2 and i!=ipport.split(":")[0]:
				r_node = i
				break
		if r_node=='':
			r_node = tmpnode
		print 'Sending r-req to',r_node
		self.soc.sendto(pac.getRawMessage(),
		 (r_node, Config.D_UDP_LISTEN_PORT))		