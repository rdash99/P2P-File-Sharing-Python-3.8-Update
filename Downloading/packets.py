from Link_Maintain.packets import Converter

'''
	This class provides interface for creating different 
	types of packets.
	
			4B 			 1B
		 ____________ ____________ _______________
		|			 |			  |
		|	Src IP   |  req-type  | depends on req-type
		|____________|____________|_______________

	req-type:1 => search-query

	format:
		___2B________________2B___________________
	   |			|	  |			     |	      |
	   |querylength |query|key-len/256   | RSA-Key|__key=> search-key
	   |____________|_____|_+ key_len%256|_PEM_format| Privacy-Enhanced-Mail

	req-type:2 => search-results

	format:
		 ___2B_____________________2B_____________________
	   	|			|			|			   |	      |
		|search-res	|search-res	|key-len/256   | AES-Key  | key=>download-key
		|length_____|___________|_+ key_len%256|_of_sender|

	src IP -> destinationIP

	req-type:3 => download-request

	format: 	2B 								2B
		|meta-data-len|data about interim node|key-size|key| key=>aes256 key
	
	src IP -> interim node IP

	req-type:4 => relay-node-request

	format:
		|0/1|ip:port to connect(optional)| 
		=> 0: forward data to src-ip
		=> 1: receive data from src-ip (here we need to give ip:port)
	req-type:5 => relay-node-reply

	format:
		|port-for-req-node|port-for-other-node(optional)|		
	
'''

class SearchPacket:
	def __init__(self, pac=''):
		#pac should always be in decrypted form..
		self.packet = pac
		self.src_ip = ''
		self.req_type = -1
		self.dat = ''
		self.key = ''
		self.isvalid = 1
		if len(pac):
			#means we have a packet
			#fragment it.
			self.fragment()
	def fragment(self):
		pac = self.packet
		self.src_ip = Converter.get_decoded_ip(pac[:4])
		self.req_type = ord(pac[4])

		if self.req_type<=0 or self.req_type>5:
			self.isvalid = 0
			return

		if self.req_type < 4:
			#they bore a format shown above
			#get the data length
			if len(pac)<6:
				self.isvalid = 0
				return
			len_dat = ord(pac[5])*256 + ord(pac[6])
			
			#check if length is within the bounds
			if len_dat+7 >= len(pac):
				self.isvalid = 0
				return
			self.dat = pac[7:7+len_dat]

			#get the key length
			key_len = ord(pac[7+len_dat])*256 + ord(pac[7+len_dat+1])
			
			#check the format of the packet
			if len(self.packet)!= 4+1+2+2+len_dat+key_len:
				self.isvalid = 0
				return
			self.key = pac[7+len_dat+2: 7+len_dat+2+key_len]

		else:
			#this will have simple format
			self.dat = pac[5:]

	#returns if the packet is valid or not
	def isValid(self):
		return self.isvalid==1

	#used for packets of rtype>=4
	def setPacketByFields(self, typ, src, payload):
		self.packet = Converter.get_encoded_ip(src) +\
						chr(typ) + payload

	
	def getRawMessage(self):
		return self.packet

	#used for packets of rtype<4
	def setPacket(self, rtype, src, dat, key):
		self.setRequestType(rtype)
		self.setIP(src)
		self.setData(dat)
		self.setKey(key)

		self.makePacket()

##########setter functions
	def setRequestType(self,n):
		#n->integer
		self.req_type=n

	def setKey(self,ky):
		self.key = ky

	def setData(self,data):
		self.dat = data

	def setIP(self,ip):
		self.src_ip = ip
###########
###########getter functions
	def getRequestType(self):
		#n->integer
		return self.req_type

	def getKey(self):
		return self.key

	def getData(self):
		return self.dat

	def getIP(self):
		return self.src_ip
	
	def makePacket(self):
		pac = ''
		#ip address
		pac += Converter.get_encoded_ip(self.src_ip)
		# print pac,'*',len(pac)
		#request-type
		pac += chr(self.req_type)
		# print pac,'*',len(pac)
		#length of payload...
		pac += chr(len(self.dat)/256) 
		pac += chr(len(self.dat)%256)
		# print pac,'*',len(pac)
		#append the payload
		pac += self.dat
		
		#append key-size
		pac += chr(len(self.key)/256)
		pac += chr(len(self.key)%256)
		# print pac,'*',len(pac)
		#append key
		pac += self.key
		# print pac,'*',len(pac)
		self.packet = pac
