'''
Link Maintain Packet
Format:
 ____________ ____________ ______________ ___________
| 	1b		 |		4b	  |    2b		 |
|Request-type| ip-address |payload length| payload
|____________|____________|______________|___________


Request-type : 1 -> Broadcast New Connection Request 
				Eg: 1789500 
				=> 1 -> code. ip:7.8.9.5 payld-len:0
			   
			   2 -> Request for connection to a specific machine
			    Eg: 26543013
			    => 2 -> code. ip:6.5.4.3 payld-len:1
			    	indegree:3 -> of the requested node.
			   
			   3 -> Path Query
			    Eg: 3234905744412
			    => 3 -> code. ip:2.3.4.9 (src_of_the_request)
			       payld-len:6 . target_ip:7.4.4.4 length_so_far:12

			   4 -> Neighbour Update
			    Eg: 41234042378
			    => 4 -> code. src_ip:1.2.3.4 
			       payld-len:4. new_neighbour_to_src_ip:2.3.7.8(+/-)

			   5 -> Path Reply, Done by that node which has same ip as target..
			   	Eg: 5376706811113
			   	=> 5 -> code. ip:3.7.6.7 (src_of_the_request)
			   	   payld-len:6. target_ip:8.1.1.1 total_hop_count:13

			   6 -> Connection Confirm
			    Eg: 6321402n
			    => 6 -> code. ip:3.2.1.4 (src)
			       payld-len:2 data: "n" => not-confirmed, "y" => confirmed

			   7 -> Link Check
			    Eg: 7321300
			    =>  7 -> code. ip:3.2.1.3 (src)
			       payld-len:0

			   8 -> Link Reply
			    Eg: 8456300

			   9 -> Intermediate Path Reply
			    Eg: 9432306777712
			    => the middle node replies 4.3.2.3 if it has an entry
			    that specifies the path to 7.7.7.7.

			   10 -> Reply for Broadcast
			    Eg: 104232014
			    => 10 -> code. src:4.2.3.2
			       payld-len:1 cur_hop_count:4
			    11 -> Disconnection data
			    Eg: 11|src|4|connect_ip
	'''

class Converter:
	#converts 1.2.3.4 to 1234
	@staticmethod
	def get_encoded_ip(ip):
		return "".join(str(chr(int(x))) for x in ip.split("."))

	#converts 1234 to 1.2.3.4
	@staticmethod
	def get_decoded_ip(ip):
		return ".".join(str(ord(x)) for x in ip)

class LinkPacket:
	#constructor for LinkPacket
	def __init__(self,msg=''):
		self.core_data=msg
		self.request_type=-1
		self.ip_address=''
		self.payload_length=-1
		self.payload=''
		self.is_valid=1
		if len(msg):
			self.segment()

	def getRequestType(self):
		return self.request_type

	def isValid(self):
		return self.is_valid==1

	#this function breaks the packet into different fields
	def segment(self):
		if len(self.core_data)<7:
			#should be atleast 7 bytes...
			self.is_valid=0
			return

		self.request_type = ord(self.core_data[0])
		if self.request_type > 11:
			#invalid code..(can be changed in future)
			self.is_valid=0
			return

		self.ip_address = ".".join(str(ord(x)) for x in self.core_data[1:5])
		self.payload_length = ord(self.core_data[5])*255 + ord(self.core_data[6])
 
		if len(self.core_data)-7!=self.payload_length:
			self.is_valid=0
			return

		if self.payload_length > 0:
			self.payload = self.core_data[7:]

	def setCoreMessage(self,msg):
		self.core_data = msg
		self.is_valid=1
		self.segment()

	def getIPAddress(self):
		return self.ip_address
	
	def getPayload(self):
		return self.payload
	
	#set the message using given parameters
	def setMessageByFields(self,c_type,src_ip,pld):
		self.request_type=c_type
		self.ip_address=src_ip
		self.payload_length=len(pld)
		self.payload=pld
		self.formPacket()

	#creates a new packet out of given parameters
	def formPacket(self):
		self.core_data=''
		ans =''
		ans += str(chr(self.request_type))
		ans += Converter.get_encoded_ip(self.ip_address)
		ans += str(chr(self.payload_length/255))
		ans += str(chr(self.payload_length%255))
		ans += self.payload
		self.core_data = ans

	def printRawMessage(self):
		print self.core_data

	def getRawMessage(self):
		return self.core_data
		
	#prints the message by fields
	def printSegmentedMessage(self):
		if self.is_valid:
			print self.request_type,self.ip_address,self.payload_length,self.payload
		else:
			print 'Corrupted Packet!'
