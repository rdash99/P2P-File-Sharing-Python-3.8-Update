class AES:
	block_size = 16
	MODE_CBC = 1
	
	def __init__(self,k,t,i):
		self.key = k
		self.typ = t
		self.iv = i

	@classmethod
	def new(self,key,typ,iv):
		return AES(key,typ,iv)

	def encrypt(self,msg):
		key16 = self.key[:16]
		res = ''
		cnt=0
		for i in msg:
			res += chr(ord(key16[cnt])^ord(i))
			cnt = (cnt+1)%16
		return res

	def decrypt(self,cip):
		key16 = self.key[:16]
		res = ''
		cnt=0
		for i in cip:
			res += chr(ord(key16[cnt])^ord(i))
			cnt = (cnt+1)%16
		return res



