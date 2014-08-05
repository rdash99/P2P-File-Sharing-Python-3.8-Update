from random import randint
class RSA:
	
	def __init__(self, pkey):
		self.public_key = pkey
		self.rsa_size = 2048

	@classmethod
	def importKey(self,key):
		return RSA(int(key))

	@classmethod
	def generate(self,sz,g1,g2,pub):
		return RSA(randint(1,256))

	def publickey(self):
		return self

	def exportKey(self):
		return str(self.public_key)

	def size(self):
		return self.rsa_size

	def encrypt(self, msg, salt):
		cipher = ''
		for i in msg:
			tmp = ord(i) - self.public_key
			if tmp<0:
				tmp += 256
			cipher += chr(tmp)
		return (cipher,0)

	def has_private(self):
		return True

	def decrypt(self, cip):
		# print "Got:",cip
		# print '^^^^^'
		plain = ''
		for i in cip:
			tmp = ord(i) + self.public_key
			tmp %= 256
			plain += chr(tmp)
		# print "Gave:",plain
		# print '^^^^^'
		return plain