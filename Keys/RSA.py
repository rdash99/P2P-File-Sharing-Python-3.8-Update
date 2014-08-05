from Crypto.PublicKey import RSA
from config import Config
import sys

class RSAKeys:
	def __init__(self, pubkey=''):
		if len(pubkey):
			#which means we are getting a public key...
			#Note: pubkey should always be in PEM Format...
			self.rsakey = RSA.importKey(pubkey)
		else:
			#create a new rsakey pair...
			self.rsakey = RSA.generate(Config.RSA_KEY_SIZE, None, None, 65537)

	def getPEMPublic(self):
		pub = self.rsakey.publickey()
		return pub.exportKey()

	def encrypt(self,msg):
		if len(msg)>self.rsakey.size()/8:
			#this key can't handle the current message...
			print 'Message exceeding key length!'
			sys.exit(1)
		cipher = self.rsakey.encrypt(msg, 'blabla')[0]
		#second arg for compatability...
		return cipher

	def decrypt(self,cipher):
		if not self.rsakey.has_private():
			#this obj only has public key...
			print 'Private key missing!'
			sys.exit(1)

		plaintxt = self.rsakey.decrypt(cipher)
		return plaintxt