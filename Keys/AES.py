
from Crypto.Random import Random#from Crypto import Random

from Crypto.Cipher import AES
from config import Config
import sys,os

'''
Wrapper class for AES.
Key-SIZE can be configured in config.py
16-byte block.
random IV
os.random Key
msg block of ENC_DEC_BLOCK_SIZE bytes is encrypted/decrypted
'''

class AESCipher:
	def __init__(self, key=''):
		self.iv = ''
		if len(key):
			#key is already supplied..just use for decrypting..
			self.aes_key = key
		else:
			#create a fresh aes key..
			self.aes_key = os.urandom(Config.AES_KEY_SIZE)
		#self.counter = 0

	def generateIV(self):
		self.iv = Random.new().read(AES.block_size)
		return self.iv

	def n_encrypt(self, msg):
		#this function is used to encrypt 
		#small messages rather than large files
		#implementation will be simple

		#check if the msg size is a multiple of '16'
		#if not, pad with zeros at the end
		msg += chr(16 - len(msg)%16)*(16 - len(msg)%16)

		#use the self.iv, which was generated previously
		#get an instance of aes with the key and our iv
		aesVar = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
		cipher_txt = aesVar.encrypt(msg)

		return cipher_txt

	def n_decrypt(self, cipher, iv):
		#for decrypting simple messages
		#rather than large files
		#cipher should  be a multiple of '16'

		if len(cipher)%16:
			print 'Block Size mismatch!'
			return ''

		# print 'Dec-key:'
		# for i in self.aes_key:
		# 	print ord(i),
		# print

		# print 'CIpher:'
		# for j in cipher:
		# 	print ord(j),
		# print

		aesVar = AES.new(self.aes_key, AES.MODE_CBC, iv)
		plain_txt = aesVar.decrypt(cipher)

		# print 'Ptext len:',len(plain_txt)
		# print 'Last-Bytes:'
		# for i in plain_txt:
		# 	print ord(i),
		# print
		#remove any padding if its there
		plain_txt = plain_txt[:-ord(plain_txt[-1])]

		return plain_txt
		
	def encrypt(self, msg):
		#message can be of any length...
		#this manages padding here..
		cipher_txt=''

		msg_chunks = \
		[msg[x:x+Config.ENC_DEC_BLOCK_SIZE] for x in range(0,len(msg),Config.ENC_DEC_BLOCK_SIZE)]
		for i in range(0, len(msg_chunks)-1):
			#doesn't require any padding...
			
			#generate a random-iv
			#???
			iv =  Random.new().read(AES.block_size)
			aesVar = AES.new(self.aes_key, AES.MODE_CBC, iv)
			cipher_txt += (iv +aesVar.encrypt(msg_chunks[i]+chr(self.counter)))
			self.counter = (self.counter+1)%256
		
		last_plain_txt = msg_chunks[-1] + chr(self.counter)
		#this may not be a multiple of enc_dec_block_size...
		#so add necessary padding...
		

		#**CAREFUL: padding zeros at the end!!**
		#last_plain_txt = last_plain_txt + \
		#chr(0)*(Config.ENC_DEC_BLOCK_SIZE-len(last_plain_txt))

		l = Config.ENC_DEC_BLOCK_SIZE

		last_plain_txt = chr(l - len(last_plain_txt)%l)*\
		( l- len(last_plain_txt)%l)

		iv=Random.new().read(AES.block_size)
		aesVar = AES.new(self.aes_key, AES.MODE_CBC, iv)
		cipher_txt += (iv +aesVar.encrypt(last_plain_txt))
		return cipher_txt

	def decrypt(self, cipher):
		#required : length of cipher must be exactly 
		# Config.ENC_DEC_BLOCK_SIZE+16...
		if len(cipher)!= Config.ENC_DEC_BLOCK_SIZE + 16:
			print 'Block Size mismatch..'
			#sys.exit(1)
			return ''

		plain_txt = ''
		#get the iv for the current cipher...
		iv = cipher[:16]
		aesVar = AES.new(self.aes_key, AES.MODE_CBC, iv)
		plain_txt = aesVar.decrypt(cipher[16:])#decipher the next bytes..
		#integrity check on the cipher...
		if ord(plain_txt[-1:])!=self.counter:
			print 'integrity failed!'
			return ''
		self.counter = (self.counter+1)%256

		plain_txt = plain_txt[:-ord(plain_txt[-1])]
		
		return plain_txt[:-1]#return all but last byte..
