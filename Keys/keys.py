import subprocess
from config import Config

'''
	this class creates an object containing the public and private KeyPair
	Each key-size can be varied and can be set in the Config.py file.

'''
class KeyPair:
	def __init__(self):
		p = subprocess.Popen(["./GetKeys",str(Config.KEY_SIZE),str(Config.MIN_KEY_SIZE)], stdout=subprocess.PIPE)
		output = p.communicate()[0]
		output = output.split()
		self._e_ = int(output[0])
		self._d_ = int(output[1])
		self._n_ = int(output[2])

	def printKeys(self):
		print self._e_,self._d_,self._n_

	def encrypt(self,msg):
		print 'h'