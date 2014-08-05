from random import randint
class Random:
	def __init__(self):
		self.seed = 100

	@classmethod
	def new(self):
		return Random()

	def read(self,n):
		res = ''
		while n:
			res += chr(randint(1,255))
			n-=1
		return res
