from socket import *

s=socket(AF_INET, SOCK_DGRAM)
s.settimeout(4)
try:
	k=s.recvfrom(1024)
except timeout:
	print 'No Connection! '