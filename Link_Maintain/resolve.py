import fcntl,struct,socket
from config import Config
class Resolve:
	@staticmethod
	def resolve_ip_address(ifname):
	    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	    Config.NODE_IP_ADDRESS = socket.inet_ntoa(fcntl.ioctl(
	        s.fileno(),
	        0x8915,  # SIOCGIFADDR
	        struct.pack('256s', ifname[:15]))[20:24])