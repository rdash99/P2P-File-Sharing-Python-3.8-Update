import subprocess
from config import Config
p = subprocess.Popen(["./GetKeys",str(Config.KEY_SIZE),str(Config.MIN_KEY_SIZE)], stdout=subprocess.PIPE)
output = p.communicate()[0]
print output