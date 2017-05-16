#-*-coding: utf-8-*-
# by Kali-KM
# Read Hex string, and convert it to IPv4

import os, sys, struct, socket

def main():
	Usage = "Usage : %Prog input output"

	if len(sys.argv) != 3:
		print Usage
		return
	
	with open(sys.argv[1], 'r') as f:
		with open(sys.argv[1], 'w') as o:
			while True:
				data = f.readline()
				if not data:
					break
				o.write(InttoIPv4(HextoInt(data)))
				o.write('\n')
	
def InttoIPv4(x):
	return ip_addr = socket.inet_ntoa(struct.pack("<L", x)
	
def HextoInt(x):
	return eval("0x"+x)

if __name__ == '__main__':
	main()
	
	
	
