# Hex_viewer.py 
#-*- coding: utf-8 -*-
# [+] Kali-KM's Hex Viewer 2015-11-03, kali-km.tistory.com
# [+] Usage : python Hex_viewer.py read_file <offset-hex>
# [+] Ex : python Hex_viewer.py read_me.exe 0x27e
# [+] 	 : python Hex_viewer.py read_me.exe 0xf

import sys

offset = 0

def func(f):
	global offset

	data = f.read(16)
	if len(data) == 0 : sys.exit(0)
	result = '%08X : ' %(offset)
	for i in range(len(data)): result += '%02X ' % (ord(data[i]))
	if len(data) != 16:
		for i in range(16-len(data)) : result += '   '
	for i in range(len(data)):
		if (ord(data[i])) >= 0x20 and (ord(data[i])) <= 0x7E: result += data[i]
		else : result += '.'
	print result
	offset += 16

def main():
	global offset
	
	if len(sys.argv) < 2:
		print "\n[-] Usage : Python Hex_viewer.py read_file <offset>"
		sys.exit(0)
	f=open(sys.argv[1],'rb')

	try:
		if sys.argv[2]==hex(0) or sys.argv[2]==str(0):
			for i in range(0,16) : func(f)
		while True:
			if sys.argv[2] == hex(offset):
				for i in range(0,16) : func(f)
			else:
				data=f.read(1)
				if len(data) == 0 : break
				offset += 1
		sys.exit(0)
	except:
		while True:
			func(f)


if __name__ == '__main__':
	main()
