
# -*-coding: utf-8 -*-
import os
import sys
import hashlib



def main():
	DirPath = sys.argv[1]
	
	md5 = hashlib.md5()
	
	for root, dirs, files in os.walk(DirPath):
		rootpath = os.path.join(os.path.abspath(DirPath), root)
		
		for file in files:
			filepath = os.path.join(rootpath, file)
			md5 = hashlib.md5()
			with open(filepath, 'rb') as f:
				while True:
					data = f.read(8192)
					if not data:
						break
					md5.update(data)
			file_hash = md5.hexdigest().upper()
			
			cmd = "rename " +filepath+" "+file_hash
			os.system(cmd)

if __name__ == '__main__':
	main()
	

