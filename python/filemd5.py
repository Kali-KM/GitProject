# -*-coding: utf-8 -*-
import os
import sys
import hashlib



def main():

	if len(sys.argv) == 1:
		print "Usage : filemd5.py [DirPath]"
		sys.exit(0)
	target_dir = sys.argv[1]
	root_path = ''
	file_list = []

	for root, dirs, files in os.walk(target_dir):
		root_path = os.path.join(os.path.abspath(target_dir), root)
		for file in files:
			filepath = os.path.join(root_path, file)
			file_list.append(filepath)
			
	md5 = hashlib.md5()

	for file_path in file_list:
		with open(file_path, 'rb') as f:
			while True:
				data = f.read(8192)
				if not data:
					break
				md5.update(data)
		hash_path =  "\"" + root_path+ "\\" + str(md5.hexdigest().upper()) + "\""
		filepath = "\"" + file_path + "\""
		cmd = "move /y " + filepath + " " + hash_path
		os.system(cmd)

if __name__ == '__main__':
	main()
	

