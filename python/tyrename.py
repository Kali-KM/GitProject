#-*-coding: utf-8-*-
# by Kali-KM
# tyrename.py

import os, sys

def main():
	Usage = "\n Usage : %Prog -r|-o target_dir"
	if len(sys.argv) != 3:
		print Usage
		return
	
	flag = sys.argv[1]
	DirPath = sys.argv[2]
	
	# change to [TN] name
	if flag == "-r":
		for root, dirs, files in os.walk(DirPath):
			rootpath = os.path.join(os.path.abspath(DirPath), root)
			dir = os.path.abspath(DirPath) + "\\"
			for file in files:
				src = os.path.join(dir,file)
				tmp = "[TN]" + file
				dst = os.path.join(dir,tmp)
				os.rename(src, dst)
				
	# change to original name
	elif flag == "-o":
		for root, dirs, files in os.walk(DirPath):
			rootpath = os.path.join(os.path.abspath(DirPath), root)
			dir = os.path.abspath(DirPath) + "\\"
			for file in files:
				if file[0:4] == "[TN]":
					src = os.path.join(dir,file)
					dst = os.path.join(dir, file[4:])
					os.rename(src, dst)
				else:
					continue
	
	# else exit program
	else:
		print Usage
		return
			
if __name__ == '__main__':
	main()