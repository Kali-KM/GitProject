#-*-coding: utf-8-*-

import os, sys, os.path
import shutil


def main():
	if len(sys.argv) < 4:
		print "\n\t[+] usage: %prog txt_file src_dir dst_dir"
		return 0
		
	txt_file = os.path.normcase(sys.argv[1])
	src_dir = os.path.normcase(sys.argv[2])
	dst_dir = os.path.normcase(sys.argv[3])
	
	f=open(txt_file, 'rb')
	
	count = 0
	while True:
		name = f.readline()
		if name == "":
			print "[+] Success."
			break
		file_name = src_dir + "\\" + name
		file_name = file_name[:-2]

		try:
			shutil.copy(file_name, dst_dir)
			count = count +1
		except Exception, e:
			print "[-] Error : " + str(e)
			
	
	print "[+] Total File Count : %d" % count		
		
if __name__ == '__main__':
	main()