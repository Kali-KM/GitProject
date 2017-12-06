# -*-coding: utf-8 -*-
# 2017-12-06  Kali-KM
# Get EntryPoint Opcode

import pefile
import sys, os


def ParsingPE(file_pull_path, result, size):
	pe = pefile.PE(file_pull_path)
	ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
	ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
	data = pe.get_memory_mapped_image()[ep:ep+size]	
	
	file_name = (file_pull_path.split("\\"))[-1]
	result.write("[+] File : " + file_name+ " \t") 
	
	for i in data:
		opcode = "%.2x " % ord(i)
		result.write(opcode)
	result.write("\n")
		
def main():
	Usage = "[*] Usage : [-l length]or drag"
	result_file = str(os.path.dirname(os.path.abspath(sys.argv[-1]))) + "\\result.txt"
	result = open(result_file, 'w')

	IsManualFlag = sys.argv[1]
	if IsManualFlag == "-l":	# 길이 지정 모드
		LengthOfCode = int(sys.argv[2],16)
		DirPath = sys.argv[3]
	
		for root, dirs, files in os.walk(DirPath):
			rootpath = os.path.join(os.path.abspath(DirPath), root)
			dir = os.path.abspath(DirPath) + "\\"
			for file in files:
				try:
					ParsingPE(dir+file, result, LengthOfCode)
				except Exception, error:
					print "[-] Error : " + str(error)
	
	else:						# 기본 드래그 모드 (0x30 bytes)
		SizeOfArg = len(sys.argv) - 1
		for i in range(SizeOfArg):
			file_name = sys.argv[i+1]#.split("\\")
			try:
				ParsingPE(file_name, result, 48)
			except Exception, error:
				print "[-] Error : " + str(error)
	result.close()
		
if __name__ == '__main__':
	main()
