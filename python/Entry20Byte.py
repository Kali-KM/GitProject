# -*-coding: utf-8 -*-
# Author : Kali-KM
# Since : 2017.02.06

import sys, os, optparse, collections

class Parsing_PE():
	def __init__(self,f):
		self.f = f
		self.IMAGE_DOS_HEADER()
		self.IMAGE_NT_HEADER()
		self.IMAGE_SECTION_HEADER()

		
	def GetEP(self):
		return self.RVAtoRAW(self.addressofentrypoint)
		
	
	def IMAGE_DOS_HEADER(self):
		dos_header = bytearray(self.f.read(0x40))   
		mz_signature = dos_header[0x0:0x2]
		
		if mz_signature != "MZ":					# Check MZ Signature
			print "[-] Not exist MZ Header..."
			sys.exit(1)
		self.e_lfanew = LtoI(dos_header[0x3C:0x40])
		
	
	def IMAGE_NT_HEADER(self):
		self.f.seek(self.e_lfanew)
		nt_header = bytearray(self.f.read(0x200))
	
		pe_signature = nt_header[0x00:0x2]
		if pe_signature != "PE":					# Check PE Signature
			print "[-] Not exist PE Header..."
			sys.exit(1)
		
	# IMAGE_NT_HEADER.IMAGE_FILE_HEADER
		file_header = nt_header[0x04:0x18]
		self.numberofsections = LtoI(file_header[0x2:0x4])
		sizeofoptionalheader = LtoI(file_header[0x10:0x12])	
	
	# IMAGE_NT_HEADER.IMAGE_OPTIONAL_HEADER
		optional_header = nt_header[0x18:0x18+sizeofoptionalheader]
		self.addressofentrypoint = LtoI(optional_header[0x10:0x14])
		imagebase = LtoI(optional_header[0x1c:0x20])
		sectionalignment = LtoI(optional_header[0x20:0x24])
		self.filealignment = LtoI(optional_header[0x24:0x28])
		

		self.sectiontable_offset = self.e_lfanew+0x18+sizeofoptionalheader	# 섹션 테이블 위치 지정
	
		
	def IMAGE_SECTION_HEADER(self):
		self.f.seek(self.sectiontable_offset)
		
		sectiontable_size = self.numberofsections*0x28
		sectiontable = bytearray(self.f.read(sectiontable_size))	
		
		self.section_name=[]
		self.section_raw=[]
		self.section_rawsize=[]
		self.section_va=[]
		self.section_vasize=[]
		
		for i in range(0,self.numberofsections):
			sec_name = sectiontable[0x0:0x8]
			virtualsize = LtoI(sectiontable[0x8:0xc])
			rva = LtoI(sectiontable[0xc:0x10])
			sizeofrawdata = LtoI(sectiontable[0x10:0x14])
			pointertorawdata = LtoI(sectiontable[0x14:0x18])

			self.section_name.append(sec_name)
			self.section_raw.append(pointertorawdata)
			self.section_rawsize.append(sizeofrawdata)
			self.section_va.append(rva)
			self.section_vasize.append(virtualsize)
			
			sectiontable = sectiontable[0x28:]
		return
		
		
	def RVAtoRAW(self,va):			    				# Convert RVA to RAW 
		for i in range(0,len(self.section_name)):
			if va in range(self.section_va[i],self.section_va[i]+self.section_vasize[i]):
				return self.section_raw[i]+(va-self.section_va[i])
		return	


def LtoI(buf):	# Little Endian To Integer
    val =0
    for i in range(0, len(buf)):
        multi = 1
        for j in range(0,i):
            multi *= 256
        val += buf[i] * multi
    return val


	
def main():
	output = str(os.path.dirname( os.path.abspath(sys.argv[1]))) + "\\result.txt"

	try:
		o=open(output, 'w')
	except Exception, e:
		print "Error - ",
		print e
	
	for i in range(len(sys.argv)-1):
		s = sys.argv[i+1].split("\\")
		f=open(sys.argv[i+1], 'rb')
		parsing = Parsing_PE(f)
		EP = parsing.GetEP()
		
		f.seek(EP)	
		data = bytearray(f.read(0x20))
		
		o.write("[+] File Name: " + s[-1] + "\t")

		for i in range(0, len(data)):
			o.write("%02X " % data[i])
		o.write("\n")
		f.close()
	o.close()
	
if __name__ == '__main__':
	main()