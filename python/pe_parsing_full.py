# -*-coding: utf-8 -*-

import sys, os, datetime, optparse, collections

class Parsing_PE():
	def __init__(self,f):
		self.f = f
		self.buf = bytearray(self.f.read())
		self.IMAGE_DOS_HEADER()
		self.IMAGE_NT_HEADER()
		self.IMAGE_SECTION_HEADER()
		
		try:
			if self.table_export_rva: self.EXPORT_Section()
			if self.table_import_rva: self.IMPORT_Section()
			if self.table_reloc_rva : self.RELOCATION_Section()
		except MemoryError:
			print "[-] This file is so big..."
			sys.exit(0)
	
	def IMAGE_DOS_HEADER(self):
		dos_header = self.buf[0x0:0x40]
		mz_signature = dos_header[0x0:0x2]
		if mz_signature != "MZ":					# Check MZ Signature
			print "[-] Not exist MZ Header..."
			sys.exit(1)
		self.e_lfanew = LtoI(dos_header[0x3C:0x40])
		print"""
[+] IMAGE_DOS_HEADER --------------------
	MZ Signature : %s
	e_lfanew : 0x%X"""%(mz_signature, self.e_lfanew)
	
	def IMAGE_NT_HEADER(self):

		nt_header = self.buf[self.e_lfanew:self.e_lfanew+0x200]
		pe_signature = nt_header[0x00:0x2]
		if pe_signature != "PE":					# Check PE Signature
			print "[-] Not exist PE Header..."
			sys.exit(1)
		
	# IMAGE_NT_HEADER.IMAGE_FILE_HEADER
		file_header = nt_header[0x04:0x18]
		machine = LtoI(file_header[0x0:0x2])
		
		self.numberofsections = LtoI(file_header[0x2:0x4]) # IMAGE_SECTION_HEADER에서 참조
		timedatestamp = time_convert(LtoI(file_header[0x4:0x8]))
		pointertosymboltable = LtoI(file_header[0x8:0xc])
		numberofsymbols = LtoI(file_header[0xc:0x10])
		sizeofoptionalheader = LtoI(file_header[0x10:0x12])
		characteristics = LtoI(file_header[0x12:0x14])			
	
	# IMAGE_NT_HEADER.IMAGE_OPTIONAL_HEADER
		optional_header = nt_header[0x18:0x18+sizeofoptionalheader]
		
		magic = LtoI(optional_header[0x0:0x2])
		linkerversion = str(LtoI(optional_header[0x2:0x3]))+"."+str(LtoI(optional_header[0x3:0x4]))
		sizeofcode = LtoI(optional_header[0x4:0x8])
		sizeofinitializeddata = LtoI(optional_header[0x8:0xc])
		sizeofuninitializeddata = LtoI(optional_header[0xc:0x10])
		
		addressofentrypoint = LtoI(optional_header[0x10:0x14])
		baseofcode = LtoI(optional_header[0x14:0x18])
		baseofdata = LtoI(optional_header[0x18:0x1c])
		imagebase = LtoI(optional_header[0x1c:0x20])
		sectionalignment = LtoI(optional_header[0x20:0x24])
		filealignment = LtoI(optional_header[0x24:0x28])
		
		osversion = str(LtoI(optional_header[0x28:0x2a]))+"."+str(LtoI(optional_header[0x2a:0x2c]))
		imageversion = str(LtoI(optional_header[0x2c:0x2e]))+"."+str(LtoI(optional_header[0x2e:0x30]))
		subsystemversion = str(LtoI(optional_header[0x30:0x32]))+"."+str(LtoI(optional_header[0x32:0x34]))
		win32version = LtoI(optional_header[0x34:0x38])
		
		sizeofimage = LtoI(optional_header[0x38:0x3c])
		sizeofheader = LtoI(optional_header[0x3c:0x40])
		
		checksum = LtoI(optional_header[0x40:0x44])
		subsystem = LtoI(optional_header[0x44:0x46])	

		dllcharacteristics = LtoI(optional_header[0x46:0x48])
		sizeofstackreserve = LtoI(optional_header[0x48:0x4c])
		sizeofstackcommit = LtoI(optional_header[0x4c:0x50])
		sizeofheapreserve = LtoI(optional_header[0x50:0x54]) 
		sizeofheapcommit = LtoI(optional_header[0x54:0x58])
		loaderflags = LtoI(optional_header[0x58:0x5c])
		numberofdatadirectories = LtoI(optional_header[0x5c:0x60])
		
		# 섹션 테이블 위치 지정 : IMAGE_SECTION_HEADER에서 참조
		self.sectiontable_offset = self.e_lfanew+0x18+sizeofoptionalheader	
	
		print """
[+] IMAGE_NT_HEADER --------------------
	# PE Signature : %s

	# IMAGE_FILE_HEADER
		Machine : 0x%X
		Number Of Sections : 0x%X
		Time Data Stamp : %s
		Pointer to Symbol Table : 0x%X
		Number Of Symbol : 0x%X
		Size Of Optional Header : 0x%X
		Characteristis : 0x%X

	# IMAGE_OPTIONAL_HEADER
		Magic : 0x%X
		Linker Version : %s
		Size Of Code : 0x%X
		Size Of Initialized Data : 0x%X
		Size Of Uninitalizeed Data : 0x%X
		Address Of Entry Point : 0x%X
		Base Of Code : 0x%X
		Base Of Data : 0x%X
		Image Base : 0x%X
		Section Alignment : 0x%X
		File Alignment : 0x%X
		O/S Version : %s
		Image Version : %s
		Subsystem Version : %s
		Win32 Version : %s
		Size Of Image : 0x%X
		Size Of Headers : 0x%X
		Checksum : 0x%X
		Subsystem : 0x%X
		DLL Characteristis : 0x%X
		Size Of Stack Reserve : 0x%X
		Size Of Stack Commit : 0x%X
		Size Of Heap Reserve : 0x%X
		Size Of Heap Commit : 0x%X
		Loader Flags : 0x%X
		Number Of Data Directories : 0x%X"""	%(pe_signature, machine, self.numberofsections, timedatestamp, pointertosymboltable,
	numberofsymbols, sizeofoptionalheader, characteristics,magic,linkerversion, sizeofcode, sizeofinitializeddata, sizeofuninitializeddata,
	addressofentrypoint, baseofcode, baseofdata, imagebase, sectionalignment, filealignment, osversion, imageversion, subsystemversion, win32version, sizeofimage, sizeofheader, checksum, subsystem, dllcharacteristics, sizeofstackreserve, sizeofstackreserve, sizeofheapreserve, sizeofheapcommit, loaderflags, numberofdatadirectories)
	
	# IMAGE_NT_HEADER.IMAGE_OPTIONAL_HEADER.IMAGE_DATA_DIRECTORY
		self.table_export_rva = LtoI(optional_header[0x60:0x64])
		self.table_export_size = LtoI(optional_header[0x64:0x68])
				
		self.table_import_rva = LtoI(optional_header[0x68:0x6c])
		self.table_import_size = LtoI(optional_header[0x6c:0x70])

		self.table_resource_rva = LtoI(optional_header[0x70:0x74])
		self.table_resource_size = LtoI(optional_header[0x74:0x78])		
		
		self.table_exception_rva = LtoI(optional_header[0x78:0x7c])
		self.table_exception_size = LtoI(optional_header[0x7c:0x80])		
		
		self.table_certificate_rva = LtoI(optional_header[0x80:0x84])
		self.table_certificate_size = LtoI(optional_header[0x84:0x88])
		
		self.table_reloc_rva = LtoI(optional_header[0x88:0x8c])
		self.table_reloc_size = LtoI(optional_header[0x8c:0x90])
		
		self.table_debug_rva = LtoI(optional_header[0x90:0x94])
		self.table_debug_size = LtoI(optional_header[0x94:0x98])		
		
		self.table_architecture_rva = LtoI(optional_header[0x98:0x9c])
		self.table_architecture_size = LtoI(optional_header[0x9c:0xa0])
		
		self.table_gp_rva = LtoI(optional_header[0xa0:0xa4])
		self.table_gp_size = LtoI(optional_header[0xa4:0xa8])	
		
		self.table_tls_rva = LtoI(optional_header[0xa8:0xac])
		self.table_tls_size = LtoI(optional_header[0xac:0xb0])		
		
		self.table_load_rva = LtoI(optional_header[0xb0:0xb4])
		self.table_load_size = LtoI(optional_header[0xb4:0xb8])		
		
		self.table_bound_rva = LtoI(optional_header[0xb8:0xbc])
		self.table_bound_size = LtoI(optional_header[0xbc:0xc0])		
		
		self.table_iat_rva = LtoI(optional_header[0xc0:0xc4])
		self.table_iat_size = LtoI(optional_header[0xc4:0xc8])		
		
		self.table_delay_rva = LtoI(optional_header[0xc8:0xcc])
		self.table_delay_size = LtoI(optional_header[0xcc:0xd0])			
		
		self.table_cli_rva = LtoI(optional_header[0xd0:0xd4])
		self.table_cli_size = LtoI(optional_header[0xd4:0xd8])
		
		print"""		
		+ IMAGE_DATA_DIRECTORY
		EXPORT Table 
			RVA : 0x%X, Size : 0x%X
		IMPORT Table
			RVA : 0x%X, Size : 0x%X
		RESOURCE Table
			RVA : 0x%X, Size : 0x%X
		EXCEPTION Table
			RVA : 0x%X, Size : 0x%X
		CERTIFICATE Table
			RVA : 0x%X, Size : 0x%X
		BASE RELOCATION Table
			RVA : 0x%X, Size : 0x%X
		DEBUG Directory
			RVA : 0x%X, Size : 0x%X
		Architecture Specific Data
			RVA : 0x%X, Size : 0x%X
		GLOBAL POINTER Register
			RVA : 0x%X, Size : 0x%X
		TLS Table
			RVA : 0x%X, Size : 0x%X
		LOAD CONFIGURATION Table
			RVA : 0x%X, Size : 0x%X
		BOUND IMPORT Table
			RVA : 0x%X, Size : 0x%X
		IMPORT Address Table
			RVA : 0x%X, Size : 0x%X
		DELAY IMPORT Descriptors
			RVA : 0x%X, Size : 0x%X
		CLI Header
			RVA : 0x%X, Size : 0x%X
		NULL
			RVA : 0x0, Size : 0x0			
	""" % (self.table_export_rva,self.table_export_size, self.table_import_rva, self.table_import_size, self.table_resource_rva, self.table_resource_size, self.table_exception_rva, self.table_exception_size, self.table_certificate_rva, self.table_certificate_size, self.table_reloc_rva, self.table_reloc_size, self.table_debug_rva, self.table_debug_size, self.table_architecture_rva, self.table_architecture_size, self.table_gp_rva, self.table_gp_size, self.table_tls_rva, self.table_tls_size, self.table_load_rva, self.table_load_size, self.table_bound_rva, self.table_bound_size, self.table_iat_rva, self.table_iat_size, self.table_delay_rva, self.table_delay_size, self.table_cli_rva, self.table_cli_size)
		return
	
		
	def IMAGE_SECTION_HEADER(self):
		sectiontable_size = self.numberofsections*0x28		
		sectiontable = self.buf[self.sectiontable_offset : self.sectiontable_offset+sectiontable_size]
		
		print "[+] IMAGE_SECTION_HEADER --------------------"
		
		# 각 섹션의 주소 변환을 위해 이를 저장할 배열을 선언
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
			pointertorelocations = LtoI(sectiontable[0x18:0x1c])
			pointertolinenumbers = LtoI(sectiontable[0x1c:0x20])
			numberofrelocations = LtoI(sectiontable[0x20:0x22])
			numberoflinenumbers = LtoI(sectiontable[0x22:0x24])
			characteristics = LtoI(sectiontable[0x24:0x28])
			
			self.section_name.append(sec_name)
			self.section_raw.append(pointertorawdata)
			self.section_rawsize.append(sizeofrawdata)
			self.section_va.append(rva)
			self.section_vasize.append(virtualsize)
			
			sectiontable = sectiontable[0x28:]

			print"""
	# IMAGE_SECTION_HEADER %s
		Name : %s
		Virtual Size : 0x%X
		RVA : 0x%X
		Size of Raw Data : 0x%X
		Pointer to Raw Data : 0x%X
		Pointer to Relocations : 0x%X
		Pointer to Line Numbers : 0x%X
		Number of Relocations : 0x%X
		Number of Line Numbers : 0x%X
		Characteristis : 0x%X"""% (sec_name, sec_name,virtualsize, rva,sizeofrawdata,pointertorawdata,pointertorelocations,pointertolinenumbers,numberofrelocations,numberoflinenumbers,characteristics)
		return
		
	
	def EXPORT_Section(self):
	
		export_section_offset = self.RVAtoRAW(self.table_export_rva)	
		export_data = self.buf[export_section_offset:]
		
		print"\n[+] EXPORT Section --------------------"
		characteristics = LtoI(export_data[0x0:0x4])
		if LtoI(export_data[0x04:0x08]) == 0 : timedatestamp = "0"
		else : timedatestamp = time_convert(LtoI(export_data[0x04:0x08]))
		version = str(LtoI(export_data[0x8:0xa]))+"."+str(LtoI(export_data[0xa:0xc]))
		
		ordinal_base =  LtoI(export_data[0x10:0x14])
		numberoffunctions = LtoI(export_data[0x14:0x18])
		numberofnames = LtoI(export_data[0x18:0x1c])
		export_addresstable_rva = LtoI(export_data[0x1c:0x20]) 
		export_addresstable_offset = self.RVAtoRAW(export_addresstable_rva)
		export_nametable_rva = LtoI(export_data[0x20:0x24])
		export_nametable_offset = self.RVAtoRAW(export_nametable_rva)
		export_ordinaltable_rva = LtoI(export_data[0x24:0x28])
		export_ordinaltable_offset = self.RVAtoRAW(export_ordinaltable_rva)
		
		dll_name_offset = self.RVAtoRAW(LtoI(export_data[0xc:0x10]))
		name_buf = self.buf[dll_name_offset:]
		dll_name = []
		while True:
			if not name_buf or name_buf[0] == 0: break
			else:
				dll_name.append(name_buf[0])
				name_buf = name_buf[1:]
		dll_name = "".join(str(bytearray(dll_name)))	
			
		print"""
	Characteristis : 0x%X
	Time Date Stamp : %s
	Version : %s
	Name : %s
	Ordinal Base : 0x%X
	Number of Functions : 0x%X
	Number of Names : 0x%X
	Address Table RVA : 0x%X (Offset : 0x%X)
	Name Talbe RVA : 0x%X (Offset : 0x%X)
	Ordinal Table : 0x%X (Offset : 0x%X)
		"""%(characteristics,timedatestamp,version,dll_name,ordinal_base,numberoffunctions,numberofnames, export_addresstable_rva,export_addresstable_offset ,export_nametable_rva, export_nametable_offset,export_ordinaltable_rva,export_ordinaltable_offset)

# Export Ordinal Table		
		print"""
	* Export Ordinal Table
	Offset  Data  Base   Value
	=============================================="""
		eot_data = self.buf[export_ordinaltable_offset:]
		tmp_data = eot_data
		tmp_offset = export_ordinaltable_offset
		ordinals = []
		
		for i in range(0,numberofnames):
			ordinal = LtoI(tmp_data[0x0:0x2])
			ordinals.append(ordinal+ordinal_base)
			tmp_data = tmp_data[0x2:]
			print "\t0x%X  0x%X + 0x%X  >   0x0%X" % (tmp_offset, ordinal, ordinal_base,ordinal+ordinal_base)
			tmp_offset+=4
		
# Export Name Table
		print"""
	* Export Name Table
	Offset   Data	Ordinal   Value
	=============================================="""
		ent_data = self.buf[export_nametable_offset:]
		tmp_data = ent_data
		tmp_offset = export_nametable_offset
		api_names = []
		
		for i in range(0,numberofnames):
			api_rva = LtoI(tmp_data[0x0:0x4])
			api_offset = self.RVAtoRAW(api_rva)
			api_data = self.buf[api_offset:]
			api_name = []
			while True:
				if api_data[0] == 0:
					api_name = "".join(str(bytearray(api_name)))
					break
				else:
					api_name.append(api_data[0])
					api_data = api_data[1:]
			api_names.append(api_name)
			print "\t0x%X  0x%X  0x0%X  %s" % (tmp_offset, api_rva, ordinals[i],api_name)
			tmp_data = tmp_data[0x4:]
			tmp_offset += 0x4	
		
		set = {}				# 딕셔너리 생성				
		for i in range(0,len(ordinals)):
			set[ordinals[i]] = api_names[i]
		
# Export Address Table 
		print"""
	* Export Address Table
	Offset   Data	Ordinal   Value
	=============================================="""
		eat_data = self.buf[export_addresstable_offset:]
		tmp_data = eat_data
		tmp_offset = export_addresstable_offset
		
		ordinals.sort()   # 번호 순대로 정렬 > EAT는 서수를 기준으로 위치
		
		for ordinal in ordinals : # for 문으로 수정해야함
			api_rva = LtoI(tmp_data[0x0:0x4])
			if api_rva == 0 : break
			api_name = set[ordinal]	     # 각 서수에 맞는 API 이름 추출			
			print "\t0x%X  0x%X   0x0%X   %s" % (tmp_offset, api_rva,ordinal, api_name)
			tmp_offset += 0x4
			tmp_data = tmp_data[0x4:]
		return

		
	def IMPORT_Section(self):
		import_section_offset = self.RVAtoRAW(self.table_import_rva)
		import_data = self.buf[import_section_offset:]
		
		print"\n[+] IMPORT Section --------------------"	
		tmp_data = import_data
		arr_name = []
		arr_int = []
		arr_iat = []

# IMPORT Directory Table
		
		while True:
			if LtoI(tmp_data[0x0:0x14]) == 0: break
			int_rva = LtoI(tmp_data[0x0:0x04])

			int_offset = self.RVAtoRAW(int_rva)
			if int_offset == None: int_offset = 0
			if LtoI(tmp_data[0x4:0x8]) == 0: timedatestamp = "0"
			else: timedatestamp = time_convert(LtoI(tmp_data[0x4:0x8]))
			forwarderchain = LtoI(tmp_data[0x8:0xc])
			name_rva = LtoI(tmp_data[0xc:0x10])
			name_offset = self.RVAtoRAW(name_rva)
			
			name_buf = self.buf[name_offset:]	
			name = []
			while True:
				if name_buf[0] == 0: 
					name = "".join(str(bytearray(name)))
					break
				else:
					name.append(name_buf[0])
					name_buf = name_buf[1:]			
			iat_rva = LtoI(tmp_data[0x10:0x14])
			iat_offset = self.RVAtoRAW(iat_rva)
			tmp_data =tmp_data[0x14:]	
			
			arr_name.append(name)
			arr_int.append(int_rva)
			arr_iat.append(iat_rva)
			
			
			print"""
	Import Name Table RVA : 0x%X (Offset : 0x%X)
	Time Data Stamp : %s
	Forwarder Chain : 0x%X
	Name RVA : 0x%X (Name : %s)
	Import Address Table RVA : 0x%X (Ofset : 0x%X)"""%(int_rva,int_offset,timedatestamp,forwarderchain, name_rva, name, iat_rva, iat_offset)

	
# Import Name Table	
		print"""\n
	* Import Name Table
	Offset   Data	 Name
	=============================================="""
		for i in range(0,len(arr_int)):
			int_rva = arr_int[i]
			int_offset = self.RVAtoRAW(int_rva)
			int_data = self.buf[int_offset:]			
			if int_rva == 0:
				int_offset = 0
				int_data = [0]*4
			
			tmp_offset = int_offset	
			while True:
				api_rva = LtoI(int_data[0x0:0x4])
				if api_rva == 0: break
				api_offset = self.RVAtoRAW(api_rva)
				
				ordinal_flag = 0
				api_data = [0]
				try:
					api_data = self.buf[api_offset+2:]								
				except TypeError:
					ordinal_flag = 1
					pass
				api_name = []		
				while True:
					if api_data[0] == 0: 
						api_name = "".join(str(bytearray(api_name)))
						break
					else:
						api_name.append(api_data[0])
						api_data = api_data[1:]
				int_data = int_data[0x4:]
				if ordinal_flag == 1:
					api_name = "0x"+str(hex(api_rva)[-3:])[-3:-1]+" (Ordinal)"
				print "\t0x%X  0x%X    %s" % (tmp_offset, api_rva, api_name)
				tmp_offset += 0x4
			print"\t--------------------------------------%s" % arr_name[i]
			
# Import Address Table
		print"""\n
	* Import Address Table
	Offset   RVA	Data 	 Value
	=============================================="""
		for i in range(0,len(arr_iat)):
			iat_rva = arr_iat[i]
			iat_offset = self.RVAtoRAW(iat_rva)
			iat_data = self.buf[iat_offset:]
			
			tmp_offset = iat_offset
			tmp_rva = iat_rva
			
			while True:
				api_rva = LtoI(iat_data[0x0:0x4])
				if api_rva == 0:break
				api_offset = self.RVAtoRAW(api_rva)				
				ordinal_flag = 0
				try:
					api_data = self.buf[api_offset+2:]
				except TypeError:
					ordinal_flag = 1
					pass		
					
				api_name = []
				
				
				try:
					while True:
						if api_data[0] == 0:
							api_name = "".join(str(bytearray(api_name)))
							break
						else:
							api_name.append(api_data[0])
							api_data = api_data[1:]
				except:
					api_name = ""
				iat_data = iat_data[0x4:]
				if ordinal_flag == 1:
					api_name = "0x"+str(hex(api_rva)[-3:])[-3:-1]+" (Ordinal)"
				print "\t0x%X  0x%X  0x%X    %s" % (tmp_offset, tmp_rva,api_rva, api_name)
				tmp_offset += 0x4
				tmp_rva += 0x4
			print"\t--------------------------------------%s" % arr_name[i]
		return
	
	
	def RELOCATION_Section(self):
		print"\n[+] Relocation Section --------------------\n"
	
		reloc_section_offset = self.RVAtoRAW(self.table_reloc_rva)
		reloc_data = self.buf[reloc_section_offset:]
	
		
		while True:
			reloc_base = LtoI(reloc_data[0x0:0x4])
			if reloc_base == 0: break
			reloc_sizeofblock = LtoI(reloc_data[0x4:0x8])
			reloc_num = (reloc_sizeofblock-8)/2
			print"\tBase Address : 0x%X\n\tSize of Block : 0x%X (Num : 0x%X)" % (reloc_base, reloc_sizeofblock, reloc_num)

			typeoffset_data = reloc_data[0x8:]			
			for i in range(0,reloc_num):
				type_word = LtoI(typeoffset_data[0x0:0x2])
				type_offset = (type_word & 0xfff)
				if type_offset == 0:
					type_rva = 0
					type_raw = 0
				else:
					type_rva = reloc_base+type_offset
					type_raw = self.RVAtoRAW(type_rva)
				print "\t\tType Value : 0x%X --- RVA : 0x%X (Offset : 0x%X)" %(type_word,type_rva,type_raw)		
				typeoffset_data = typeoffset_data[0x2:]
				
			reloc_data = reloc_data[(reloc_num*2)+8:]
			print "\t---------------------------------------------"
		return

		
	def RVAtoRAW(self,va):			    				# Convert RVA to RAW 
		for i in range(0,len(self.section_name)):
			if va in range(self.section_va[i],self.section_va[i]+self.section_vasize[i]):
				return self.section_raw[i]+(va-self.section_va[i])
		return		
	
	def WhereAtSection(self,va):
		for i in range(0,len(self.section_name)):
			if va in range(self.section_va[i],self.section_va[i]+self.section_vasize[i]):
				return self.section_raw[i], self.section_rawsize[i]	

def LtoI(buf):	# Little Endian To Integer
    val =0
    for i in range(0, len(buf)):
        multi = 1
        for j in range(0,i):
            multi *= 256
        val += buf[i] * multi
    return val

def time_convert(int_buf):
	time_format = "%Y-%m-%d %H:%M:%S"
	timestamp = datetime.datetime.fromtimestamp(int_buf).strftime(time_format)
	return timestamp
	
def main():
	usage="[+] Usage : pythn pe_parser.py -f <file name>"
	parser = optparse.OptionParser(usage=usage)
	parser.add_option('-f', '--file',dest='target_file',help='specifies the file name')
	(options,args) = parser.parse_args()
	if not options.target_file:
		print parser.usage
		sys.exit(0)

	f=open(options.target_file,'rb')
	parsing = Parsing_PE(f)
	
if __name__ == '__main__':
	main()