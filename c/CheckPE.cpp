bool CheckPE(HANDLE hFile)
{
	IMAGE_DOS_HEADER *pDos;
	IMAGE_NT_HEADERS *pNt;
	IMAGE_FILE_HEADER *pFile;
	IMAGE_OPTIONAL_HEADER *pOption;
	IMAGE_DATA_DIRECTORY *pDataDir;
	IMAGE_SECTION_HEADER *pSection;
	DWORD NumberofSections;
	DWORD NumberofData;
	DWORD PointertoRawdata;
	DWORD SizeofRawdata;
	DWORD dwSize;

	HANDLE hMap = CreateFileMapping(hFile, 0, PAGE_READONLY, 0, 0, 0);
	void *pBase = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);


	/* (BYTE *)는 그 주소와 상수를 더하기 위해 필요함 */
	pDos = (IMAGE_DOS_HEADER *)pBase;
	pNt = (IMAGE_NT_HEADERS *)(pDos->e_lfanew + (BYTE *)pDos);
	pFile = (IMAGE_FILE_HEADER *)((BYTE *)pNt + 4);
	pOption = (IMAGE_OPTIONAL_HEADER *)((BYTE *)pNt + 0x18);

	if (pDos->e_magic != 0x5a4d || pNt->Signature != 0x4550)
	{
		return FALSE;
	}

	NumberofSections = pFile->NumberOfSections;
	NumberofData = pOption->NumberOfRvaAndSizes;

	pDataDir = (IMAGE_DATA_DIRECTORY *)((BYTE *)pOption + 0x60);
	pSection = (IMAGE_SECTION_HEADER *)((BYTE *)pDataDir + (NumberofData * 8));

	for (int i = 0; i < NumberofSections-1; i++)
	{
		pSection++; // 마지막 섹션으로 이동
	}

	PointertoRawdata = pSection->PointerToRawData;
	SizeofRawdata = pSection->SizeOfRawData;
	dwSize = GetFileSize(hFile, &dwSize);

	UnmapViewOfFile(pBase);
	CloseHandle(hMap);

	/* 실제 파일의 사이즈가 PE 구조에 나타난 크기 보다 작을 경우 FALSE 반환 */
	if (PointertoRawdata + SizeofRawdata > dwSize)
	{
		return FALSE;
	}

	return TRUE;
}