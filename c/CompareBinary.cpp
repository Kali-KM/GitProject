#include <Windows.h>
#include <cstdio>
#include <iostream>

using namespace std;

void SearchFile(char *Path);
bool CheckPE(HANDLE hFile);
int CompareBin(HANDLE hFile);

int dwC_Offset;
int dwC_Size;
char *lpData;

int main(int argc, char **argv)
{
	
	if (argc != 5)
	{
		cout << "\n[-] Usage : CompareBinary.exe <target_path> <ScrFile> <hex offset> <hex size>" << endl;
		cout << "\tex) CompareBinary.exe C:\\Target C:\\ScrFile.exe 1f0 c00" << endl;
		return 0;
	}

	DWORD dwRead;
	char *Path = argv[1];
	char *scrFile = argv[2];
	dwC_Offset = (int)strtol(argv[3], NULL, 16);
	dwC_Size = (int)strtol(argv[4], NULL, 16);

	lpData = (char *)malloc(sizeof(char)*dwC_Size);
	HANDLE hScr = CreateFile(scrFile, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	SetFilePointer(hScr, dwC_Offset, 0, 0);
	ReadFile(hScr, lpData, dwC_Size, &dwRead, 0);

	/*
	for (int i = 0; i < 0x10; i++)
	{
		printf("%X ", (BYTE)lpData[i]);
	}
	*/

	SearchFile(Path);
}

void SearchFile(char *Path)
{
	int diff = 0;
	double average = 0.0;
	char FindName[0x100];
	char NextDir[0x100];
	char FullPath[0x100];

	WIN32_FIND_DATA FindData;
	BOOL result = FALSE;
	HANDLE hFile;

	sprintf(FindName, "%s\\*", Path);

	HANDLE hFind = FindFirstFile(FindName, &FindData);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		cout << "Error - Can't find a file : " << GetLastError() << endl;
		return;
	}

	while (TRUE)
	{
		if (FindData.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY)
		{	/*
			- 찾은 파일의 속성이 폴더인지 확인.
			- 폴더 속성이 맞고, 이름이 "." 과 ".." 인지 확인.
			- 둘 다 아니라면 폴더 이름을 경로에 추가 후 재귀.
			*/
			if (strcmp(FindData.cFileName, ".") && strcmp(FindData.cFileName, ".."))
			{
				sprintf(NextDir, "%s\\%s", Path, FindData.cFileName);
				SearchFile(NextDir);
			}
		}
		else
		{	/* 폴더가 아니라면 파일의 경로와 이름을 출력 */
			sprintf(FullPath, "%s\\%s", Path, FindData.cFileName);
			hFile = CreateFile(FullPath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
			if (CheckPE)
			{
				diff = CompareBin(hFile);
				average = 100 - (((double)diff / (double)dwC_Size) * 100);
				printf("File : %s, Different : %d, Similarity : %.2lf%%\n", FindData.cFileName, diff, average);
			}
			CloseHandle(hFile);
		}
		result = FindNextFile(hFind, &FindData);
		if (!result)
		{
			if (GetLastError() == ERROR_NO_MORE_FILES)
			{	/* 폴더에 더 이상 파일이 없는 경우 리턴 */
				return;
			}
		}
	}
}

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

	for (int i = 0; i < NumberofSections - 1; i++)
	{
		pSection++; 
	}

	PointertoRawdata = pSection->PointerToRawData;
	SizeofRawdata = pSection->SizeOfRawData;
	dwSize = GetFileSize(hFile, &dwSize);

	UnmapViewOfFile(pBase);
	CloseHandle(hMap);

	if (PointertoRawdata + SizeofRawdata > dwSize)
	{
		return FALSE;
	}

	return TRUE;
}

int CompareBin(HANDLE hFile)
{
	DWORD dwRead;
	int count = 0;

	char *dstData = (char *)malloc(sizeof(char)*dwC_Size);
	SetFilePointer(hFile, dwC_Offset, 0, 0);
	ReadFile(hFile, dstData, dwC_Size, &dwRead, 0);

	for (int i = 0; i < dwC_Size; i++)
	{
		if ((BYTE)lpData[i] != (BYTE)dstData[i])
		{
			count++;
		}
	}

	return count;
}