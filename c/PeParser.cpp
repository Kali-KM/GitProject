#include <Windows.h>
#include <iostream>
#include <cstdio>
#define EXPORT extern "C" __declspec(dllexport)

typedef struct PE_INFO
{
	BYTE bResult;
	DWORD EntryPoint;
}PE_INFO;

EXPORT PE_INFO PeParsing(HANDLE hFile);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	return 1;
}

PE_INFO PeParsing(HANDLE hFile)
{
	PE_INFO PeInfo = { 1, 0 };
	PE_INFO Error = {0, 0};

	if (hFile == INVALID_HANDLE_VALUE)
		return Error;
	DWORD dwSize = GetFileSize(hFile, NULL);
	HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);

	if (!hMap)
		return Error;

	LPVOID lpBase = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

	PIMAGE_FILE_HEADER lpHeader = (PIMAGE_FILE_HEADER)(BYTE *)lpBase;


	OutputDebugString("Fail the mapping");


	return PeInfo;
}
