#include <Windows.h>
#include <stdio.h>

int main()
{
	HANDLE hProc = 	OpenProcess(PROCESS_ALL_ACCESS, 0, 2564); 	// parameter 3 is PID
	HMODULE hMod = GetModuleHandle("KERNEL32.DLL");
	CHAR DllName[] = "C:\\Users\\user\\inject.dll";	// 
	BOOL bResult = 0;
	LPTHREAD_START_ROUTINE fpGetProc;
	HANDLE hNewThr;

	LPVOID lpAddr;
	if(!hProc)
		return GetLastError();
	
	lpAddr = VirtualAllocEx(hProc, 0, 1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if(!lpAddr)
		return GetLastError();
	
	bResult = WriteProcessMemory(hProc, lpAddr, DllName, strlen(DllName)+1, NULL);
	if(!bResult)
		return GetLastError();

	fpGetProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");
	if(!fpGetProc)
		return GetLastError();

	hNewThr = CreateRemoteThread(hProc, 0, 0, fpGetProc, lpAddr, 0, 0);
	if(!hNewThr)
		return GetLastError();

	return 0;
}