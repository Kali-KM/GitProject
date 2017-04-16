#include <Windows.h>
#include <string.h>
#include <stdio.h>
#include <TlHelp32.h>

#define ThreadQuerySetWin32StartAddress 9  

typedef NTSTATUS(WINAPI *NtQueryInformationThreadT)(HANDLE ThreadHandle, ULONG ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);

BOOL GetThreadStartAddress(DWORD tid, PVOID *EntryPoint);
BOOL CompareBinary(CHAR Buffer[], CHAR Arr[]);

int main(int argc, char *argv[])
{
	BOOL bFlag_S = FALSE;
	BOOL bFlag_R = FALSE;
	BOOL result;
	THREADENTRY32 t32;
	PVOID EntryPoint;
	DWORD NumberofByteRead, dwFileSize;
	HANDLE hProc, hSnap, hFile, hThread;

	char Buffer[0x100];
	char Data[0x300];
	char Arr[0x100];
	char *pn = Arr;
	char *ptr;

	char *pArg;
	char *FileName;
	char *Usage = "\n[-] Usage : %Prog -f=BinaryFile [-s|-r]\n\t-s : suspend a thread\n\t-r : resume a thread\n";
	printf("\n[*] Search a Thread Tool - Memory Detect");
	printf("\n[*] Author : Kali-KM,  2017.04.13\n\n");

	if (argc < 2)
	{
		printf("%s", Usage);
		return 0;
	}

	/* check argv flag */
	for (int i = 0; i < argc; i++)
	{
		pArg = strstr(argv[i], "-f=");
		if (pArg != NULL)
			FileName = pArg;
		if (!strcmp(argv[i], "-s"))
			bFlag_S = TRUE;
		if (!strcmp(argv[i], "-r"))
			bFlag_R = TRUE;
	}

	if (!FileName | (bFlag_R && bFlag_S))
	{
		printf("%s", Usage);
		return 0;
	}

	/* clearing buffer */
	memset(Buffer, 0, sizeof(Buffer));
	memset(Data, 0, sizeof(Data));
	memset(Arr, 0, sizeof(Arr));


	/* read target file */
	FileName = FileName + 3;
	hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("[-] invalid a file handle. error code : 0x%X\n", GetLastError());
		return GetLastError();
	}

	dwFileSize = GetFileSize(hFile, &dwFileSize);
	if (dwFileSize > 0x300)
		dwFileSize = 0x300;

	if (!ReadFile(hFile, Data, dwFileSize, &NumberofByteRead, 0))
	{
		printf("[-] error file read. error code : 0x%X\n", GetLastError());
		return GetLastError();
	}

	/* sting to int array */
	ptr = strtok(Data, " ");
	while (1)
	{
		*pn++ = strtol(ptr, 0, 16);
		ptr = strtok(NULL, " ");
		if (ptr == NULL)
			break;
	}


	/* Create a Snapshot Handle */
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
		return 0;

	/* if you don't initialize THREADENTRY32.dwSize, Thread32First API fails */
	t32.dwSize = sizeof(THREADENTRY32);
	if (Thread32First(hSnap, &t32))
	{
		do
		{
			result = GetThreadStartAddress(t32.th32ThreadID, &EntryPoint);
			if ((DWORD)EntryPoint == 0x1)
			{
				continue;
			}
			hProc = OpenProcess(PROCESS_VM_READ, 0, t32.th32OwnerProcessID);
			ReadProcessMemory(hProc, EntryPoint, Buffer, 0x100, &NumberofByteRead);

			if (CompareBinary(Buffer, Arr))
			{
				printf("+ Detect It, Process ID : %d, Thread ID : %d, EntryPoint :0x%X\n", t32.th32OwnerProcessID, t32.th32ThreadID, EntryPoint);
				
				/* control flag */
				if (bFlag_S | bFlag_R)
				{
					hThread = OpenThread(THREAD_ALL_ACCESS, 0, t32.th32ThreadID);
					if (hThread == INVALID_HANDLE_VALUE)
						continue;
					if (bFlag_S)
						SuspendThread(hThread);
					if (bFlag_R)
						ResumeThread(hThread);
				}
			}
		} while (Thread32Next(hSnap, &t32));
	}
	CloseHandle(hSnap);

	return 0;
}

BOOL GetThreadStartAddress(DWORD tid, PVOID *EntryPoint)
{
	PVOID ThreadInfo;
	ULONG ThreadInfoLength;
	PULONG ReturnLength;

	HMODULE hNtdll = LoadLibrary("ntdll.dll");
	NtQueryInformationThreadT NtQueryInformationThread = (NtQueryInformationThreadT)GetProcAddress(hNtdll, "NtQueryInformationThread");

	if (!NtQueryInformationThread)
		return FALSE;

	/* if NtQueryInformationThread's THREADINFOCALSS is a ThreadQurtySetWin32StartAddress, return start address of thread */
	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, 0, tid);
	NTSTATUS NtStat = NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &ThreadInfo, sizeof(ThreadInfo), NULL);

	*EntryPoint = ThreadInfo;
	return TRUE;
}

BOOL CompareBinary(CHAR Buffer[], CHAR Arr[])
{
	for (int i = 0; i < sizeof(Arr); i++)
	{
		if ((BYTE)Arr[i] == 0x90)
		{
			continue;
		}

		if ((BYTE)Arr[i] != (BYTE)Buffer[i])
		{
			return FALSE;
		}
	}
	return TRUE;
}
