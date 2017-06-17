#include <Windows.h>
#include <stdio.h>

bool Hook(char OriginCode[]);
void HookProc();

/*
- exe 형태로 제작하였지만, 이를 dll 형태로 만들어 인젝션을 수행해야 한다.
*/

int main()
{
	HANDLE hFile;
	int nError = 0;
	char OriginCode[5];
	bool bResult = Hook(OriginCode);
	if (!bResult)
	{
		nError = GetLastError(); 
		if (!nError)
		{
			printf("Error : already hooked.\n");
			return 0;
		}
		printf("Error - Code : 0x%X", nError);
		return nError;
	}
	hFile = CreateFileA("test.bin", GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Error - code : 0x%X\n", GetLastError());
	}
	printf("FILE_HANDLE : 0x%X\n", hFile);

	/* 
	- 망가진 stack 을 원래대로 되돌리기 위해 ebp 를 강제로 설정 
	- ebp 에 더해주는 값 또한 버전이나 컴파일 환경에 따라 상이함
	*/
	_asm{
		add ebp, 0x30;
	}
	return 0;
}

bool Hook(char *OriginCode)
{
	byte JmpCode[5] = { '\xE9', '\x00', '\x00', '\x00', '\x00' };
	byte ShortJmp[2] = { '\xEB', '\x05' };
	byte CheckOP[4] = { '\x00', '\x00', '\x90', '\x90' };
	HMODULE hMod = LoadLibrary("kernel32.dll");
	FARPROC fnProc = GetProcAddress(hMod, "CreateFileA");
	DWORD OldProtect, dwAddress, PatchPoint, ShortPoint;

	bool result = 0;
	memcpy(OriginCode, fnProc, 5);
	if (OriginCode[0] == '\xE9')
	{
		return 0;	// already hooked.
	}
	
	dwAddress = (DWORD)HookProc - (DWORD)fnProc - 5;
	PatchPoint = (DWORD)fnProc - 5;
	ShortPoint = (DWORD)fnProc - 2;

	VirtualProtect((PBYTE)PatchPoint, 10, PAGE_EXECUTE_READWRITE, &OldProtect);
	memcpy((PBYTE)PatchPoint, ((PBYTE)OriginCode) + 2, 3);
	memcpy((PBYTE)ShortPoint, ShortJmp, 2);
	memcpy(((PBYTE)JmpCode) + 1, &dwAddress, 4);
	memcpy(fnProc, JmpCode, 5);
	VirtualProtect((PBYTE)PatchPoint, 10, OldProtect, NULL);

	return 1;
}


void HookProc()
{
	HMODULE hMod = LoadLibrary("kernel32.dll");
	FARPROC fnProc = GetProcAddress(hMod, "CreateFileA");
	DWORD dwAddress = (DWORD)fnProc - 5;
	LPVOID FileName;

	/* CreateFileA 의 첫 번째 인자인 lpFileName 을 가지고 옴 */
	_asm{
		push ebx;
		mov ebx, [ebp + 8];
		mov FileName, ebx;
		pop ebx;
	}

	/* lpFileName 이 "test.bin" 인 경우 lpFileName 을 NULL 로 바꿈 */
	if (FileName == "test.bin")
	{
		_asm{
			push ebx;
			xor ebx, ebx;
			mov[ebp + 8], ebx;
			pop ebx;
		}
	}

	// asm 에서 add esp, ** 값은 stack 이 올바르게 구성하여, CreateFileA 이 정상 동작을 하도록 해야함
	_asm{
		add esp, 0x10;
		push dwAddress;
		retn;
	};
	return;
}
