#include <Windows.h>
#include <Stdio.h>

int main()
{
	HANDLE hFile;
	LPCTSTR lpFileName = "C:\\Users\\KaliKm\\Desktop\\test.txt";
	TCHAR *s = 0;
	char Buffer[100];
	DWORD NumberofByteRead = 0;

	hFile = CreateFile(lpFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_ALLOCATE_BUFFER, 0, GetLastError(), 0, (TCHAR *)&s, 0, 0);
		printf("Error : %s\n",s);
		LocalFree(s);
		getchar();
		return GetLastError();
	}
	
	CloseHandle(hFile);
	return 0;
}
