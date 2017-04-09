#include <Windows.h>
#include <stdio.h>

int main()
{
	DWORD dwAttribute = 0;	
	DWORD dwNewAttribute = 0;
	LPCTSTR lpFileName = "C:\\Users\\KaliKM\\Desktop\\test.exe";
	
	dwAttribute = GetFileAttributes(lpFileName);
	if(dwAttribute == -1)
	{
		return GetLastError();
	}

	/* Add a hidden attributes */
	dwNewAttribute = dwAttribute | FILE_ATTRIBUTE_HIDDEN;
	if(!SetFileAttributes(lpFileName, dwNewAttribute))
	{
		return GetLastError();
	}
	
	printf("File Attribute: 0x%X\n", dwAttribute);
	return 0;
}