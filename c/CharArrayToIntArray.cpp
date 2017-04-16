#include <stdio.h>
#include <Windows.h>
#include <string.h>

/*
before: a[] = {"5","5"," ","4","0","3","b"} ; (string)"55 40 3b"
after : b[] = {'\x55', '\x40', '\x3b'}
*/

int main()
{
	HANDLE hFile;
	DWORD dwSize;
	DWORD dwNUmberOfByteRead;
	char data[0x100];
	char arr[0x100];
	char *pn = arr;
	int result=0;

	memset(data, 0, sizeof(data));
	memset(arr, 0, sizeof(arr));

	hFile = CreateFile("C:\\test.txt", GENERIC_READ, FILE_SHARE_READ, 0,OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(hFile == INVALID_HANDLE_VALUE)
		return GetLastError();

	dwSize = GetFileSize(hFile, NULL);
	result = ReadFile(hFile, data, dwSize, &dwNUmberOfByteRead, 0);
	/* ex) data[] = "50 4b c0 00" ; string data */
	
	if(!result)
		return GetLastError();

	char *ptr = strtok(data, " "); 
	while(1)
	{
		/* mov arr+i, hex_data */
		*pn++ = strtol(ptr, 0, 16); 
		ptr = strtok(NULL, " ");
		if(ptr==NULL)
			break;
	}
}

/*
char* StringToIntArray(char *data)
{
	char arr[0x100];
	char *pn = arr;
	char *ptr = strtok(data, "");
	while(1)
	{
		*pn++ = strtol(ptr, 0, 16);
		ptr = strtok(NUL, " ");
		if(ptr== NULL)
			break;
	}
	return arr	
}

*/
