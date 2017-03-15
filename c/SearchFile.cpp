
#include <Windows.h>
#include <cstring>
#include <cstdio>
#include <iostream>

using namespace std;

void FindFile(char *Path);

int main(int argc, char *argv[])
{
	char *FileName = argv[1];
	FindFile(FileName);
}

void FindFile(char *Path)
{
	char FindName[0x100];
	char NextDir[0x100];
	WIN32_FIND_DATA FindData;
	BOOL result = FALSE;

	sprintf(FindName, "%s\\*", Path);

	HANDLE hFind = FindFirstFile(FindName, &FindData);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		cout << "Error - Can't find a file : " << GetLastError() << endl;
		return;
	}

	while (TRUE)
	{	
		if(FindData.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY)
		{	/* 
				- 찾은 파일의 속성이 폴더인지 확인.
				- 폴더 속성이 맞고, 이름이 "." 과 ".." 인지 확인.
				- 둘 다 아니라면 폴더 이름을 경로에 추가 후 재귀.
			*/
			if (strcmp(FindData.cFileName, ".") && strcmp(FindData.cFileName,".."))
			{
				sprintf(NextDir, "%s\\%s", Path, FindData.cFileName);
				FindFile(NextDir);
			}
		}
		else
		{	/* 폴더가 아니라면 파일의 경로와 이름을 출력 */
			printf("File name : %s\\%s\n", Path,FindData.cFileName);
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