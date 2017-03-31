#include <Windows.h>
#include <stdio.h>

void TYRename(char *Path, char *FileName);

int main(int argc, char *argv[])
{
	WIN32_FIND_DATA FindFileData;
	char DirName[100];
	char PathName[100];
	char FileName[100];

	printf("[*] Rename _ Kali-KM 2017.03.31\n");
	if(argc != 2)
	{
		printf("\t[-] Usage : %Prog [dir_path]\n");
		return 0;
	}

	strcpy(DirName, argv[1]);
	strcpy(PathName, DirName);
	strcat(DirName, "\\*");
	
	HANDLE hFind = FindFirstFile(DirName, &FindFileData);
	if(!hFind)
	{
		return 0;
	}
	while (1)
	{
		if(!FindNextFile(hFind, &FindFileData))
		{
			break;
		}
		strcpy(FileName, FindFileData.cFileName);
		if(strcmp(FileName, ".") && strcmp(FileName, ".."))
		{
			TYRename(PathName, FileName);	
		}
	}
	return 1;
}


void TYRename(char *Path, char *FileName)
{
	char NewName[150];
	char OldName[150];
	int result = 0;

	strcpy(OldName, Path);
	strcat(OldName, "\\");
	strcat(OldName, FileName);
	
	strcpy(NewName, Path);
	strcat(NewName, "\\");
	strcat(NewName, "[TN]");
	strcat(NewName, FileName);

	result = rename(OldName, NewName);
	printf("NewName : %s, Result : %d\n", NewName, result);
}