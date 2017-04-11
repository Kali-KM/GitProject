#include <Windows.h>
#include <stdio.h>

int main()
{
	HMODULE hModule;

	hModule = GetModuleHandle("test.dll");
	if(!hModule)
	{
		GetLastError();
		return 0;
	}

	return 1;
}
