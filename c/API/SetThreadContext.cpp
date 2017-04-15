#include <stdio.h>
#include <Windows.h>

ULONG Bypass();

int main()
{
	CONTEXT Context;
	Context.ContextFlags = CONTEXT_FULL;
	
	HANDLE hThread = GetCurrentThread();
	BOOL bResult = GetThreadContext(hThread, &Context);
	
	if(!bResult)
		return GetLastError();
	
	Context.Eip = (ULONG)(PLONG)Bypass;
	bResult = SetThreadContext(hThread, &Context);
	if(!bResult)
		return GetLastError();
	
	return 0;
}

ULONG Bypass()
{
	printf("bypass Routine\n");
	return 0;
}
