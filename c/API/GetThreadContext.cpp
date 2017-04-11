#include <Windows.h>
#include <stdio.h>>

int main()
{
	LPCONTEXT lpContext;
	lpContext->ContextFlags = CONTEXT_FULL;
	/* GetThreadContext 호출 전 반드시 ContextFlags 를 미리 설정 */

	HANDLE hThread = GetCurrentThread();
	BOOL bResult = GetThreadContext(hThread, lpContext);

	if(!bResult)
		return GetLastError();

	return 0;
}
