#include <Windows.h>
#include <iostream>


using namespace std;

BOOL ShellExeRoutine();
BOOL CreateSuspendRoutine();

int main(int argc, char *argv[])
{
	int Time;
	char *FileName;

	STARTUPINFO lpStartupInfo; 
	PROCESS_INFORMATION lpProcessInformation;
	BOOL Flag;
	HANDLE hThread;
	HANDLE hProc;
	DWORD result=0;
	DWORD dwThreadId;
	DWORD dwProcId;

	cout << "\n[*] Process Suspend Tool v1.0 - 2016.12.06" << endl;

	if(argc != 3)
	{
		cout << "[-] Usage : PsSuspend.exe file time\n" << endl;
		return 0;
	}
	
	memset(&lpStartupInfo, 0, sizeof(lpStartupInfo));
	memset(&lpProcessInformation, 0, sizeof(lpProcessInformation));

	Time = atoi(argv[2]);
	FileName = argv[1];
	
	cout << "[*] Target File Name : " << FileName << ", Running Time : " << Time << " millisecond\n" << endl;

	Flag = CreateProcess(0, FileName, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &lpStartupInfo, &lpProcessInformation);
	if(!Flag)
	{
		cout << "[-] Error : Can't execute the File, ErrorCode : 0x" << hex << GetLastError() << endl;
		return 0;
	}

	hThread = lpProcessInformation.hThread;
	hProc = lpProcessInformation.hProcess;
	dwThreadId = lpProcessInformation.dwThreadId;
	dwProcId = lpProcessInformation.dwProcessId;

	result = ResumeThread(hThread);
	if(result)
	{
		cout << "[+] Start the Process. PID : " <<dwProcId<<" TID : "<<dwThreadId << endl;
	}
	else
	{
		cout << "[-] Error : Can't resume the Process, ErrorCode : " << GetLastError() << endl;
		return 0;
	}
	Sleep(Time);
	result = SuspendThread(hThread);
	if(!result)
		cout << "[+] Successed in Suspending!\n\t if you want to resume the thread, type any key." << endl; 
	system("pause");
	ResumeThread(hThread);
	return 1;
}
