// DllInjection.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

typedef struct _SHELL_CODE
{
	char szPath[MAX_PATH];
	char szInstruction[0x20];
} SHELL_CODE, *PSHELL_CODE;

int _tmain(int argc, _TCHAR* argv[])
{
	STARTUPINFO SI = {0};
	PROCESS_INFORMATION PI = {0};
	CONTEXT Context = {0};
	LPVOID Buffer = NULL;
	TCHAR ApplicationName[MAX_PATH] = {0};
	TCHAR CurrentDirectory[MAX_PATH] = {0};

	CopyMemory(ApplicationName, argv[1], sizeof(WCHAR) * (lstrlen(argv[1]) + 1));
	CopyMemory(CurrentDirectory, argv[1], sizeof(WCHAR) * (lstrlen(argv[1]) + 1));
	if (!PathRemoveFileSpec(CurrentDirectory))
	{
		_tprintf_s(TEXT("PathRemoveFileSpec failed: %d\n"), GetLastError());
		return -1;
	}

	SI.cb = sizeof(SI);
	if (!CreateProcess(ApplicationName, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, CurrentDirectory, &SI,	&PI))
	{
		_tprintf_s(TEXT("CreateProcess failed: %d\n"), GetLastError());
		return -1;
	}

	Context.ContextFlags = CONTEXT_INTEGER;
	if (!GetThreadContext(PI.hThread, &Context))
	{
		_tprintf_s(TEXT("GetThreadContext failed: %d\n"), GetLastError());
		return -1;
	}

	CHAR szDllName[] = "Injection.dll";
	CHAR szShellCode[] = "\x60\x68\x12\x34\x56\x78\xb8\x12\x34\x56\x78\xff\xd0\x61\xe9\x12\x34\x56\x78";

	Buffer = VirtualAllocEx(PI.hProcess, NULL, sizeof(SHELL_CODE), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (Buffer == NULL)
	{
		_tprintf_s(TEXT("Failed to allocate buffer in the target process\n"));
		return -1;
	}

	*(DWORD*)(szShellCode + 2) = (DWORD)Buffer;
	*(DWORD*)(szShellCode + 7) = (DWORD)LoadLibraryA;
	*(DWORD*)(szShellCode + 15) = Context.Eax - (DWORD)((PUCHAR)Buffer + FIELD_OFFSET(SHELL_CODE, szInstruction) + sizeof(szShellCode) - 1);

	SHELL_CODE ShellCode;
	CopyMemory(((PSHELL_CODE)&ShellCode)->szPath, szDllName, sizeof(szDllName));
	CopyMemory(((PSHELL_CODE)&ShellCode)->szInstruction, szShellCode, sizeof(szShellCode));

	DWORD NumberOfBytesWritten = 0;
	if (!WriteProcessMemory(PI.hProcess, Buffer, &ShellCode, sizeof(SHELL_CODE), &NumberOfBytesWritten))
	{
		_tprintf_s(TEXT("WriteProcessMemory failed: %d\n"), GetLastError());
		return -1;
	}
	
	Context.Eax = (DWORD)(((PSHELL_CODE)Buffer)->szInstruction);

	if (!SetThreadContext(PI.hThread, &Context))
	{
		_tprintf_s(TEXT("SetThreadContext failed: %d\n"), GetLastError());
		return -1;
	}

	ResumeThread(PI.hThread);

	return 0;
}

