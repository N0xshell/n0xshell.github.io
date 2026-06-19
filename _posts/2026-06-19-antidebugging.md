---
title: "AntiDebugging"
date: 2026-06-19 00:00:00 +0100
categories: [Malware, Development]
tags:
  - malware
  - development
---

# AntiDebugging


## Techniques.c

```c
#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include "structs.h"

/*
	IsdebuggerPresent() API, returns TRUE if a debugger is being attached to the calling process
*/


BOOL IsDebuggerPresent1() {

	// Get address PEB (GSx60 is PEB pointer)
	PPEB pPeb = (PEB*)(__readgsqword(0x60));

	if (pPeb->BeingDebugged == 1)
		return TRUE;
	return FALSE;

}

/*
	NtQueryInformationProcess detects debugging via ProcessDebugPort & ProcessDebugObjectHandle
*/

BOOL NtQInfoProcess() {

	NTSTATUS                      STATUS = NULL;
	fnNtQueryInformationProcess   pNtQueryInformationProcess = NULL;
	DWORD64                       dwIsDebuggerPresent = NULL;
	DWORD64                       hProcessDebugObject = NULL;

	// Get Memory Address NtQueryInformationProcess from ntdll.dll
	pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("NTDLL.DLL")), "NtQueryInformationProcess");


	// ProcessDebugPort Method
	STATUS = pNtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &dwIsDebuggerPresent, sizeof(DWORD64), NULL);
	if (STATUS != 0x0) {
		printf("[!] NtQueryInformationProcess Failed: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	if (dwIsDebuggerPresent) {
		printf("[+] Debugger Detected!\n");
		return TRUE;
	}


	// ProcessDebugObjectHandle Method
	STATUS = pNtQueryInformationProcess(GetCurrentProcess(), ProcessDebugObjectHandle, &hProcessDebugObject, sizeof(DWORD64), NULL);
	if (STATUS != 0x0 && STATUS != 0xC0000353) {
		printf("[!] NtQueryInformationProcess Failed: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	if (hProcessDebugObject)
		return TRUE;

	return FALSE;
}

/*
	Hardware breakpoint detection, checks if the registers dr0-3 are 0
*/

BOOL HWBP_Check() {
	CONTEXT Ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

	// Get current threadcontext
	if (!GetThreadContext(GetCurrentThread(), &Ctx)) {
		printf("[!] GetThreadContext Failed %d \n", GetLastError());
		return FALSE;
	}

	// Check Hardware Breakpoint by checking registers aren't set to 0
	if (Ctx.Dr0 || Ctx.Dr1 || Ctx.Dr2 || Ctx.Dr3) {
		printf("[+] Debugger Detected ! \n");
		return TRUE;
	}

	return FALSE;
}


/*
	Detect Debuggers Via Name (Array)
*/

WCHAR* g_BlockSoftware[5] = {
	L"x64dbg.exe",
	L"x32dbg.exe",
	L"binaryninja.exe",
	L"VsDebugConsole.exe",
	L"ida.exe"
};

BOOL BlockSoftware() {

	HANDLE hSnapshot = NULL;
	PROCESSENTRY32W		ProcEntry = { .dwSize = sizeof(PROCESSENTRY32W) };
	BOOL				bSTATE = FALSE;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolHelp32Snapshot Failed %d \n", GetLastError());
		goto _End;
	}

	if (!Process32FirstW(hSnapshot, &ProcEntry)) {
		printf("[!] Process32FirstW Failed %d \n", GetLastError());
		goto _End;
	}

	do {
		for (int i = 0; i < 5; i++) {
			if (wcscmp(ProcEntry.szExeFile, g_BlockSoftware[i]) == 0) {
				wprintf(L"\t[+] Found \"%ls\" Of Pid %d \n", ProcEntry.szExeFile, ProcEntry.th32ProcessID);
				bSTATE = TRUE;
				break;
			}
		}

		if (bSTATE)
			break;
	} while (Process32NextW(hSnapshot, &ProcEntry));

_End:
	if (!hSnapshot)
		CloseHandle(hSnapshot);
	return bSTATE;
}

/*
	Detect debugging by evaluating time started and current time, if to long its being debugged GetTickCount64()
*/

BOOL TimeCheck1() {
	DWORD dwTime1, dwTime2 = 0;

	dwTime1 = GetTickCount64();
	dwTime2 = GetTickCount64();

	if ((dwTime2 - dwTime1) > 70)
		return TRUE;

	return FALSE;
}

/*
	Send message to debugger is thats succeeds debugging is happening
*/

BOOL SendMessageDbg() {

	// Make sure value is non 0 before execution
	SetLastError(1);
	OutputDebugStringW(L"N0xshell");

	if (GetLastError())
		return TRUE;
	return FALSE;
}

int main() {

	printf("[+] Press <Enter> To Start Anti Analysis Techniques! \n");
	getchar();

	// Method: IsDebuggerPresent
	printf("[+] Running: IsDebuggerPresent1 \n");
	if (IsDebuggerPresent1()) {
		printf("[!] Debugger Detected [IsDebuggerPresent1] \n");
		exit(1);
	}
	else
		printf("\t[+] IsDebuggerPresent1 Done! \n");

	// Method: NtQueryInformationProcess
	printf("[+] Running: NtQInfoProcess \n");
	if (NtQInfoProcess()) {
		printf("[!] Debugger Detected [NtQInfoProcess] \n");
		exit(1);
	}
	else
		printf("\t[+] NtQInfoProcess Done! \n");

	// Method: HWBP_Check (Thread Register check)
	printf("[+] Running: HWBP_Check \n");
	if (HWBP_Check()) {
		printf("[!] Debugger Detected [HWBP_Check] \n");
		exit(1);
	}
	else
		printf("\t[+] HWBP_Check Done \n");

	// Method: BlockSoftware Check
	printf("[+] Running: BlockSoftware \n");
	if (BlockSoftware()) {
		printf("[!] Debugger Detected [BlockSoftware] \n");
		exit(1);
	}
	else
		printf("\t[+] BlockSoftware Done \n");

	// Method: TimeCheck
	printf("[+] Running: TimeCheck1 \n");
	if (TimeCheck1()) {
		printf("[!] Debugger Detected [TimeCheck1] \n");
		exit(1);
	}
	else
		printf("\t[+] TimeCheck1 Done \n");


	printf("[+] Press <Enter> To Exit! \n");
	getchar();
	return 0;
}
```

