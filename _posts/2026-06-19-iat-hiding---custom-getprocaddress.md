---
title: "IAT Hiding - Custom GetProcAddress"
date: 2026-06-19 00:00:00 +0100
categories: [Malware, Development]
tags:
  - malware
  - development
---

# IAT Hiding - Custom GetProcAddress


## Custom-GetProcAddress.c

```c
#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

FARPROC CustomGetProcAddress(_In_ HMODULE hModule, _In_ LPCSTR lpApiName) {
	PBYTE pBase = (PBYTE)hModule;

	// Getting DOS Header
	PIMAGE_DOS_HEADER pImgheader = (PIMAGE_DOS_HEADER)pBase;
	if (pImgheader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	// Gettting NT Header
	PIMAGE_NT_HEADERS pImgNTheader = (PIMAGE_NT_HEADERS)(pBase + pImgheader->e_lfanew);
	if (pImgNTheader->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// Getting Optional Header
	PIMAGE_OPTIONAL_HEADER pImgOptheader = &pImgNTheader->OptionalHeader;
	if (!pImgOptheader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
		return NULL;

	// Getting Image Export Table
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + pImgOptheader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// Getting function's array pointers
	PDWORD FuncNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);

	// Getting functions address array pointer
	PDWORD FuncAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);

	// Getting ordinal array pointer
	PWORD FuncOrdinalArray = (PDWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

	// Find correct function
	for (DWORD i = 0; i < pImgExportDir->NumberOfNames; i++) {
		// Getting function name
		CHAR* pFuncName = (CHAR*)(pBase + FuncNameArray[i]);

		// Getting Address of function through ordinal
		PVOID pFuncAddress = (PVOID)(pBase + FuncAddressArray[FuncOrdinalArray[i]]);

		// compare provided functionname with the export
		if (strcmp(lpApiName, pFuncName) == 0) {
			printf("[ %0.4d ] NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %d \n", i, pFuncName, FuncAddressArray, FuncOrdinalArray[i]);
			return pFuncAddress;
		}
	}

	return NULL;
}

int main() {
	printf("[+] Original GetProcAddress 0x%p \n", GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtAllocateVirtualMemory"));
	printf("[+] GetProcAddress Replacement : 0x%p \n", CustomGetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtAllocateVirtualMemory"));

	return 0;
}
```

