---
title: "IAT-Camoflage"
date: 2026-06-20 00:00:00 +0100
categories: [Malware, Development]
tags:
  - malware
  - development
---

# IAT-Camoflage


## iat-camoflage.c

```c
/*
	- Its important to make the malware appear to be normal so to instead hiding WinAPI's, its more effective to create fake imported functions.
	- This can be done by calling the WinAPI with NULL parameters.
*/

#include <Windows.h>
#include <stdio.h>

// Generate a compile-time-derived seed based on __TIME__
int RandomCompileTimeSeed(void)
{
	return '0' * -40271 +
		__TIME__[7] * 1 +			// seconds ones
		__TIME__[6] * 10 +			// seconds tens
		__TIME__[4] * 60 +			// minutes ones
		__TIME__[3] * 600 +			// minutes tens
		__TIME__[1] * 3600 +		// hours ones
		__TIME__[0] * 36000;		// hours tens
}

// Dummy helper intended to discourage compiler optimization.
PVOID HelperFunc(_Out_ PVOID* ppAddr) {
	PVOID pAddr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);
	
	if (!pAddr)
		return NULL;

	// Store a compile-time-derived value (0-254) in the buffer
	*(int*)pAddr = RandomCompileTimeSeed() % 0xFF;

	// Return the allocated address to the caller
	*ppAddr = pAddr;

	return pAddr;

}

// Fill important the fake WinAPI to cameflage the IAT
VOID IATCamo() {
	PVOID pAddr = NULL;
	
	int* a = (int*)HelperFunc(&pAddr);

	// The generated value is always in the range [0, 254], making this condition impossible
	if (*a > 350) {
		unsigned __int64 i = MessageBoxA(NULL, NULL, NULL, NULL);
		i = GetLastError();
		i = RegisterClassW(NULL);
		i = IsWindowVisible(NULL);
		i = ConvertDefaultLocale(NULL);
		i = MultiByteToWideChar(NULL, NULL, NULL, NULL, NULL, NULL);
		i = IsDialogMessageW(NULL, NULL);
	}

	// Cleaning up
	HeapFree(GetProcessHeap(), 0, pAddr);
}

int main(void) {
	IATCamo();

	return 0;
}

```

