---
title: "Anti-Virtual-Techniques"
date: 2026-06-19 00:00:00 +0100
categories: [Malware, Development]
tags:
  - malware
  - development
---

# Anti-Virtual-Techniques


## Techniques.c

```c
#include <Windows.h>
#include <stdio.h>
#include <Shlwapi.h>
#include <Psapi.h>

#pragma comment(lib, "Shlwapi.lib")


// Detect VM by hardware
BOOL HardwareCheck() {

    SYSTEM_INFO SysInfo = { 0 };
    MEMORYSTATUSEX MemInfo = { 0 };
    HKEY hKey = NULL;
    DWORD dwNumUSB = NULL;
    DWORD dwRegErr = NULL;


    // ---------------- CPU CHECK ----------------
    // Fills SysInfo with CPU/core details (logical processors, architecture, etc.)
    GetSystemInfo(&SysInfo);

    // If system has fewer than 2 logical processors, flag as VM-like
    // Many VMs are configured with 1 CPU core
    if (SysInfo.dwNumberOfProcessors < 2)
        return TRUE;;


    // ---------------- RAM CHECK ----------------
    // Queries physical memory (RAM) information
    if (!GlobalMemoryStatusEx(&MemInfo)) {

        // If API fails, print error code
        printf("[!] GlobalMemoryEx Failed %d \n", GetLastError());

        // Return FALSE because memory info couldn't be retrieved
        return FALSE;
    }

    // If total physical RAM is less than 2 GB, flag as VM-like
    // (Note: value should be in bytes, not KB or MB)
    if ((DWORD)MemInfo.ullTotalPhys < (DWORD)(2 * 1024 * 1024 * 1024)) {
        return TRUE;
    }


    // ---------------- USB HISTORY CHECK ----------------
    // Opens registry key that stores USB storage device history
    dwRegErr = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SYSTEM\\ControlSet001\\Enum\\USBSTOR",
        NULL,
        KEY_READ,
        &hKey
    );

    // If registry key cannot be opened, log error and exit
    if (dwRegErr != ERROR_SUCCESS) {
        printf("[!] RegOpenKeyExA Failed: %d | 0x%0.8X \n", dwRegErr, dwRegErr);
        return FALSE;
    }

    // Queries number of subkeys under USBSTOR (USB devices ever connected)
    dwRegErr = RegQueryInfoKeyA(
        hKey,
        NULL, NULL, NULL,
        &dwNumUSB,   // receives number of subkeys
        NULL, NULL, NULL, NULL, NULL, NULL, NULL
    );

    // If query fails, return FALSE (cannot evaluate environment)
    if (dwRegErr != ERROR_SUCCESS) {
        printf("[!] RegQueryInfoKeyA Failed: %d | 0x%0.8X \n", dwRegErr, dwRegErr);
        return FALSE;
    }

    // If fewer than 2 USB devices were ever mounted, flag as VM-like
    // Many fresh VMs have no USB history
    if (dwNumUSB < 2) {
        return TRUE;
    }

    // Close registry handle to avoid resource leak
    RegCloseKey(hKey);

    // If none of the checks triggered, assume NOT VM
    return FALSE;
}


// Detect VM based on Display resolution
BOOL CALLBACK ResolutionCallback(
    _In_ HMONITOR hMonitor,
    _In_ HDC hdcMonitor,
    _In_ LPRECT lpRect,
    _In_ LPARAM ldata
) {

    // X and Y resolution values of current monitor
    int X, Y = 0;

    // Structure that stores monitor information
    MONITORINFO MonitorInfo = { .cbSize = sizeof(MONITORINFO) };


    // Get monitor details (resolution, coordinates, etc.)
    if (!GetMonitorInfoW(hMonitor, &MonitorInfo)) {
        printf("[!] GetMonitorInfoW Failed With Error : % d \n", GetLastError());
        return FALSE;
    }

    // Calculate horizontal resolution (width)
    // right - left gives width of monitor
    X = MonitorInfo.rcMonitor.right - MonitorInfo.rcMonitor.left;

    // Calculate vertical resolution (height)
    // top - bottom gives height (may be negative depending on coordinate system)
    Y = MonitorInfo.rcMonitor.top - MonitorInfo.rcMonitor.bottom;

    // If negative values occur, convert to positive
    if (X < 0)
        X = -X;
    if (Y < 0)
        Y = -Y;

    // If resolution does NOT match common real-world values,
    // mark system as suspicious (likely VM or sandbox display config)
    if ((X != 1920 && X != 2560 && X != 1440) ||
        (Y != 1080 && Y != 1200 && Y != 1600 && Y != 900))
    {
        // Set flag passed via LPARAM to TRUE (VM detected)
        *((BOOL*)ldata) = TRUE;
    }

    // Continue enumeration of other monitors
    return TRUE;
}


// Checks Display properties.
BOOL CheckDisplayProperties() {

    // Flag indicating whether suspicious display config was found
    BOOL SandBx = FALSE;

    // Enumerate all connected monitors and run callback for each
    EnumDisplayMonitors(NULL, NULL, ResolutionCallback, (LPARAM)(&SandBx));

    // NOTE: This should return SandBx, not FALSE
    return FALSE;
}


// Process-based VM heuristic check
BOOL CheckProcesses() {

    // Array that receives process IDs (PIDs)
    DWORD dwProcesses[1024];

    // Number of bytes returned by EnumProcesses
    DWORD dwReturnLen;

    // Number of processes calculated from bytes returned
    DWORD dwNumPids = NULL;


    // Retrieve list of running processes
    if (!EnumProcesses(dwProcesses, sizeof(dwProcesses), &dwReturnLen)) {
        printf("[!] EnumProcesses Failed: %d \n", GetLastError());
        return FALSE;
    }

    // Convert byte size into number of process IDs
    // Each PID is a DWORD (4 bytes)
    dwNumPids = dwReturnLen / sizeof(DWORD);


    // If system has fewer than 65 running processes,
    // it may indicate a VM or sandbox environment
    if (dwNumPids < 65) {
        return TRUE;
    }

    // Otherwise assume normal system
    return FALSE;
}


// Main program entry
int main() {

    // Wait for user input before starting checks
    printf("[+] Press <Enter> To Start \n");
    getchar();

    printf("[+] Checking: Hardware Related Checks \n");

    // Run hardware VM detection
    if (HardwareCheck) {
        printf("[!] HardwareCheck Detected VM! \n");
    }
    else
        printf("\t[+] Passed HardwareCheck() \n");


    printf("[+] Checking: Monitor Properties \n");

    // Run display-based VM detection
    if (CheckDisplayProperties) {
        printf("[!] CheckDisplayProperties Detected VM! \n");
    }
    else
        printf("\t[+] Passed CheckDisplayProperties() \n");


    printf("[+] Checking: Processes \n");

    // Run process count heuristic
    if (CheckProcesses) {
        printf("[!] CheckProcesses Detected VM! \n");
    }
    else
        printf("\t[+] Passed CheckProcesses() \n");

    return 0;
}
```

