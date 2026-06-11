---
title: "StaticAPI-Hashing"
date: 2026-06-11 00:00:00 +0100
categories: [Malware, Development]
tags:
  - malware
  - code
---

# StaticAPI-Hashing

**Folder:** `StaticAPI-Hashing`

## apihashing.c

```c
#include <Windows.h>        // Core Windows API definitions (HMODULE, FARPROC, etc.)
#include <stdio.h>          // For printf() and getchar()
#include <winternl.h>       // Contains PEB, PPEB, UNICODE_STRING, LIST_ENTRY structures

// =============================================
// Custom LDR_DATA_TABLE_ENTRY Structure
// Microsoft hides some fields in winternl.h, so we define our own
// to access BaseDllName reliably.
// =============================================
typedef struct _MY_LDR_DATA_TABLE_ENTRY
{
    PVOID Reserved1[2];                     
    LIST_ENTRY InMemoryOrderLinks;          // Linked list pointer for walking modules
    PVOID Reserved2[2];                     
    PVOID DllBase;                          // Base address of the DLL in memory (what we need)
    PVOID Reserved3[2];                     
    UNICODE_STRING FullDllName;             // Full path of DLL (e.g. C:\Windows\System32\user32.dll)
    UNICODE_STRING BaseDllName;             // Just the filename (e.g. USER32.DLL) - best for hashing
    BYTE Reserved4[8];                      
    PVOID Reserved5[3];                    
    union
    {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} MY_LDR_DATA_TABLE_ENTRY, * PMY_LDR_DATA_TABLE_ENTRY;


// =============================================
// Hashing Function: Jenkins One-at-a-Time (32-bit)
// =============================================
#define SEED 7
#define HashA(API) HashingJenkins32BitA((PCHAR)API)

// This function computes a hash for a given string.
// We use it for both DLL names and function names.
UINT32 HashingJenkins32BitA(_In_ PCHAR String)
{
    if (!String) return 0;                  // Safety check: prevent crash on NULL

    SIZE_T Index = 0;                       // Current position in string
    UINT32 Hash = 0;                        // Accumulated hash value
    SIZE_T strLength = lstrlenA(String);    // Get string length using Windows API

    while (Index != strLength)              // Loop through each character
    {
        Hash += String[Index++];            // Add current character to hash
        Hash += Hash << SEED;               
        Hash += Hash >> 6;                  
    }

    return Hash;                            // Return hash
}


// =============================================
// Resolve Function Address by Hash (Manual Export Table Parsing)
// =============================================
FARPROC GetProcessAddrHash(_In_ HMODULE hModule, _In_ DWORD dwApiHash)
{
    if (!hModule || !dwApiHash)             // Basic validation
        return NULL;

    PBYTE pBase = (PBYTE)hModule;           // Treat DLL base as byte pointer for RVA calculations

    // --- Parse PE Headers ---
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)  // Check 'MZ' signature
        return NULL;

    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(pBase + pDosHdr->e_lfanew);  // Jump to NT header

    // Get Export Directory RVA
    IMAGE_DATA_DIRECTORY ExportDir = pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (ExportDir.VirtualAddress == 0)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ExportDir.VirtualAddress);

    // Three important arrays in export directory:
    PDWORD NameArray = (PDWORD)(pBase + pExportDir->AddressOfNames);        // Function names
    PDWORD AddressArray = (PDWORD)(pBase + pExportDir->AddressOfFunctions);    // Function RVAs
    PWORD  OrdinalArray = (PWORD)(pBase + pExportDir->AddressOfNameOrdinals);  // Name-to-Ordinal mapping

    // Loop through all named exported functions
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++)
    {
        CHAR* pFuncName = (CHAR*)(pBase + NameArray[i]);   // Get function name string

        if (dwApiHash == HashA(pFuncName))                 // Compare hash
        {
            DWORD funcRVA = AddressArray[OrdinalArray[i]]; // Get relative virtual address
            return (FARPROC)(pBase + funcRVA);             // Return absolute address
        }
    }

    return NULL;                            // Function not found
}


// =============================================
// Resolve Module (DLL) by Hash from PEB
// =============================================
HMODULE GetModuleHandleHash(_In_ DWORD dwModuleHash)
{
    if (!dwModuleHash)
        return NULL;

    // Get Process Environment Block (PEB) using GS register (x64 only)
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (!pPeb || !pPeb->Ldr)
        return NULL;

    // Start walking the InMemoryOrderModuleList
    PLIST_ENTRY pHead = &pPeb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY pEntry = pHead->Flink;

    while (pEntry != pHead)                 // Loop until we return to head (circular list)
    {
        // Get our custom structure using CONTAINING_RECORD macro
        PMY_LDR_DATA_TABLE_ENTRY pDte = CONTAINING_RECORD(pEntry, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (pDte->DllBase)                  // Skip entries without base address
        {
            UNICODE_STRING* pName = &pDte->BaseDllName;   // Use BaseDllName (clean filename)

            if (pName->Length > 0 && pName->Buffer)
            {
                CHAR UpperCaseDLL[MAX_PATH] = { 0 };      // Buffer for converted name
                SIZE_T i = 0;

                // Convert UNICODE (WCHAR) to ANSI (CHAR) + uppercase
                for (i = 0; i < (pName->Length / sizeof(WCHAR)) && i < MAX_PATH - 1; i++)
                {
                    UpperCaseDLL[i] = (CHAR)toupper((UCHAR)pName->Buffer[i]);
                }
                UpperCaseDLL[i] = '\0';


                if (HashA(UpperCaseDLL) == dwModuleHash)  // Hash match
                {
                    return (HMODULE)pDte->DllBase;         // Return DLL base address
                }
            }
        }

        pEntry = pEntry->Flink;             // Move to next module in list
    }

    return NULL;                            // Module not found
}


// =============================================
// Function Typedef + Precomputed Hashes
// =============================================
typedef int (WINAPI* fnMessageBoxA)(
    HWND   hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT   uType
    );

// These hashes were pre-calculated from uppercase strings
#define USER32DLL_HASH      0xA48F48AC      // Hash("USER32.DLL")
#define MESSAGEBOXA_HASH    0xD1CC12B7      // Hash("MessageBoxA")


int main()
{
    // Print hashes for verification
    printf("[i] Hash Of \"USER32.DLL\"  Is : 0x%08X\n", HashA("USER32.DLL"));
    printf("[i] Hash Of \"MessageBoxA\" Is : 0x%08X\n\n", HashA("MessageBoxA"));

    // Force load user32.dll into the process
    LoadLibraryA("USER32.DLL");

    // Resolve module handle using hash only
    HMODULE hUser32 = GetModuleHandleHash(USER32DLL_HASH);
    if (!hUser32)
    {
        printf("[!] GetModuleHandleHash failed - Could not find user32.dll\n");
        return -1;
    }

    printf("[+] Found user32.dll at: 0x%p\n", hUser32);

    // Resolve function address using hash only
    fnMessageBoxA pMessageBoxA = (fnMessageBoxA)GetProcessAddrHash(hUser32, MESSAGEBOXA_HASH);
    if (!pMessageBoxA)
    {
        printf("[!] Failed to resolve MessageBoxA by hash\n");
        return -1;
    }

    printf("[+] Resolved MessageBoxA at: 0x%p\n\n", pMessageBoxA);

    // Call the function
    pMessageBoxA(NULL, "Malware API Hashing Test", "N0xshell", MB_OK | MB_ICONEXCLAMATION);

    printf("[+] Success! Press <Enter> to exit...\n");
    getchar();

    return 0;
}
```

---

