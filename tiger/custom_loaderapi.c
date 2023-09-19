#include <stdio.h>

#include "custom_loaderapi.h"
#include "string_hashing.h"
#include "structs.h"

#define ERR -0x1
#define SUCCESS 0x0

#define STRUCTS

HMODULE Custom_GetModuleHandle(DWORD64 ModuleHash) {
	// Obtain the PEB offset
#ifdef _WIN64
	PPEB			pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB			pPeb = (PEB*)(__readfsdword(0x30));
#endif

	// PEB LDR DATA to be able to retrieve the module data
	PPEB_LDR_DATA LdrData = pPeb->LdrData;
	// Retrieve all memory-loaded Module entries 
	PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)LdrData->InMemoryOrderModuleList.Flink;

	// Go through all loaded modules and verify
	while (LdrDataTableEntry) {
		if (LdrDataTableEntry->FullDllName.Length != NULL) {

			if (CRC32B((PBYTE)LdrDataTableEntry->FullDllName.Buffer) == ModuleHash) {
				//printf("\t[!] FOUND: \"%ws\" ( %#p ) \n", LdrDataTableEntry->FullDllName.Buffer, (HMODULE)(LdrDataTableEntry->InInitializationOrderLinks.Flink));

#ifdef STRUCTS
				return (HMODULE)(LdrDataTableEntry->InInitializationOrderLinks.Flink);
#else
				return (HMODULE)LdrDataTableEntry->Reserved2[0];
#endif
			}
		}
		else { break; }

		LdrDataTableEntry = *(PLDR_DATA_TABLE_ENTRY*)(LdrDataTableEntry);
	}

    return NULL;

}

FARPROC Custom_GetProcAddress(HMODULE hModule, DWORD64 ApiHashName) {

	FARPROC pFunctionAddress = NULL;
	HMODULE hModuleBase = hModule;

	if (hModuleBase == NULL) {
		return ERR;
	}

	PIMAGE_DOS_HEADER imgDosHdr = (PIMAGE_DOS_HEADER)hModuleBase;
	PIMAGE_NT_HEADERS imgNtHdr = (PIMAGE_NT_HEADERS)((unsigned char*)imgDosHdr + imgDosHdr->e_lfanew);
	PIMAGE_OPTIONAL_HEADER imgOptHdr = (PIMAGE_OPTIONAL_HEADER)&imgNtHdr->OptionalHeader;
	PIMAGE_DATA_DIRECTORY imgDataDir = &imgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY imgExportDir = (PIMAGE_EXPORT_DIRECTORY)((unsigned char*)hModuleBase + imgDataDir->VirtualAddress);

	DWORD numberOfNames = imgExportDir->NumberOfNames;
	PDWORD AddressOfFunctions = (PDWORD)((unsigned char*)hModuleBase + imgExportDir->AddressOfFunctions);
	PWORD AddressOfNameOrdinals = (PWORD)((unsigned char*)hModuleBase + imgExportDir->AddressOfNameOrdinals);
	PDWORD AddressOfNames = (PDWORD)((unsigned char*)hModuleBase + imgExportDir->AddressOfNames);

	DWORD index = 0;

	for (index; index < numberOfNames; index++) {
		char* FunctionName = (char*)((unsigned char*)hModuleBase + AddressOfNames[index]);
		
		if (CRC32B(FunctionName) == ApiHashName) {
			WORD ordinal = AddressOfNameOrdinals[index];
			PDWORD targetFunctionAddr = (PDWORD)((unsigned char*)hModuleBase + AddressOfFunctions[index]);
			pFunctionAddress = targetFunctionAddr;
			//printf("\t + FOUND:  %s -> %p\n", FunctionName, pFunctionAddress);
		}
	}

	if (pFunctionAddress != NULL) {
		return pFunctionAddress;
	} 

	return NULL;
}