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

			// Verify the module name matches the one of the hash
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

		// Continue the loop if we didnt find the module we're looking for
		LdrDataTableEntry = *(PLDR_DATA_TABLE_ENTRY*)(LdrDataTableEntry);
	}

    return NULL;

}

//
// Does NOT work with forwarded functions
// so if a function is forwarded, it will need manual debugging
// to find where the function is actually located 
//
FARPROC Custom_GetProcAddress(HMODULE hModule, DWORD64 ApiHashName) {

	// Declare storing variables
	FARPROC pFunctionAddress = NULL;
	HMODULE hModuleBase = hModule;

	if (hModuleBase == NULL) {
		return ERR;
	}

	// Obtain image dos headers
	PIMAGE_DOS_HEADER imgDosHdr = (PIMAGE_DOS_HEADER)hModuleBase;

	// Obtain NT headers
	PIMAGE_NT_HEADERS imgNtHdr = (PIMAGE_NT_HEADERS)((unsigned char*)imgDosHdr + imgDosHdr->e_lfanew);

	// Obtain Optional headers
	PIMAGE_OPTIONAL_HEADER imgOptHdr = (PIMAGE_OPTIONAL_HEADER)&imgNtHdr->OptionalHeader;

	// From optional headers, get the Data Directory's Exports
	PIMAGE_DATA_DIRECTORY imgDataDir = &imgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	// Obtain the export directory and retrieve the address of it
	PIMAGE_EXPORT_DIRECTORY imgExportDir = (PIMAGE_EXPORT_DIRECTORY)((unsigned char*)hModuleBase + imgDataDir->VirtualAddress);

	DWORD	numberOfNames			= imgExportDir->NumberOfNames; 
	PDWORD	AddressOfFunctions		= (PDWORD)((unsigned char*)hModuleBase + imgExportDir->AddressOfFunctions);
	PWORD	AddressOfNameOrdinals	= (PWORD)((unsigned char*)hModuleBase + imgExportDir->AddressOfNameOrdinals);
	PDWORD	AddressOfNames			= (PDWORD)((unsigned char*)hModuleBase + imgExportDir->AddressOfNames);

	// Loop through all exported function
	DWORD index = 0;
	for (index; index < numberOfNames; index++) {
		char* FunctionName = (char*)((unsigned char*)hModuleBase + AddressOfNames[index]);
		
		// Match the hash with the function we're looking for
		if (CRC32B(FunctionName) == ApiHashName) {
			WORD ordinal = AddressOfNameOrdinals[index];
			PDWORD targetFunctionAddr = (PDWORD)((unsigned char*)hModuleBase + AddressOfFunctions[index]);
			pFunctionAddress = targetFunctionAddr;
		}
	}

	if (pFunctionAddress != NULL) {
		return pFunctionAddress;
	} 

	return NULL;
}