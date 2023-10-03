#include "indirect_syscall.h"
#include "debug/debug.h"

#define RANGE 500
#define UP -32
#define DOWN 32

VOID SetSSN(DWORD dwSSN, PVOID pRandSyscallAddress);
LONG RunSyscall();

NTDLL_STRUCT _G_NtdllConf;

BOOL ObtainSyscall(IN DWORD64 dwSysHash, OUT PNTSYSCALL pNtSys) {

	// Initialise the NTDLL structure
	if (!_G_NtdllConf.uModule) {
		if (!InitNtdllStruct()) {
			return FALSE;
		}
		//PRINTA("[+] Initialised the NTDLL structure !\n");
	}
	//PRINTA("[+] Got base address of NTDLL -> %#p\n", (PVOID)_G_NtdllConf.uModule);
	
	// if no hash value was specified
	if (dwSysHash != NULL) {
		pNtSys->dwSyscallHash = dwSysHash;
		//PRINTA("[!] dwSyscallHash -> %llx\n", pNtSys->dwSyscallHash);
	}
	else {
		return FALSE;
	}

	size_t index = 0;
	for (index; index < _G_NtdllConf.dwNumberOfNames; index++) {

		PCHAR pFunctionName = (PCHAR)(_G_NtdllConf.uModule + _G_NtdllConf.pdwArrayOfNames[index]);
		PVOID pFunctionAddr = (PVOID)(_G_NtdllConf.uModule + _G_NtdllConf.pdwArrayOfAddresses[_G_NtdllConf.pwArrayOfOrdinals[index]]);
		/*
		PRINTA("[*] SYSCALL FUNCTION INFO -> \n\
\t\t- FUNCTION NAME ->		%s\n\
\t\t- FUNCTION ADDRESS ->		%#p\n", pFunctionName, pFunctionAddr);
		//getchar();
		*/
		if (CRC32B(pFunctionName) == dwSysHash) {

			// Save the matched function address
			pNtSys->pSyscallAddress = pFunctionAddr;

			if (*((PBYTE)pFunctionAddr) == 0x4C
				&& *((PBYTE)pFunctionAddr + 1) == 0x8B
				&& *((PBYTE)pFunctionAddr + 2) == 0xD1
				&& *((PBYTE)pFunctionAddr + 3) == 0xB8
				&& *((PBYTE)pFunctionAddr + 6) == 0x00
				&& *((PBYTE)pFunctionAddr + 7) == 0x00) {

				BYTE high = *((PBYTE)pFunctionAddr + 5);
				BYTE low = *((PBYTE)pFunctionAddr + 4);
				pNtSys->dwSSN = (high << 8) | low;
				break; // break for-loop [i]
			}

			// if hooked - scenario 1
			if (*((PBYTE)pFunctionAddr) == 0xE9) {

				for (WORD idx = 1; idx <= RANGE; idx++) {
					// check neighboring syscall down
					if (*((PBYTE)pFunctionAddr + idx * DOWN) == 0x4C
						&& *((PBYTE)pFunctionAddr + 1 + idx * DOWN) == 0x8B
						&& *((PBYTE)pFunctionAddr + 2 + idx * DOWN) == 0xD1
						&& *((PBYTE)pFunctionAddr + 3 + idx * DOWN) == 0xB8
						&& *((PBYTE)pFunctionAddr + 6 + idx * DOWN) == 0x00
						&& *((PBYTE)pFunctionAddr + 7 + idx * DOWN) == 0x00) {

						BYTE high = *((PBYTE)pFunctionAddr + 5 + idx * DOWN);
						BYTE low = *((PBYTE)pFunctionAddr + 4 + idx * DOWN);
						pNtSys->dwSSN = (high << 8) | low - idx;
						break; // break for-loop [idx]
					}
					// check neighboring syscall up
					if (*((PBYTE)pFunctionAddr + idx * UP) == 0x4C
						&& *((PBYTE)pFunctionAddr + 1 + idx * UP) == 0x8B
						&& *((PBYTE)pFunctionAddr + 2 + idx * UP) == 0xD1
						&& *((PBYTE)pFunctionAddr + 3 + idx * UP) == 0xB8
						&& *((PBYTE)pFunctionAddr + 6 + idx * UP) == 0x00
						&& *((PBYTE)pFunctionAddr + 7 + idx * UP) == 0x00) {

						BYTE high = *((PBYTE)pFunctionAddr + 5 + idx * UP);
						BYTE low = *((PBYTE)pFunctionAddr + 4 + idx * UP);
						pNtSys->dwSSN = (high << 8) | low + idx;
						break; // break for-loop [idx]
					}
				}
			}

			// if hooked - scenario 2
			if (*((PBYTE)pFunctionAddr + 3) == 0xE9) {

				for (WORD idx = 1; idx <= RANGE; idx++) {
					// check neighboring syscall down
					if (*((PBYTE)pFunctionAddr + idx * DOWN) == 0x4C
						&& *((PBYTE)pFunctionAddr + 1 + idx * DOWN) == 0x8B
						&& *((PBYTE)pFunctionAddr + 2 + idx * DOWN) == 0xD1
						&& *((PBYTE)pFunctionAddr + 3 + idx * DOWN) == 0xB8
						&& *((PBYTE)pFunctionAddr + 6 + idx * DOWN) == 0x00
						&& *((PBYTE)pFunctionAddr + 7 + idx * DOWN) == 0x00) {

						BYTE high = *((PBYTE)pFunctionAddr + 5 + idx * DOWN);
						BYTE low = *((PBYTE)pFunctionAddr + 4 + idx * DOWN);
						pNtSys->dwSSN = (high << 8) | low - idx;
						break; // break for-loop [idx]
					}
					// check neighboring syscall up
					if (*((PBYTE)pFunctionAddr + idx * UP) == 0x4C
						&& *((PBYTE)pFunctionAddr + 1 + idx * UP) == 0x8B
						&& *((PBYTE)pFunctionAddr + 2 + idx * UP) == 0xD1
						&& *((PBYTE)pFunctionAddr + 3 + idx * UP) == 0xB8
						&& *((PBYTE)pFunctionAddr + 6 + idx * UP) == 0x00
						&& *((PBYTE)pFunctionAddr + 7 + idx * UP) == 0x00) {

						BYTE high = *((PBYTE)pFunctionAddr + 5 + idx * UP);
						BYTE low = *((PBYTE)pFunctionAddr + 4 + idx * UP);
						pNtSys->dwSSN = (high << 8) | low + idx;
						break; // break for-loop [idx]
					}
				}
			}

			break; // break for-loop [i]

		}

	}

	// ---------------------- INDIRECT SYSCALL ---------------------------
	// check if still have a SYSCALL address
	if (!pNtSys->pSyscallAddress) {
		return FALSE;
	}

	// looking somewhere random (0xFF byte away from the syscall address)
	ULONG_PTR uFuncAddress = (ULONG_PTR)pNtSys->pSyscallAddress + 0xFF;

	// getting the 'syscall' instruction of another syscall function
	DWORD z = 0, x = 1;
	for (z, x; z <= RANGE; z++, x++) {
		if (*((PBYTE)uFuncAddress + z) == 0x0F && *((PBYTE)uFuncAddress + x) == 0x05) {
			pNtSys->pRandSyscallAddress = ((ULONG_PTR)uFuncAddress + z);
			break; // break for-loop [x & z]
		}
	}

	// checking if all NT_SYSCALL's (pNtSys) element are initialized
	if (pNtSys->dwSSN != NULL &&
		pNtSys->pSyscallAddress != NULL &&
		pNtSys->dwSyscallHash != NULL &&
		pNtSys->pRandSyscallAddress != NULL) 
	{
		//PRINTA("[+] All elements of pNtSys struct populated !\n");
		return TRUE;
	}
	else {
		return FALSE;
	}
}

BOOL InitNtdllStruct(void) {

	//Obtain the PEB offset
	PPEB pPEB = (PEB*)__readgsqword(0x60);
	if (!pPEB || pPEB->OSMajorVersion != 0xA) {
		return FALSE;
	}

	// getting ntdll.dll module (skipping our local image element)
	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPEB->LdrData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	ULONG_PTR NtdllBase = (ULONG_PTR)pLdr->DllBase;
	if (NtdllBase == NULL) {
		return FALSE;
	}

	// fetching the dos header of ntdll
	PIMAGE_DOS_HEADER ImgDosHdr = (PIMAGE_DOS_HEADER)NtdllBase;
	if (ImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// fetching the nt headers of ntdll
	PIMAGE_NT_HEADERS ImgNtHdrs = (PIMAGE_NT_HEADERS)(NtdllBase + ImgDosHdr->e_lfanew);
	if (ImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	// obtain the IMAGE_EXPORT_DIRECTORY address
	PIMAGE_EXPORT_DIRECTORY ImgExpDir =
		(PIMAGE_EXPORT_DIRECTORY)(NtdllBase + ImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (!ImgExpDir) {
		return FALSE;
	}

	_G_NtdllConf.uModule = NtdllBase;
	_G_NtdllConf.dwNumberOfNames = ImgExpDir->NumberOfNames;
	_G_NtdllConf.pdwArrayOfNames = (PDWORD)(NtdllBase + ImgExpDir->AddressOfNames);
	_G_NtdllConf.pdwArrayOfAddresses = (PDWORD)(NtdllBase + ImgExpDir->AddressOfFunctions);
	_G_NtdllConf.pwArrayOfOrdinals = (PDWORD)(NtdllBase + ImgExpDir->AddressOfNameOrdinals);

	// checking everything went fine above
	if (!_G_NtdllConf.uModule ||
		!_G_NtdllConf.dwNumberOfNames ||
		!_G_NtdllConf.pdwArrayOfNames ||
		!_G_NtdllConf.pdwArrayOfAddresses ||
		!_G_NtdllConf.pwArrayOfOrdinals)
	{
		return FALSE;
	}
	else {
		return TRUE;
	}

}