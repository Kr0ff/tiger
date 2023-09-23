#include "anti-debug.h"
#include "indirect_syscall.h"
#include "debug.h"

// https://github.com/LordNoteworthy/al-khaser
#define DEBUG

BOOL AntiDebugPEBCheck() {
	// Obtain the PEB offset
#ifdef _WIN64
	PPEB			pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB			pPeb = (PEB*)(__readfsdword(0x30));
#endif

	BOOLEAN debugged = pPeb->BeingDebugged;
	//printf("[!] Is Debugged -> %d\n", debugged);
	return (debugged == 1) ? TRUE : FALSE;
}

BOOL NtGlobalFlagCheck(VOID)
/*++

Routine Description:

	NtGlobalFlag is a DWORD value inside the process PEB. This value
	contains many flags set by the OS that affects the way the process
	runs. When a process is being debugged, the flags:
		- FLG_HEAP_ENABLE_TAIL_CHECK (0x10)
		- FLG_HEAP_ENABLE_FREE_CHECK (0x20)
		- FLG_HEAP_VALIDATE_PARAMETERS(0x40) are set for the process

	If the 32-bit executable is being run on a 64-bit system, both the
	32-bit and 64-bit PEBs are checked. The WoW64 PEB address is
	fetched via the WoW64 Thread Environment Block (TEB) at FS:[0x18]-0x2000.

Arguments:

	None

Return Value:

	TRUE - if debugger was detected
	FALSE - otherwise
--*/
{
	PDWORD pNtGlobalFlag = NULL, pNtGlobalFlagWoW64 = NULL;

#if defined (ENV64BIT)
	pNtGlobalFlag = (PDWORD)(__readgsqword(0x60) + 0xBC);

#elif defined(ENV32BIT)
	/* NtGlobalFlags for real 32-bits OS */
	BYTE* _teb32 = (BYTE*)__readfsdword(0x18);
	DWORD _peb32 = *(DWORD*)(_teb32 + 0x30);
	pNtGlobalFlag = (PDWORD)(_peb32 + 0x68);

	if (IsWoW64())
	{
		/* In Wow64, there is a separate PEB for the 32-bit portion and the 64-bit portion
		which we can double-check */

		BYTE* _teb64 = (BYTE*)__readfsdword(0x18) - 0x2000;
		DWORD64 _peb64 = *(DWORD64*)(_teb64 + 0x60);
		pNtGlobalFlagWoW64 = (PDWORD)(_peb64 + 0xBC);
	}
#endif

	BOOL normalDetected = pNtGlobalFlag && *pNtGlobalFlag & 0x00000070;
	BOOL wow64Detected = pNtGlobalFlagWoW64 && *pNtGlobalFlagWoW64 & 0x00000070;

	if (normalDetected || wow64Detected)
		return TRUE;
	else
		return FALSE;
}



BOOL DelayExecution(FLOAT ftMinutes) {

	NTAPI_FUNC _G_NTFUNC = { 0 };

	// Converting minutes to milliseconds  
	DWORD               dwMilliSeconds = ftMinutes * 60000;
	LARGE_INTEGER       DelayInterval = { 0 };
	LONGLONG            Delay = NULL;
	NTSTATUS            STATUS = NULL;
	DWORD               _T0 = NULL,
						_T1 = NULL;

	// Converting from milliseconds to the 100-nanosecond - negative time interval
	Delay = dwMilliSeconds * 10000;
	DelayInterval.QuadPart = -Delay;

	_T0 = GetTickCount64();

	// Sleeping for 'dwMilliSeconds' ms 
	ObtainSyscall(NTDELAYEXECUTION_HASH, &_G_NTFUNC.NtDelayExecution);
	SET_SYSCALL(_G_NTFUNC.NtDelayExecution);
#ifdef DEBUG
	PRINTA("[+] Starting execution delay!\n");
#endif
	if ((STATUS = RunSyscall(FALSE, &DelayInterval)) != 0x00 && STATUS != STATUS_TIMEOUT) {
#ifdef DEBUG
			PRINTA("[!] NtDelayExecution Failed With Error: 0x%0.8X \n", STATUS);
#endif
			return -1;
	}

	_T1 = GetTickCount64();

	// Slept for at least 'dwMilliSeconds' ms, then 'DelayExecution' succeeded, otherwise it failed
	if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
		return FALSE;

	return TRUE;
}