#include "exception_handler.h"

#include "../typedefs.h"
#include "../custom_loaderapi.h"

#include "../debug/debug.h"

DWORD64 _G_OriginalFunctionRip;
DWORD64 _G_HookFunctionRip;

int set_handlerinfo(DWORD64 OriginalFunctionRip, DWORD64 HookFunctionRip) {
	if (OriginalFunctionRip == NULL || HookFunctionRip == NULL) {
		return -1;
	}
	
	_G_OriginalFunctionRip	= OriginalFunctionRip;
	_G_HookFunctionRip = HookFunctionRip;

	return 0;
}

LONG WINAPI e_handler(EXCEPTION_POINTERS* ExceptionInfo) {
	
	t_RtlSetProcessIsCritical SetCriticalProcess =
		(t_RtlSetProcessIsCritical)_GetProcAddress(_GetModuleHandle(NTDLL_HASH), RTLSETPROCESSISCRITICAL_HASH);
	t_TerminateProcess TerminateProcess = (t_TerminateProcess)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), TERMINTATEPROCESS_HASH);


	// Check EXCEPTION_POINTERS dont result in ACCESS_VIOLATION
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
#ifdef DEBUG
		PRINTA("[-] Exception handler ACCESS_VIOLATION Hit ( Code: %d )\n", ExceptionInfo->ExceptionRecord->ExceptionCode);
#endif
		SetCriticalProcess(TRUE, NULL, FALSE);
		TerminateProcess(NtCurrentProcess(), -1);

		return EXCEPTION_NONCONTINUABLE;
	}

	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
		if (ExceptionInfo->ContextRecord->Rip == _G_OriginalFunctionRip) {
#ifdef DEBUG
			PRINTA("[+] Exception caught -> Hit ( 0x%p )\n", ExceptionInfo->ContextRecord->Rip);
#endif

			// Set EFlags to resume execution
			ExceptionInfo->ContextRecord->EFlags |= (1 << 16);
			// Point to the custom (hook) function
			ExceptionInfo->ContextRecord->Rip = _G_HookFunctionRip;

			// Alternatively, can skip the breakpoint by incrementing the RIP register 
			//ExceptionInfo->ContextRecord->Rip++;
		}
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;

}