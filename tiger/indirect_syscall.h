#include "structs.h"
#include "string_hashing.h"
#include "typedefs.h"

typedef struct _NTSYSCALL {
    DWORD dwSSN;                    // syscall number
    DWORD64 dwSyscallHash;           // syscall hash value
    PVOID pSyscallAddress;          // syscall address
    PVOID pRandSyscallAddress;      // address of a random 'syscall' instruction in ntdll  

} NTSYSCALL, *PNTSYSCALL;

typedef struct _NTDLL_STRUCT
{
    PDWORD      pdwArrayOfAddresses; // The VA of the array of addresses of ntdll's exported functions   
    PDWORD      pdwArrayOfNames;     // The VA of the array of names of ntdll's exported functions       
    PWORD       pwArrayOfOrdinals;   // The VA of the array of ordinals of ntdll's exported functions     
    DWORD       dwNumberOfNames;     // The number of exported functions from ntdll.dll                 
    ULONG_PTR   uModule;             // The base address of ntdll - requred to calculated future RVAs  

} NTDLL_STRUCT, *PNTDLL_STRUCT;

typedef struct _NTAPI_FUNC
{
    NTSYSCALL	NtAllocateVirtualMemory;
    NTSYSCALL	NtProtectVirtualMemory;
    NTSYSCALL	NtCreateThreadEx;
    NTSYSCALL	NtWaitForSingleObject;
    NTSYSCALL   NtDelayExecution;

}NTAPI_FUNC, * PNTAPI_FUNC;

VOID _SetSSn(DWORD dwSSN, PVOID pRandSyscallAddress);
LONG _RunSyscall();

#define SET_SYSCALL(pNtSys) (_SetSSn((DWORD)pNtSys.dwSSN,(PVOID)pNtSys.pRandSyscallAddress))

BOOL ObtainSyscall(IN DWORD64 dwSysHash, OUT PNTSYSCALL pNtSys);
BOOL InitNtdllStruct();
BOOL InitializeNtSyscalls();
