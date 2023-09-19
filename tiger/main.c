#include "custom_loaderapi.h"
#include "debug.h"
#include "printf.h"
#include "rc4.h"

#define ERR -0x1
#define SUCCESS 0x0

#define NTALLOCATEVIRTUALMEMORY 0xffffffffe0762feb
#define VIRTUALALLOC 0xffffffff09ce0d4a
#define KERNEL32 0xffffffff330c7795
#define NTDLL 0xffffffff7808a3d2

int main(void) {

	printf("======== Press Enter to start ========\n");
	getchar();

	HMODULE hKernel32 = _GetModuleHandle(KERNEL32);
	HMODULE hNtdll = _GetModuleHandle(NTDLL);
	if (hKernel32 == NULL || hNtdll == NULL) {
		printf("[-] Unable to obtain address of kernel32/ntdll in memory\n");
		return ERR;
	}

	printf("[+] Address of ->\n\t| KERNEL32 -> %#p\n\t| NTDLL -> %#p\n", hKernel32, hNtdll);
	
	FARPROC ntapi = _GetProcAddress(hNtdll, NTALLOCATEVIRTUALMEMORY);
	FARPROC k32api = _GetProcAddress(hKernel32, VIRTUALALLOC);

	printf("[+] Address of -> \n\t| NtAllocateVirtualMemory -> %#p\n\t| VirtualAlloc -> %#p\n", ntapi, k32api);

	return SUCCESS;
}