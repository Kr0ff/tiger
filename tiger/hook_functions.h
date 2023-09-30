#include "structs.h"

#define SET_SCADDRESS(hProcess, pScAddress, sSize, dwProtection) (set_scaddress(hProcess, pScAddress, sSize, dwProtection))

// Jump function for WinAPI()
BOOL set_scaddress(HANDLE hProcess, PVOID pScAddress, SIZE_T sSize, ULONG dwProtection);
//void __stdcall hook_Sleep(DWORD dwMilliseconds);
int __stdcall hook_MessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);