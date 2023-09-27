#include "structs.h"

#define _GetModuleHandle Custom_GetModuleHandle
#define _GetProcAddress Custom_GetProcAddress

HMODULE Custom_GetModuleHandle(DWORD64 ModuleHash);
FARPROC Custom_GetProcAddress(HMODULE hModule, DWORD64 ApiHash);

