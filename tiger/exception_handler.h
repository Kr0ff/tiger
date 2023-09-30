#include "structs.h"

#define SET_HANDLERINFO(OriginalFunctionRip, HookFunctionRip) (set_handlerinfo(OriginalFunctionRip, HookFunctionRip))

//LONG WINAPI e_handler(EXCEPTION_POINTERS* ExceptionInfo, DWORD64 OriginalFunctionRip, DWORD64 HookFunctionRip);
LONG WINAPI e_handler(EXCEPTION_POINTERS* ExceptionInfo);
int set_handlerinfo(DWORD64 OriginalFunctionRip, DWORD64 HookFunctionRip);