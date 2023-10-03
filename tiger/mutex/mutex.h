#include "../structs.h"

BOOL InitialiaseNTSyscalls();

HANDLE _CreateMutant(WCHAR* wMutantName);
BOOL _DestroyMutant(HANDLE hMutant);