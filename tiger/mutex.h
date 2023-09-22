#include "structs.h"

HANDLE _CreateMutex(LPCWSTR mutexName);
BOOL _DestroyMutex(HANDLE hMutex);