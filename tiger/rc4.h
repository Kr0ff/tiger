#include "structs.h"
#include "ntstatus.h"

NTSTATUS WINAPI SystemFunction032(struct ustring* data, const struct ustring* key);
NTSTATUS CryptMemory032(PVOID memoryAddr, SIZE_T memoryblkSize, char* key, SIZE_T keySize);