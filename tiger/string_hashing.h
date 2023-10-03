#include "structs.h"

#define CRC32B(str) crc32b(str)
#define CRC32H(message) crc32h(message)
#define DJB2(str) djb2(str)

DWORD64 crc32b(PBYTE str);
DWORD64 crc32h(unsigned char* message);
DWORD64 djb2(PBYTE str);