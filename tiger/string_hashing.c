#include "string_hashing.h"

DWORD64 crc32b(PBYTE str) {
    // Source: https://stackoverflow.com/a/21001712
    DWORD64 byte, crc, mask;
    int i = 0, j;
    crc = 0xFFFFFFFF;
    while (str[i] != 0) {
        byte = str[i];
        crc = crc ^ byte;
        for (j = 7; j >= 0; j--) {
            mask = -((int)crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
        i = i + 1;
    }
    return ~crc;
}

#define CRC32HSEED 0xEDB88320

DWORD64 crc32h(unsigned char* message) {
    //Source: https://web.archive.org/web/20190108202303/http://www.hackersdelight.org/hdcodetxt/crc.c.txt
    int i, crc;
    unsigned int byte, c;
    const unsigned int g0 = CRC32HSEED, g1 = g0 >> 1,
        g2 = g0 >> 2, g3 = g0 >> 3, g4 = g0 >> 4, g5 = g0 >> 5,
        g6 = (g0 >> 6) ^ g0, g7 = ((g0 >> 6) ^ g0) >> 1;

    i = 0;
    crc = 0xFFFFFFFF;
    while ((byte = message[i]) != 0) {    // Get next byte.
        crc = crc ^ byte;
        c = ((crc << 31 >> 31) & g7) ^ ((crc << 30 >> 31) & g6) ^
            ((crc << 29 >> 31) & g5) ^ ((crc << 28 >> 31) & g4) ^
            ((crc << 27 >> 31) & g3) ^ ((crc << 26 >> 31) & g2) ^
            ((crc << 25 >> 31) & g1) ^ ((crc << 24 >> 31) & g0);
        crc = ((unsigned)crc >> 8) ^ c;
        i = i + 1;
    }
    return ~crc;
}

DWORD64 djb2(PBYTE str) {
    DWORD64 dwHash = 0x35333831;
    INT c;

    while (c = *str++)
        dwHash = ((dwHash << 0x5) + dwHash) + c;

    return dwHash;
}
