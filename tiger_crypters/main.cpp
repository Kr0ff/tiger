#include "encryption/rc4.h"
#include "encryption/xor.h"

int wmain(int argc, wchar_t* argv[]) {

	// Modifications done in rc4.cpp
	//_CryptMemory032();

	unsigned char bytes[] = {
		0x31, 0xc0,
		0xc3
	};
	
	// XOR encrypted using 'A' = 0x41 as key
	unsigned char xbytes[] = { 0x70,0x81,0x82 };

	DWORD _size = sizeof(bytes);

	unsigned char _key = 0x86;
	xor_cryptA(bytes, _key, _size);

	return 0;
}