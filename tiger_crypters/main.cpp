#include "rc4.h"
#include "xor.h"

int wmain(int argc, wchar_t* argv[]) {

	// Modifications done in rc4.cpp
	//_CryptMemory032();

	WCHAR wstr[] = L"hello world!";
	WCHAR wkey = L'A';
	//xor_cryptW(wstr, wkey);



	char str[] = "hello world!";
	unsigned char key = 0x41;
	//xor_cryptA(str, key);

	char* baseStr = (char*)"kylewbanks.com";
	char* encStr = (char*)"\x2a\x38\x2d\x24\x36\x23\x20\x2f\x2a\x32\x6f\x22\x2e\x2c";
	//char encrypted[];
	encryptDecrypt(encStr);
	

	return 0;
}