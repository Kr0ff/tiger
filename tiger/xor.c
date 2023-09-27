#include "xor.h"

void xor_cryptA(unsigned char str[], unsigned char key) {

	DWORD sizeStr = sizeof(str);
	int i = 0;

	for (i; i < sizeStr; i++) {
		str[i] = str[i] ^ key;
	}

	return;
}

void xor_cryptW(WCHAR wstr[], WCHAR key) {
	DWORD sizeWStr = sizeof(wstr);
	int i = 0;
	
	for (i; i < sizeWStr; i++) {
		wstr[i] = wstr[i] ^ key;
	}

	return;
}