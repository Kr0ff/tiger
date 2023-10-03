#include "xor.h"

void xor_cryptA(unsigned char str[], unsigned char key, DWORD size) {

	//DWORD sizeStr = sizeof(str);
	unsigned char xor_d[] = { 0 };

	DWORD i = 0;
	for (i; i < size; i++) {
		str[i] = str[i] ^ key;
		printf("\\x%02x", str[i]);
	}

	return;
}

void xor_cryptW(WCHAR wstr[], WCHAR key) {
	size_t sizeWStr = wcslen(wstr);
	WCHAR wxord[] = { 0 };

	int i = 0;
	for (i; i < sizeWStr; i++) {
		wxord[i] = wstr[i] ^ key;
		//wxord[i]++;
		wprintf(L"\\x%02x", wxord[i]);
	}
	return;
}