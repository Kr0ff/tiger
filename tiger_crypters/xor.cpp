#include "xor.h"

void encryptDecrypt(char* input) {
	unsigned char key = 0x41; //Can be any chars, and any size array
	char output[MAX_PATH];
	printf("Size: %d\n", strlen(input));


	int i;
	for (i = 0; i < strlen(input); i++) {
		output[i] = input[i] ^ key;
		printf("%s", output[i]);
	}
}


void xor_cryptA(unsigned char str[], unsigned char key) {

	DWORD sizeStr = strlen((char*)str);
	unsigned char xord[] = { 0 };

	int i = 0;
	for (i; i < sizeStr; i++) {
		xord[i] = str[i] ^ key;
		printf("\\x%02x", str[i]);
	}

	printf("\nDecrypting....\n");

	unsigned char enc[] = "\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x21";
	unsigned char xkey = 0x41;

	for (i; i < sizeof enc; i++) {
		enc[i] = enc[i] ^ xkey;
		printf("%s", enc[i]);
	}
	printf("\n");
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
	//wprintf(L"Total: %x\n", wxord);

	wprintf(L"\nDecrypting....\n");

	WCHAR enc[] = L"\x29\x24\x2d\x2d\x2e\x61\x36\x2e\x33\x2d\x25\x60";
	WCHAR xkey = L'A';

	for (i; i < sizeWStr; i++) {
		printf("%s", (enc[i] ^ xkey));
	}
	wprintf(L"\n");
	return;
}