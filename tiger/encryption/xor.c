#include "xor.h"

void xor_cryptA(unsigned char str[], unsigned char key, SIZE_T _size) {

	SIZE_T i = 0;
	for (i; i < _size; i++) {
		str[i] = str[i] ^ key;
	}

	return;
}