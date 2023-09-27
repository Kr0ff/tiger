#include "structs.h"
#include <stdio.h>

#define XORA(str, _key) xor_cryptA(str, _key)
#define XORW(wstr, _key) xor_cryptW(wstr, _key)

void xor_cryptA(unsigned char str[], unsigned char key);
void xor_cryptW(WCHAR str[], WCHAR wkey);