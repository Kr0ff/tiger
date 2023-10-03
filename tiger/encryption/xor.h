#include "../structs.h"

#define XORA(str, _key, _size) xor_cryptA(str, _key, _size)
//#define XORW(wstr, _key) xor_cryptW(wstr, _key)

void xor_cryptA(unsigned char str[], unsigned char key, DWORD size);
//void xor_cryptW(WCHAR str[], WCHAR wkey);