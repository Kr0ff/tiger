#include "helper_functions.h"

PVOID ZwMoveMemory(PVOID dest, const PVOID src, SIZE_T len) {
	char* d = (char*)dest;
	char* s = (char*)src;

	if (d < s)
		while (len--)
			*d++ = *s++;
	else {
		char* lasts = s + (len - 1);
		char* lastd = d + (len - 1);
		while (len--)
			*lastd-- = *lasts--;
	}
	return dest;
}