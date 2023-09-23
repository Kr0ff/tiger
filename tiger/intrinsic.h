#pragma once
// The `extern` keyword sets the `memset` function as an external function.
extern void* __cdecl memset(void* Destination, int Value, size_t Size);

// The `#pragma intrinsic(memset)` and #pragma function(memset) macros are Microsoft-specific compiler instructions.
// They force the compiler to generate code for the memset function using a built-in intrinsic function.
#pragma intrinsic(memset)
#pragma function(memset)

void* __cdecl memset(void* Destination, int Value, size_t Size) {
    // logic similar to memset's one
    unsigned char* p = (unsigned char*)Destination;
    while (Size > 0) {
        *p = (unsigned char)Value;
        p++;
        Size--;
    }
    return Destination;
}