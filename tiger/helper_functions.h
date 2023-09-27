#include "structs.h"

PVOID ZwMoveMemory(
	_Inout_ PVOID dest,
	_In_    const PVOID src,
	_In_    SIZE_T len
);