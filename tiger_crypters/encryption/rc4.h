#pragma once
#include "ntstatus.h"
#include "../structs.h"

typedef struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	PUCHAR Buffer;
} data, key;


typedef NTSTATUS(NTAPI* t_SystemFunction032)
(
	struct ustring* data,
	const struct ustring* key
);

BOOL _CryptMemory032();