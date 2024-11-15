﻿#include "anti-disass.h"
#include "../structs.h"

extern void __AsmConstantCondition();
extern void __AsmJmpSameTarget();
extern void __AsmImpossibleDisassm();
extern void __AsmFunctionPointer(DWORD);
extern void __AsmReturnPointerAbuse(DWORD64);

#ifndef _WIN64
extern void __AsmSEHMisuse();
#endif

/*
	This technique is composed of a single conditional jump instruction placed where the condition
	will always be the same.
*/
void AntiDisassmConstantCondition()
{
	__AsmConstantCondition();
}

/*
	The most common anti-disassembly technique seen in the wild is two back-to back
	conditional jump instructions that both point to the same target. For example,
	if a jz XYZ is followed by jnz XYZ, the location XYZ will always be jumped to
*/
void AntiDisassmAsmJmpSameTarget()
{
	__AsmJmpSameTarget();
}


/*
	By using a data byte placed strategically after a conditional jump instruction
	with the idea that disassembly starting at this byte will prevent the real instruction
	that follows from being disassembled because the byte that inserted is the opcode for
	a multibyte instruction.

*/
void AntiDisassmImpossibleDiasassm()
{
	__AsmImpossibleDisassm();
}


/*
	If function pointers are used in handwritten assembly or crafted in a nonstandard way
	in source code, the results can be difficult to reverse engineer without dynamic analysis.
*/
void AntiDisassmFunctionPointer()
{

	DWORD Number = 2;
	__AsmFunctionPointer(Number);
}


/*
	The most obvious result of this technique is that the disassembler doesn't show any
	code cross - reference to the target being jumped to.
*/
void AntiDisassmReturnPointerAbuse()
{
	__AsmReturnPointerAbuse(666);
}

#ifndef _WIN64
void AntiDisassmSEHMisuse()
{
	__AsmSEHMisuse();
}
#endif