.data
	wSystemCall DWORD 0000h
	qSyscallInsAdress QWORD 0h
.code 
	
	SetSSN PROC
			xor eax, eax                          ; eax = 0
			mov wSystemCall, eax                  ; wSystemCall = 0
			mov qSyscallInsAdress, rax            ; qSyscallInsAdress = 0
			mov eax, ecx                          ; eax = ssn
			mov wSystemCall, eax                  ; wSystemCall = eax = ssn
			mov r8, rdx                           ; r8 = AddressOfASyscallInst
			mov qSyscallInsAdress, r8             ; qSyscallInsAdress = r8 = AddressOfASyscallInst
			ret
	SetSSN ENDP

	RunSyscall PROC
			xor r10, r10                          ; r10 = 0
			mov rax, rcx                          ; rax = rcx
			mov r10, rax                          ; r10 = rax = rcx
			mov eax, wSystemCall                  ; eax = ssn
			jmp Run                               ; execute 'Run'
			xor eax, eax      ; wont run
			xor rcx, rcx      ; wont run
			shl r10, 2        ; wont run
		Run:
			jmp qword ptr [qSyscallInsAdress]   ; jumping to the 'syscall' instruction
			xor r10, r10                        ; r10 = 0
			mov qSyscallInsAdress, r10          ; qSyscallInsAdress = 0
			ret
	RunSyscall ENDP

end
