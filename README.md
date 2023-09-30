# tiger

Tiger is a initial access payload loader for Win64. It has the following features:

* Indirect Syscalls using TartarusGate       [✅]
* Anti-Disassembly                           [✅]
* Anti-Debugging                             [✅]
* Memory hiding via hardware breakpoints     [✅]
* RC4 Encryption of shellcode                [✅]
* Payload exec monitoring via NtCreateMutant [✅]
* Import Address Table (IAT) camoflage       [✅]
* String hashing (CRC32B)                    [✅]
* ETW Bypass via hardware breakpoints        [❌]
* Maybe more to add... ?
