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
* ETW Bypass via byte patch                  [✅]
* Maybe more to add... ?

As of now the payload works great against MDE (no block mode tested only) with Havoc. The code could likely be modified to use a different method of memory allocation, prevent creation of user thread or even inject directly into a sacrificial process that does PPID spoofing and has a `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON`. Self-deletion of the initial access payload might work as well to prevent the binary from persisting on disk after execution. 

For more advanced features, call stack spoofing could be implemented as well however, this is pretty advanced and I have no clue how that could work or to even implement.
