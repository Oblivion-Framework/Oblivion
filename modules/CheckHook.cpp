#include <Windows.h>
#include <stdio.h>
#include <iostream>

int main()
{
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)ntdll;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)ntdll + dosHeader->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)ntdll + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    int counter = 0;
    DWORD* AddressOfNamesTable = (DWORD*)((BYTE*)ntdll + exportDir->AddressOfNames);
    WORD* AddressOfOrdinalsTable = (WORD*)((BYTE*)ntdll + exportDir->AddressOfNameOrdinals);
    DWORD* AddressOfFuncs = (DWORD*)((BYTE*)ntdll + exportDir->AddressOfFunctions);
    
    for(int i = 0; i < exportDir->NumberOfNames; ++i)
    {
        char* name = (char*)((BYTE*)ntdll + AddressOfNamesTable[i]);
        DWORD* address = (DWORD*)((BYTE*)ntdll + AddressOfFuncs[(WORD)AddressOfOrdinalsTable[i]]);
        //printf("Function: [%s]\n", name);
        //printf("\\___[Address: 0x%p]\n", address);
        if(address[4] == 0x050f0375)
        {
            counter++;
            printf("%x %x %x %x %x %x\n", address[0], address[1], address[2],address[3],address[4],address[5]);
            // check for e9 opcodes address[1] holds SSN so dont check that one but do check the rest
        }
    }
    printf("Number of syscalls: %d\n", counter);
}
