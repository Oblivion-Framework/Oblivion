#include <Windows.h>
#include <stdio.h>
#include <psapi.h>
#include <tchar.h>


void EnumerateDLLs()
{
    HMODULE hModules[1024];
    DWORD cbNeeded;
    if(!EnumProcessModules((HANDLE)-1, hModules, sizeof(hModules), &cbNeeded))
    {
        printf("EnumerateProcessModules() failed with error code %d", GetLastError());
        return;
    }
    TCHAR DllName[MAX_PATH]; //MAX_PATH is 260
    for(int i = 0; i < (cbNeeded/sizeof(HMODULE)); ++i)
    {
        if(GetModuleFileNameExA((HANDLE)-1, hModules[i], DllName, sizeof(DllName)/sizeof(TCHAR)))
        {
            printf("[%d] Loaded Module: %s\n", i, TEXT(DllName));
        }
        else
        {
            printf("[-] Unable to load library error code %d\n", GetLastError());
        }
    }
    return;
}
