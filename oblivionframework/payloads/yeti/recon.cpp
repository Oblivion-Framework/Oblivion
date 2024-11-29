#include <windows.h>
#include <TlHelp32.h>
#include <LM.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <unordered_map>
#include <functional>
#include <iomanip>

using namespace std;

void systemInfo() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    cout << "\n== SYSTEM INFO ==" << endl;
    cout << "Process Architecture: " << si.wProcessorArchitecture << endl;
    cout << "Number of Processors: " << si.dwNumberOfProcessors << endl;

    OSVERSIONINFO osInfo;
    ZeroMemory(&osInfo, sizeof(OSVERSIONINFO));
    osInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    if (GetVersionEx(&osInfo)) {
        cout << "OS Version: " << osInfo.dwMajorVersion << "." << osInfo.dwMinorVersion << endl;
        cout << "Build Number: " << osInfo.dwBuildNumber << endl;
    } else {
        cout << "Failed to find OS Info" << endl;
    }

    char hostname[256];
    DWORD size = sizeof(hostname);
    if (GetComputerNameA(hostname, &size)) {
        cout << "Host Name: " << hostname << endl;
    } else {
        cout << "Failed to retrieve host name" << endl;
    }

    char username[256];
    DWORD username_len = sizeof(username);
    if (GetUserNameA(username, &username_len)) {
        cout << "User Name: " << username << endl;
    } else {
        cout << "Failed to retrieve user name" << endl;
    }

    DWORD tickCount = GetTickCount();
    DWORD uptimeInSeconds = tickCount / 1000;
    DWORD uptimeInDays = uptimeInSeconds / 86400;
    uptimeInSeconds %= 86400;
    DWORD uptimeInHours = uptimeInSeconds / 3600;
    uptimeInSeconds %= 3600;
    DWORD uptimeInMinutes = uptimeInSeconds / 60;
    uptimeInSeconds %= 60;

    cout << "System Uptime: " << uptimeInDays << " days, " 
         << uptimeInHours << " hours, " 
         << uptimeInMinutes << " minutes, " 
         << uptimeInSeconds << " seconds." << endl;

    // CPU Information
    cout << "\n== CPU INFO ==" << endl;
    cout << "Number of CPU Cores: " << si.dwNumberOfProcessors << endl;

    // Memory Information
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memStatus)) {
        cout << "Total Physical Memory: " 
             << memStatus.ullTotalPhys / (1024 * 1024) << " MB" << endl;
        cout << "Available Physical Memory: " 
             << memStatus.ullAvailPhys / (1024 * 1024) << " MB" << endl;
    } else {
        cout << "Failed to retrieve memory information" << endl;
    }
        // Disk Information (C: drive)
    cout << "\n== DISK INFO ==" << endl;
    ULARGE_INTEGER freeBytesToCaller, totalBytes, freeBytes;
    if (GetDiskFreeSpaceExW(L"C:\\", &freeBytesToCaller, &totalBytes, &freeBytes)) {
        cout << "Total Disk Space: " 
            << totalBytes.QuadPart / (1024 * 1024 * 1024) << " GB" << endl;
        cout << "Free Disk Space: " 
            << freeBytes.QuadPart / (1024 * 1024 * 1024) << " GB" << endl;
    } else {
        cout << "Failed to retrieve disk information" << endl;
    }

}


void listprocs() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        cout << "Failed to take process snapshot." << endl;
        return;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    cout << "\n== RUNNING PROCESSES ==" << endl;

    if (Process32First(hSnapshot, &pe)) {
        do {
            wcout << L"Process Name: " << pe.szExeFile << L" | Process ID: " << pe.th32ProcessID << endl;
        } while (Process32Next(hSnapshot, &pe));
    } else {
        cout << "Failed to enumerate processes." << endl;
    }

    CloseHandle(hSnapshot);
}

void executeCommand(const string &command, const string &header) {
    cout << "\n== " << header << " ==" << endl;
    FILE *pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        cout << "Failed to execute command: " << command << endl;
        return;
    }

    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        cout << buffer;
    }
    _pclose(pipe);
}

void netrecon() {
    cout << "\n== NETWORK INFO ==" << endl;
    executeCommand("ipconfig", "IP CONFIGURATION");
    executeCommand("netstat -an", "ACTIVE NETWORK CONNECTIONS");
    executeCommand("arp -a", "ARP TABLES");
}

void LoggedUsers() {
    LPWKSTA_USER_INFO_1 pBuf = NULL;
    DWORD dwEntriesRead = 0, dwTotalEntries = 0;
    NET_API_STATUS nStatus;

    cout << "\n== LOGGED IN USERS ==" << endl;

    nStatus = NetWkstaUserEnum(NULL, 1, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, NULL);
    if (nStatus == NERR_Success && pBuf != NULL) {
        for (DWORD i = 0; i < dwEntriesRead; i++) {
            wcout << L"User: " << pBuf[i].wkui1_username;

            LPUSER_INFO_1 pUserInfo = NULL;
            nStatus = NetUserGetInfo(NULL, pBuf[i].wkui1_username, 1, (LPBYTE*)&pUserInfo);
            if (nStatus == NERR_Success && pUserInfo != NULL) {
                wcout << L" | Privileges: ";
                switch (pUserInfo->usri1_priv) {
                    case USER_PRIV_GUEST:
                        wcout << L"Guest";
                        break;
                    case USER_PRIV_USER:
                        wcout << L"User";
                        break;
                    case USER_PRIV_ADMIN:
                        wcout << L"Administrator";
                        break;
                    default:
                        wcout << L"Unknown";
                }
                NetApiBufferFree(pUserInfo);
            } else {
                wcout << L" | Failed to retrieve privileges.";
            }

            wcout << endl;
        }
        NetApiBufferFree(pBuf);
    } else {
        cout << "Failed to find logged-in users. Error code: " << GetLastError() << endl;
    }
}

void WiFiRecon() {
    cout << "\n== Wi-Fi PROFILES ==" << endl;
    executeCommand("netsh wlan show profiles", "Wi-Fi Profiles");

    cout << "\n== Wi-Fi PASSWORDS ==" << endl;
    string profile;
    cout << "Enter a Wi-Fi profile name to display the password: ";
    getline(cin, profile);

    if (!profile.empty()) {
        string command = "netsh wlan show profile \"" + profile + "\" key=clear";
        executeCommand(command, "Wi-Fi Passwords");
    }
}

void CheckAntivirus() {
    cout << "\n== ANTIVIRUS CHECK ==" << endl;
    executeCommand("wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName", "Installed Antivirus"); // try doing something else looks sus asf
    // Try enumerating DLLs and printing them out to see the presence of current process hooked
    // and also enumerate ntdll functions for hook by going to every syscall stub and checking e9 opcode

}// i just dont know how to do the av check

void clearScreen() {
    system("cls");
}

int main() {
    unordered_map<string, function<void()>> commands = {
        {"systeminfo", systemInfo},
        {"listprocs", listprocs},
        {"netrecon", netrecon},
        {"loggedusers", LoggedUsers},
        {"wifirecon", WiFiRecon},
        {"checkantivirus", CheckAntivirus},
        {"clear", [](){ clearScreen(); }} 
    };
    
    string input;
    
   while (true) { 
        cout << "\nEnter a function name to execute (systeminfo, listprocs, netrecon, loggedusers, wifirecon, checkantivirus), 'clear' to clear the screen, or 'exit' to quit: ";
        getline(cin, input);

        if (input == "exit") {
            break;
        }

        auto cmd = commands.find(input);
        if (cmd != commands.end()) {
            cmd->second(); 
        } else {
            cout << "Invalid function name. Please try again." << endl;
        }
    }

    return 0;
}
