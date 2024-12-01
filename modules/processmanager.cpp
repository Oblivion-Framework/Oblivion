#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <psapi.h>
#include <iomanip>

using namespace std;

typedef long NTSTATUS;
#define NTAPI __stdcall

typedef NTSTATUS(NTAPI* NtSuspendProcessType)(HANDLE ProcessHandle);
typedef NTSTATUS(NTAPI* NtResumeProcessType)(HANDLE ProcessHandle);

bool CreateRemoteProcess(const string& executablePath) {
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(STARTUPINFOA);

    if (CreateProcessA(
        executablePath.c_str(),
        NULL,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        cout << "Process created successfully. PID: " << pi.dwProcessId << '\n';
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    } else {
        cout << "Failed to create process. Error: " << GetLastError() << '\n';
        return false;
    }
}

bool TerminateRemoteProcess(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (hProcess == NULL) {
        cout << "Failed to open process. Error: " << GetLastError() << '\n';
        return false;
    }

    if (TerminateProcess(hProcess, 0)) {
        cout << "Process terminated successfully. PID: " << processId << '\n';
        CloseHandle(hProcess);
        return true;
    } else {
        cout << "Failed to terminate process. Error: " << GetLastError() << '\n';
        CloseHandle(hProcess);
        return false;
    }
}

bool SuspendRemoteProcess(DWORD processId) {
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (!hNtDll) {
        cout << "Failed to load ntdll.dll. Error: " << GetLastError() << '\n';
        return false;
    }

    NtSuspendProcessType pNtSuspendProcess = (NtSuspendProcessType)GetProcAddress(hNtDll, "NtSuspendProcess");
    if (!pNtSuspendProcess) {
        cout << "Failed to find NtSuspendProcess. Error: " << GetLastError() << '\n';
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, processId);
    if (hProcess == NULL) {
        cout << "Failed to open process. Error: " << GetLastError() << '\n';
        return false;
    }

    NTSTATUS status = pNtSuspendProcess(hProcess);
    if (status == 0) {
        cout << "Process suspended successfully. PID: " << processId << '\n';
        CloseHandle(hProcess);
        return true;
    } else {
        cout << "Failed to suspend process. NTSTATUS: " << status << '\n';
        CloseHandle(hProcess);
        return false;
    }
}

bool UnsuspendRemoteProcess(DWORD processId) {
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (!hNtDll) {
        cout << "Failed to load ntdll.dll. Error: " << GetLastError() << '\n';
        return false;
    }

    NtResumeProcessType pNtResumeProcess = (NtResumeProcessType)GetProcAddress(hNtDll, "NtResumeProcess");
    if (!pNtResumeProcess) {
        cout << "Failed to find NtResumeProcess. Error: " << GetLastError() << '\n';
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, processId);
    if (hProcess == NULL) {
        cout << "Failed to open process. Error: " << GetLastError() << '\n';
        return false;
    }

    NTSTATUS status = pNtResumeProcess(hProcess);
    if (status == 0) {
        cout << "Process resumed successfully. PID: " << processId << '\n';
        CloseHandle(hProcess);
        return true;
    } else {
        cout << "Failed to resume process. NTSTATUS: " << status << '\n';
        CloseHandle(hProcess);
        return false;
    }
}

DWORD GetProcessIdByName(const string& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        cout << "Failed to create process snapshot. Error: " << GetLastError() << '\n';
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (processName == pe32.szExeFile) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    cout << "Process not found: " << processName << '\n';
    return 0;
}

void ListRunningProcesses() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        cout << "Failed to create process snapshot. Error: " << GetLastError() << '\n';
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    cout << "PID\t\tProcess Name\n";
    cout << "----------------------------------\n";

    if (Process32First(hSnapshot, &pe32)) {
        do {
            cout << pe32.th32ProcessID << "\t\t" << pe32.szExeFile << '\n';
        } while (Process32Next(hSnapshot, &pe32));
    } else {
        cout << "Failed to retrieve processes. Error: " << GetLastError() << '\n';
    }

    CloseHandle(hSnapshot);
}

void QueryProcessMemory(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        cout << "Failed to open process for memory query. Error: " << GetLastError() << '\n';
        return;
    }

    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        cout << "Memory Usage for PID " << processId << ":\n";
        cout << "Working Set Size: " << pmc.WorkingSetSize << " bytes\n";
        cout << "Peak Working Set Size: " << pmc.PeakWorkingSetSize << " bytes\n";
        cout << "Pagefile Usage: " << pmc.PagefileUsage << " bytes\n";
        cout << "Peak Pagefile Usage: " << pmc.PeakPagefileUsage << " bytes\n";
    } else {
        cout << "Failed to retrieve memory info. Error: " << GetLastError() << '\n';
    }

    CloseHandle(hProcess);
}

bool SetProcessPriority(DWORD processId, const string& priorityLevel) {
    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, processId);
    if (hProcess == NULL) {
        cout << "Failed to open process. Error: " << GetLastError() << '\n';
        return false;
    }

    DWORD priorityClass = 0;
    if (priorityLevel == "idle") {
        priorityClass = IDLE_PRIORITY_CLASS;
    } else if (priorityLevel == "below_normal") {
        priorityClass = BELOW_NORMAL_PRIORITY_CLASS;
    } else if (priorityLevel == "normal") {
        priorityClass = NORMAL_PRIORITY_CLASS;
    } else if (priorityLevel == "above_normal") {
        priorityClass = ABOVE_NORMAL_PRIORITY_CLASS;
    } else if (priorityLevel == "high") {
        priorityClass = HIGH_PRIORITY_CLASS;
    } else if (priorityLevel == "real_time") {
        priorityClass = REALTIME_PRIORITY_CLASS;
    } else {
        cout << "Invalid priority level.\n";
        CloseHandle(hProcess);
        return false;
    }

    if (SetPriorityClass(hProcess, priorityClass)) {
        cout << "Priority changed successfully to " << priorityLevel << ". PID: " << processId << '\n';
        CloseHandle(hProcess);
        return true;
    } else {
        cout << "Failed to set priority. Error: " << GetLastError() << '\n';
        CloseHandle(hProcess);
        return false;
    }
}

void ListProcessModules(DWORD processId) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        cout << "Failed to create module snapshot. Error: " << GetLastError() << '\n';
        return;
    }

    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);

    cout << "Loaded modules for PID " << processId << ":\n";
    cout << "Module Name\t\tBase Address\n";
    cout << "----------------------------------\n";

    if (Module32First(hSnapshot, &me32)) {
        do {
            cout << me32.szModule << "\t\t" << "0x" 
                 << setw(8) << setfill('0') 
                 << hex << reinterpret_cast<uintptr_t>(me32.modBaseAddr) << '\n';
        } while (Module32Next(hSnapshot, &me32));
    } else {
        cout << "Failed to retrieve modules. Error: " << GetLastError() << '\n';
    }

    CloseHandle(hSnapshot);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cout << "Usage: " << argv[0] << " <command> [argument]\n";
        cout << "Commands: create, terminate, suspend, unsuspend, list, priority, meminfo\n";
        cout << "Arguments: <Path>\nterminate: <PID/Name>\nsuspend:   <PID/Name>\nunsuspend: <PID/Name>\npriority:  <PID/Name> <PriorityLevel>\nmeminfo:   <PID/Name>\nmodules:   <PID/Name>";
        return 1;
    }

    string command = argv[1];
    string argument = argc > 2 ? argv[2] : "";

    if (command == "create" && !argument.empty()) {
        CreateRemoteProcess(argument);
    } else if (command == "terminate") {
        DWORD pid = GetProcessIdByName(argument);
        if (pid != 0) TerminateRemoteProcess(pid);
    } else if (command == "suspend") {
        DWORD pid = GetProcessIdByName(argument);
        if (pid != 0) SuspendRemoteProcess(pid);
    } else if (command == "unsuspend") {
        DWORD pid = GetProcessIdByName(argument);
        if (pid != 0) UnsuspendRemoteProcess(pid);
    } else if (command == "list") {
        ListRunningProcesses();
    } else if (command == "priority" && argc == 4) {
        DWORD pid = GetProcessIdByName(argv[2]);
        if (pid != 0) SetProcessPriority(pid, argv[3]);
    } else if (command == "meminfo") {
        DWORD pid = GetProcessIdByName(argument);
        if (pid != 0) QueryProcessMemory(pid);
    } else if( command == "modules") {
        DWORD pid = GetProcessIdByName(argument);
        if (pid != 0) ListProcessModules(pid);
    } else {
        cout << "invalid command or argument\n";
    }

    return 0;
}
