#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <stdbool.h>
#include <winsvc.h>

#define MAX_PATH_LENGTH 512
#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

typedef struct {
    bool isRunning;
    TCHAR driverName[MAX_PATH_LENGTH];
    TCHAR configPath[MAX_PATH_LENGTH];
    TCHAR driverPath[MAX_PATH_LENGTH];
    DWORD configVersion;
    bool isDriverLoaded;
} SysmonInfo;

bool findRegistryKeyWithSysmon(TCHAR *foundKey, DWORD bufferSize) {
    static const TCHAR* possiblePaths[] = {
        TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Sysmon/Operational"),
        TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"),
        TEXT("SOFTWARE\\Sysinternals\\Sysmon")
    };

    for (int i = 0; i < sizeof(possiblePaths)/sizeof(possiblePaths[0]); i++) {
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, possiblePaths[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            _tcscpy_s(foundKey, bufferSize, possiblePaths[i]);
            RegCloseKey(hKey);
            return true;
        }
    }

    // Do an exhaustive search across all Sysinternals keys
    HKEY hBaseKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE"), 0, KEY_READ, &hBaseKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        TCHAR subKeyName[MAX_KEY_LENGTH];
        DWORD subKeyNameSize = MAX_KEY_LENGTH;

        while (RegEnumKeyEx(hBaseKey, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            if (_tcscmp(subKeyName, TEXT("Sysinternals")) == 0) {
                HKEY hSysInternalsKey;
                if (RegOpenKeyEx(hBaseKey, TEXT("Sysinternals"), 0, KEY_READ, &hSysInternalsKey) == ERROR_SUCCESS) {
                    DWORD sysmonIndex = 0;
                    TCHAR sysmonKeyName[MAX_KEY_LENGTH];
                    DWORD sysmonKeyNameSize = MAX_KEY_LENGTH;

                    while (RegEnumKeyEx(hSysInternalsKey, sysmonIndex, sysmonKeyName, &sysmonKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                        if (_tcsstr(sysmonKeyName, TEXT("Sysmon")) != NULL) {
                            _stprintf_s(foundKey, bufferSize, TEXT("SOFTWARE\\Sysinternals\\%s"), sysmonKeyName);
                            RegCloseKey(hSysInternalsKey);
                            RegCloseKey(hBaseKey);
                            return true;
                        }
                        sysmonIndex++;
                        sysmonKeyNameSize = MAX_KEY_LENGTH;
                    }
                    RegCloseKey(hSysInternalsKey);
                }
            }
            index++;
            subKeyNameSize = MAX_KEY_LENGTH;
        }
        RegCloseKey(hBaseKey);
    }

    return false;
}

bool findSysmonService(TCHAR *serviceName, DWORD bufferLength) {
    _tcscpy_s(serviceName, bufferLength, TEXT("Sysmon"));

    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scManager) {
        return false;
    }

    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;

    EnumServicesStatusEx(scManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                        NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);

    if (bytesNeeded == 0) {
        CloseServiceHandle(scManager);
        return false;
    }

    ENUM_SERVICE_STATUS_PROCESS* services = (ENUM_SERVICE_STATUS_PROCESS*)malloc(bytesNeeded);
    if (!services) {
        CloseServiceHandle(scManager);
        return false;
    }

    bool found = false;
    if (EnumServicesStatusEx(scManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                          (LPBYTE)services, bytesNeeded, &bytesNeeded, &servicesReturned,
                          &resumeHandle, NULL)) {

        for (DWORD i = 0; i < servicesReturned; i++) {
            if (_tcsstr(services[i].lpServiceName, TEXT("Sysmon")) != NULL) {
                _tcscpy_s(serviceName, bufferLength, services[i].lpServiceName);
                found = true;
                break;
            } else if (_tcsstr(services[i].lpDisplayName, TEXT("System Monitor")) != NULL) {
                _tcscpy_s(serviceName, bufferLength, services[i].lpServiceName);
                found = true;
                break;
            }
        }
    }

    free(services);
    CloseServiceHandle(scManager);
    return found;
}

bool isSysmonRunning(TCHAR *detectedServiceName) {
    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scManager) {
        return false;
    }

    bool result = false;
    TCHAR serviceName[MAX_PATH_LENGTH];

    if (detectedServiceName != NULL && detectedServiceName[0] != '\0') {
        _tcscpy_s(serviceName, MAX_PATH_LENGTH, detectedServiceName);
    } else if (!findSysmonService(serviceName, MAX_PATH_LENGTH)) {
        _tcscpy_s(serviceName, MAX_PATH_LENGTH, TEXT("Sysmon"));
    }

    SC_HANDLE sysmonService = OpenService(scManager, serviceName, SERVICE_QUERY_STATUS);

    if (sysmonService) {
        SERVICE_STATUS_PROCESS status;
        DWORD bytesNeeded;

        if (QueryServiceStatusEx(sysmonService, SC_STATUS_PROCESS_INFO,
                              (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
            result = (status.dwCurrentState == SERVICE_RUNNING);
            if (detectedServiceName != NULL) {
                _tcscpy_s(detectedServiceName, MAX_PATH_LENGTH, serviceName);
            }
        }
        CloseServiceHandle(sysmonService);
    }

    CloseServiceHandle(scManager);
    return result;
}

bool findSysmonDriverKey(TCHAR *keyPath, DWORD bufferSize) {
    static const TCHAR* possibleDriverKeys[] = {
        TEXT("SYSTEM\\CurrentControlSet\\Services\\SysmonDrv"),
        TEXT("SYSTEM\\CurrentControlSet\\Services\\SysmonDrv64"),
        TEXT("SYSTEM\\CurrentControlSet\\Services\\SysMon")
    };

    for (int i = 0; i < sizeof(possibleDriverKeys)/sizeof(possibleDriverKeys[0]); i++) {
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, possibleDriverKeys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            _tcscpy_s(keyPath, bufferSize, possibleDriverKeys[i]);
            RegCloseKey(hKey);
            return true;
        }
    }

    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Services"), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        TCHAR subKeyName[MAX_KEY_LENGTH];
        DWORD subKeyNameSize = MAX_KEY_LENGTH;

        while (RegEnumKeyEx(hKey, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            if (_tcsstr(subKeyName, TEXT("Sysmon")) != NULL || _tcsstr(subKeyName, TEXT("SysMon")) != NULL) {
                _stprintf_s(keyPath, bufferSize, TEXT("SYSTEM\\CurrentControlSet\\Services\\%s"), subKeyName);
                RegCloseKey(hKey);
                return true;
            }
            index++;
            subKeyNameSize = MAX_KEY_LENGTH;
        }
        RegCloseKey(hKey);
    }

    return false;
}

bool getSysmonDriverName(TCHAR *driverName, DWORD bufferSize, TCHAR *driverPath, DWORD pathBufferSize) {
    TCHAR keyPath[MAX_PATH_LENGTH];
    if (!findSysmonDriverKey(keyPath, MAX_PATH_LENGTH)) {
        return false;
    }

    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return false;
    }

    TCHAR keyName[MAX_PATH_LENGTH];
    _tcscpy_s(keyName, MAX_PATH_LENGTH, _tcsrchr(keyPath, '\\') + 1);
    _tcscpy_s(driverName, bufferSize, keyName);

    DWORD dataType;
    DWORD dataSize = pathBufferSize;

    RegQueryValueEx(hKey, TEXT("ImagePath"), NULL, &dataType, (LPBYTE)driverPath, &dataSize);
    RegCloseKey(hKey);

    return true;
}

void findSysmonEventLogs(TCHAR *channelName, DWORD bufferSize) {
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels"), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        TCHAR subKeyName[MAX_KEY_LENGTH];
        DWORD subKeyNameSize = MAX_KEY_LENGTH;

        while (RegEnumKeyEx(hKey, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            if (_tcsstr(subKeyName, TEXT("Sysmon")) != NULL || _tcsstr(subKeyName, TEXT("SysMon")) != NULL) {
                _tcscpy_s(channelName, bufferSize, subKeyName);
                RegCloseKey(hKey);
                return;
            }
            index++;
            subKeyNameSize = MAX_KEY_LENGTH;
        }
        RegCloseKey(hKey);
    }

    _tcscpy_s(channelName, bufferSize, TEXT("Microsoft-Windows-Sysmon/Operational"));
}

bool getSysmonConfigPath(TCHAR *configPath, DWORD bufferSize) {
    TCHAR registryKey[MAX_PATH_LENGTH];
    if (!findRegistryKeyWithSysmon(registryKey, MAX_PATH_LENGTH)) {
        TCHAR sysmonPath[MAX_PATH_LENGTH];
        DWORD pathSize = GetSystemDirectory(sysmonPath, MAX_PATH_LENGTH);
        if (pathSize > 0 && pathSize < MAX_PATH_LENGTH) {
            _tcscat_s(sysmonPath, MAX_PATH_LENGTH, TEXT("\\Sysmon.exe"));
            if (GetFileAttributes(sysmonPath) != INVALID_FILE_ATTRIBUTES) {
                _tcscpy_s(configPath, bufferSize, TEXT("Default configuration (no XML file)"));
                return true;
            }

            pathSize = GetWindowsDirectory(sysmonPath, MAX_PATH_LENGTH);
            if (pathSize > 0 && pathSize < MAX_PATH_LENGTH) {
                _tcscat_s(sysmonPath, MAX_PATH_LENGTH, TEXT("\\Sysmon.exe"));
                if (GetFileAttributes(sysmonPath) != INVALID_FILE_ATTRIBUTES) {
                    _tcscpy_s(configPath, bufferSize, TEXT("Default configuration (no XML file)"));
                    return true;
                }
            }
        }
        return false;
    }

    HKEY hKey;
    DWORD dataType;
    DWORD dataSize = bufferSize;

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, registryKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return false;
    }

    LONG result = RegQueryValueEx(hKey, TEXT("ConfigFile"), NULL, &dataType, (LPBYTE)configPath, &dataSize);

    if (result != ERROR_SUCCESS) {
        // Try other common value names
        result = RegQueryValueEx(hKey, TEXT("Configuration"), NULL, &dataType, (LPBYTE)configPath, &dataSize);
    }

    if (result != ERROR_SUCCESS) {
        // Search for any value that could contain a file path
        DWORD valueIndex = 0;
        TCHAR valueName[MAX_VALUE_NAME];
        DWORD valueNameSize = MAX_VALUE_NAME;
        BYTE valueData[MAX_PATH_LENGTH];
        DWORD valueDataSize = MAX_PATH_LENGTH;

        while (RegEnumValue(hKey, valueIndex, valueName, &valueNameSize, NULL, &dataType,
                            valueData, &valueDataSize) == ERROR_SUCCESS) {
            if (dataType == REG_SZ && _tcsstr((TCHAR*)valueData, TEXT(".xml")) != NULL) {
                _tcscpy_s(configPath, bufferSize, (TCHAR*)valueData);
                RegCloseKey(hKey);
                return true;
            }
            valueIndex++;
            valueNameSize = MAX_VALUE_NAME;
            valueDataSize = MAX_PATH_LENGTH;
        }

        _tcscpy_s(configPath, bufferSize, TEXT("Configuration not found in registry"));
    }

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

DWORD getSysmonConfigVersion() {
    TCHAR registryKey[MAX_PATH_LENGTH];
    DWORD version = 0;

    if (!findRegistryKeyWithSysmon(registryKey, MAX_PATH_LENGTH)) {
        return 0;
    }

    HKEY hKey;
    DWORD dataType;
    DWORD dataSize = sizeof(DWORD);

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, registryKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueEx(hKey, TEXT("ConfigVersion"), NULL, &dataType, (LPBYTE)&version, &dataSize) != ERROR_SUCCESS) {
            RegQueryValueEx(hKey, TEXT("Version"), NULL, &dataType, (LPBYTE)&version, &dataSize);
        }
        RegCloseKey(hKey);
    }

    return version;
}

bool findSysmonExecutable(TCHAR *exePath, DWORD bufferSize) {
    // Check system directory first
    DWORD pathSize = GetSystemDirectory(exePath, bufferSize);
    if (pathSize > 0 && pathSize < bufferSize) {
        _tcscat_s(exePath, bufferSize, TEXT("\\Sysmon.exe"));
        if (GetFileAttributes(exePath) != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
    }

    // Check Windows directory
    pathSize = GetWindowsDirectory(exePath, bufferSize);
    if (pathSize > 0 && pathSize < bufferSize) {
        _tcscat_s(exePath, bufferSize, TEXT("\\Sysmon.exe"));
        if (GetFileAttributes(exePath) != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
    }

    // Check PATH environment variable
    TCHAR pathEnv[32767];
    if (GetEnvironmentVariable(TEXT("PATH"), pathEnv, 32767)) {
        TCHAR *context = NULL;
        TCHAR *token = _tcstok_s(pathEnv, TEXT(";"), &context);

        while (token != NULL) {
            _tcscpy_s(exePath, bufferSize, token);
            _tcscat_s(exePath, bufferSize, TEXT("\\Sysmon.exe"));

            if (GetFileAttributes(exePath) != INVALID_FILE_ATTRIBUTES) {
                return true;
            }

            _tcscpy_s(exePath, bufferSize, token);
            _tcscat_s(exePath, bufferSize, TEXT("\\Sysmon64.exe"));

            if (GetFileAttributes(exePath) != INVALID_FILE_ATTRIBUTES) {
                return true;
            }

            token = _tcstok_s(NULL, TEXT(";"), &context);
        }
    }

    return false;
}

bool loadSysmonRules(const TCHAR *configFilePath) {
    TCHAR commandLine[MAX_PATH_LENGTH * 2];
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    TCHAR sysmonPath[MAX_PATH_LENGTH];
    if (!findSysmonExecutable(sysmonPath, MAX_PATH_LENGTH)) {
        return false;
    }

    _stprintf_s(commandLine, MAX_PATH_LENGTH * 2, TEXT("\"%s\" -c \"%s\""), sysmonPath, configFilePath);

    if (!CreateProcess(NULL, commandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        return false;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return (exitCode == 0);
}

void analyzeSysmonActivity() {
    TCHAR channelName[MAX_PATH_LENGTH];
    findSysmonEventLogs(channelName, MAX_PATH_LENGTH);

    HANDLE hEventLog = OpenEventLog(NULL, channelName);
    if (hEventLog == NULL) {
        // Try the default name as fallback
        hEventLog = OpenEventLog(NULL, TEXT("Microsoft-Windows-Sysmon/Operational"));
        if (hEventLog == NULL) {
            printf("Failed to open Sysmon event log\n");
            return;
        }
    }

    DWORD bytesNeeded = 0;
    DWORD recordCount = 0;

    if (GetNumberOfEventLogRecords(hEventLog, &recordCount)) {
        printf("Total Sysmon events: %lu\n", recordCount);
    } else {
        printf("Failed to get Sysmon event count. Error code: %lu\n", GetLastError());
    }

    // Try to get the oldest record time
    DWORD oldestRecord = 0;
    if (GetOldestEventLogRecord(hEventLog, &oldestRecord) && recordCount > 0) {
        printf("Oldest event record number: %lu\n", oldestRecord);
    }

    CloseEventLog(hEventLog);
}

bool isDriverLoaded(const TCHAR *driverName) {
    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scManager) {
        return false;
    }

    SC_HANDLE driverService = OpenService(scManager, driverName, SERVICE_QUERY_STATUS);
    bool result = false;

    if (driverService) {
        SERVICE_STATUS status;
        if (QueryServiceStatus(driverService, &status)) {
            result = (status.dwCurrentState == SERVICE_RUNNING);
        }
        CloseServiceHandle(driverService);
    }

    CloseServiceHandle(scManager);
    return result;
}

void gatherSysmonInfo(SysmonInfo *info) {
    ZeroMemory(info, sizeof(SysmonInfo));

    TCHAR serviceName[MAX_PATH_LENGTH] = {0};
    info->isRunning = isSysmonRunning(serviceName);

    if (info->isRunning) {
        getSysmonDriverName(info->driverName, MAX_PATH_LENGTH, info->driverPath, MAX_PATH_LENGTH);
        getSysmonConfigPath(info->configPath, MAX_PATH_LENGTH);
        info->configVersion = getSysmonConfigVersion();
        info->isDriverLoaded = isDriverLoaded(info->driverName);
    }
}

void printSysmonInfo(const SysmonInfo *info) {
    printf("Sysmon Status:\n");
    printf("-------------\n");
    printf("Is Running: %s\n", info->isRunning ? "Yes" : "No");

    if (info->isRunning) {
        printf("Driver Name: %s\n", info->driverName);
        printf("Driver Path: %s\n", info->driverPath);
        printf("Driver Loaded: %s\n", info->isDriverLoaded ? "Yes" : "No");
        printf("Config Path: %s\n", info->configPath);
        printf("Config Version: %lu\n", info->configVersion);
    } else {
        printf("Sysmon service not detected on this system\n");
    }
}

int main(int argc, char *argv[]) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);

    SysmonInfo info;
    gatherSysmonInfo(&info);
    printSysmonInfo(&info);

    if (info.isRunning) {
        printf("\nAnalyzing Sysmon Activity:\n");
        printf("------------------------\n");
        analyzeSysmonActivity();

        if (argc > 1) {
            printf("\nAttempting to load Sysmon rules from: %s\n", argv[1]);
            if (loadSysmonRules(argv[1])) {
                printf("Successfully loaded Sysmon rules\n");
            } else {
                DWORD error = GetLastError();
                printf("Failed to load Sysmon rules. Error code: %lu\n", error);
                if (error == ERROR_ACCESS_DENIED) {
                    printf("Access denied - Administrator privileges required\n");
                }
            }
        }
    }

    return 0;
}
