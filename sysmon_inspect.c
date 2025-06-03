#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <stdbool.h>
#include <winsvc.h>
#include <strsafe.h> 

#define MAX_PATH_LENGTH 512
#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

typedef struct {
    bool isRunning;
    TCHAR serviceName[MAX_PATH_LENGTH];
    TCHAR driverName[MAX_PATH_LENGTH];
    TCHAR configPath[MAX_PATH_LENGTH];
    TCHAR driverPath[MAX_PATH_LENGTH];
    DWORD configVersion;
    bool isDriverLoaded;
} SysmonInfo;

bool findRegistryKeyWithSysmon(TCHAR *foundKey, DWORD bufferSizeInChars) {
    static const TCHAR* possiblePaths[] = {
        TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Sysmon/Operational"),
        TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"),
        TEXT("SOFTWARE\\Sysinternals\\Sysmon")
    };

    for (int i = 0; i < sizeof(possiblePaths)/sizeof(possiblePaths[0]); i++) {
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, possiblePaths[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            StringCchCopy(foundKey, bufferSizeInChars, possiblePaths[i]);
            RegCloseKey(hKey);
            return true;
        }
    }

    HKEY hSwKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE"), 0, KEY_READ, &hSwKey) == ERROR_SUCCESS) {
        HKEY hSysinternalsKey;
        if (RegOpenKeyEx(hSwKey, TEXT("Sysinternals"), 0, KEY_READ, &hSysinternalsKey) == ERROR_SUCCESS) {
            DWORD index = 0;
            TCHAR subKeyName[MAX_KEY_LENGTH];
            DWORD subKeyNameSize = MAX_KEY_LENGTH;
            while (RegEnumKeyEx(hSysinternalsKey, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                if (_tcsstr(subKeyName, TEXT("Sysmon")) != NULL) {
                    StringCchPrintf(foundKey, bufferSizeInChars, TEXT("SOFTWARE\\Sysinternals\\%s"), subKeyName);
                    RegCloseKey(hSysinternalsKey);
                    RegCloseKey(hSwKey);
                    return true;
                }
                index++;
                subKeyNameSize = MAX_KEY_LENGTH;
            }
            RegCloseKey(hSysinternalsKey);
        }
        RegCloseKey(hSwKey);
    }
    return false;
}

bool findSysmonService(TCHAR *serviceNameOut, DWORD bufferLengthInChars) {
    if (serviceNameOut == NULL || bufferLengthInChars == 0) {
        return false;
    }
    serviceNameOut[0] = _T('\0');

    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scManager) {
        return false;
    }

    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;
    ENUM_SERVICE_STATUS_PROCESS* services = NULL;
    bool found = false;

    EnumServicesStatusEx(scManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                         NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);

    if (GetLastError() != ERROR_MORE_DATA) {
        CloseServiceHandle(scManager);
        return false;
    }

    services = (ENUM_SERVICE_STATUS_PROCESS*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesNeeded);
    if (!services) {
        CloseServiceHandle(scManager);
        return false;
    }

    resumeHandle = 0;
    if (EnumServicesStatusEx(scManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                             (LPBYTE)services, bytesNeeded, &bytesNeeded, &servicesReturned,
                             &resumeHandle, NULL)) {
        for (DWORD i = 0; i < servicesReturned; i++) {
            if (_tcsstr(services[i].lpServiceName, TEXT("Sysmon")) != NULL ||
                (services[i].lpDisplayName && _tcsstr(services[i].lpDisplayName, TEXT("System Monitor")) != NULL)) {
                StringCchCopy(serviceNameOut, bufferLengthInChars, services[i].lpServiceName);
                found = true;
                break;
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, services);
    CloseServiceHandle(scManager);
    return found;
}

bool isSysmonRunning(TCHAR *identifiedServiceName, DWORD serviceNameBufferLenChars) {
    if (identifiedServiceName == NULL || serviceNameBufferLenChars == 0) return false;

    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scManager) {
        identifiedServiceName[0] = _T('\0');
        return false;
    }

    bool result = false;
    TCHAR currentServiceName[MAX_PATH_LENGTH];

    if (identifiedServiceName[0] != _T('\0')) {
         StringCchCopy(currentServiceName, MAX_PATH_LENGTH, identifiedServiceName);
    } else {
        if (!findSysmonService(currentServiceName, MAX_PATH_LENGTH)) {
            StringCchCopy(currentServiceName, MAX_PATH_LENGTH, TEXT("Sysmon"));
        }
    }

    StringCchCopy(identifiedServiceName, serviceNameBufferLenChars, currentServiceName);


    SC_HANDLE sysmonService = OpenService(scManager, currentServiceName, SERVICE_QUERY_STATUS);
    if (sysmonService) {
        SERVICE_STATUS_PROCESS status;
        DWORD bytesNeeded;
        if (QueryServiceStatusEx(sysmonService, SC_STATUS_PROCESS_INFO,
                                 (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
            result = (status.dwCurrentState == SERVICE_RUNNING);
        }
        CloseServiceHandle(sysmonService);
    } else {
         identifiedServiceName[0] = _T('\0'); // Service not found, clear output name
    }

    CloseServiceHandle(scManager);
    return result;
}

bool findSysmonDriverKey(TCHAR *keyPath, DWORD bufferSizeInChars) {
    static const TCHAR* possibleDriverKeys[] = {
        TEXT("SYSTEM\\CurrentControlSet\\Services\\SysmonDrv"),
        TEXT("SYSTEM\\CurrentControlSet\\Services\\Sysmon64"), // Common variation
        TEXT("SYSTEM\\CurrentControlSet\\Services\\Sysmon") // Sometimes just "Sysmon" for the driver
    };

    for (int i = 0; i < sizeof(possibleDriverKeys)/sizeof(possibleDriverKeys[0]); i++) {
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, possibleDriverKeys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            StringCchCopy(keyPath, bufferSizeInChars, possibleDriverKeys[i]);
            RegCloseKey(hKey);
            return true;
        }
    }

    HKEY hServicesKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Services"), 0, KEY_READ, &hServicesKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        TCHAR subKeyName[MAX_KEY_LENGTH];
        DWORD subKeyNameSize = MAX_KEY_LENGTH;
        while (RegEnumKeyEx(hServicesKey, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            if (_tcsstr(subKeyName, TEXT("Sysmon")) != NULL || _tcsstr(subKeyName, TEXT("SysMon")) != NULL) {
                 StringCchPrintf(keyPath, bufferSizeInChars, TEXT("SYSTEM\\CurrentControlSet\\Services\\%s"), subKeyName);
                RegCloseKey(hServicesKey);
                return true;
            }
            index++;
            subKeyNameSize = MAX_KEY_LENGTH;
        }
        RegCloseKey(hServicesKey);
    }
    return false;
}

bool getSysmonDriverInfo(TCHAR *driverName, DWORD driverNameBufferSizeInChars, TCHAR *driverPath, DWORD driverPathBufferSizeInChars) {
    if (driverName == NULL || driverPath == NULL || driverNameBufferSizeInChars == 0 || driverPathBufferSizeInChars == 0) {
        return false;
    }
    driverName[0] = _T('\0');
    driverPath[0] = _T('\0');

    TCHAR keyPath[MAX_PATH_LENGTH];
    if (!findSysmonDriverKey(keyPath, MAX_PATH_LENGTH)) {
        return false;
    }

    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return false;
    }

    const TCHAR *serviceNameFromPath = _tcsrchr(keyPath, _T('\\'));
    if (serviceNameFromPath != NULL) {
        StringCchCopy(driverName, driverNameBufferSizeInChars, serviceNameFromPath + 1);
    } else {
        StringCchCopy(driverName, driverNameBufferSizeInChars, keyPath); // Should not happen for full paths
    }

    DWORD dataType;
    DWORD dataSizeBytes = driverPathBufferSizeInChars * sizeof(TCHAR);
    bool success = false;

    if (RegQueryValueEx(hKey, TEXT("ImagePath"), NULL, &dataType, (LPBYTE)driverPath, &dataSizeBytes) == ERROR_SUCCESS) {
        if ((dataType == REG_SZ || dataType == REG_EXPAND_SZ) && dataSizeBytes > 0) {
             // Ensure null termination if API didn't for some reason or buffer was exact fit without space for null
            if (dataSizeBytes >= driverPathBufferSizeInChars * sizeof(TCHAR)) { // If data filled the buffer
                 driverPath[driverPathBufferSizeInChars - 1] = _T('\0'); // Force null termination
            }
            // Otherwise, API should have null-terminated it if it's REG_SZ/REG_EXPAND_SZ
            success = true;
        } else {
            driverPath[0] = _T('\0'); // Invalid type or empty data
        }
    } else {
        driverPath[0] = _T('\0');
    }

    RegCloseKey(hKey);
    return success;
}

void findSysmonEventLogChannel(TCHAR *channelName, DWORD bufferSizeInChars) {
    if (channelName == NULL || bufferSizeInChars == 0) return;
    channelName[0] = _T('\0');

    HKEY hChannelsKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels"), 0, KEY_READ, &hChannelsKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        TCHAR subKeyName[MAX_PATH_LENGTH]; // Event channel names can be long
        DWORD subKeyNameSize = MAX_PATH_LENGTH;
        while (RegEnumKeyEx(hChannelsKey, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            if (_tcsstr(subKeyName, TEXT("Sysmon")) != NULL || _tcsstr(subKeyName, TEXT("SysMon")) != NULL) {
                StringCchCopy(channelName, bufferSizeInChars, subKeyName);
                RegCloseKey(hChannelsKey);
                return;
            }
            index++;
            subKeyNameSize = MAX_PATH_LENGTH;
        }
        RegCloseKey(hChannelsKey);
    }
    StringCchCopy(channelName, bufferSizeInChars, TEXT("Microsoft-Windows-Sysmon/Operational"));
}

bool getSysmonConfigPath(TCHAR *configPath, DWORD bufferSizeInChars) {
    if (configPath == NULL || bufferSizeInChars == 0) return false;
    configPath[0] = _T('\0');

    TCHAR registryKey[MAX_PATH_LENGTH];
    if (!findRegistryKeyWithSysmon(registryKey, MAX_PATH_LENGTH)) {
        TCHAR sysmonExePathTest[MAX_PATH_LENGTH];
        DWORD pathSize = GetSystemDirectory(sysmonExePathTest, MAX_PATH_LENGTH);
        if (pathSize > 0 && pathSize < MAX_PATH_LENGTH) {
            StringCchCat(sysmonExePathTest, MAX_PATH_LENGTH, TEXT("\\Sysmon.exe"));
            if (GetFileAttributes(sysmonExePathTest) != INVALID_FILE_ATTRIBUTES) {
                StringCchCopy(configPath, bufferSizeInChars, TEXT("Default configuration (Sysmon executable found, no specific XML path in registry)"));
                return true;
            }
        }
        pathSize = GetWindowsDirectory(sysmonExePathTest, MAX_PATH_LENGTH);
         if (pathSize > 0 && pathSize < MAX_PATH_LENGTH) {
            StringCchCat(sysmonExePathTest, MAX_PATH_LENGTH, TEXT("\\Sysmon.exe"));
            if (GetFileAttributes(sysmonExePathTest) != INVALID_FILE_ATTRIBUTES) {
                StringCchCopy(configPath, bufferSizeInChars, TEXT("Default configuration (Sysmon executable found, no specific XML path in registry)"));
                return true;
            }
        }
        StringCchCopy(configPath, bufferSizeInChars, TEXT("Sysmon registry key not found"));
        return false;
    }

    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, registryKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        StringCchCopy(configPath, bufferSizeInChars, TEXT("Failed to open Sysmon registry key"));
        return false;
    }

    DWORD dataType;
    DWORD dataSizeBytes = bufferSizeInChars * sizeof(TCHAR);
    LONG regResult;

    regResult = RegQueryValueEx(hKey, TEXT("ConfigFile"), NULL, &dataType, (LPBYTE)configPath, &dataSizeBytes);
    if (regResult == ERROR_SUCCESS && (dataType == REG_SZ || dataType == REG_EXPAND_SZ) && dataSizeBytes > 0) {
        RegCloseKey(hKey);
        return true;
    }

    dataSizeBytes = bufferSizeInChars * sizeof(TCHAR); // Reset for next call
    regResult = RegQueryValueEx(hKey, TEXT("Configuration"), NULL, &dataType, (LPBYTE)configPath, &dataSizeBytes);
    if (regResult == ERROR_SUCCESS && (dataType == REG_SZ || dataType == REG_EXPAND_SZ) && dataSizeBytes > 0) {
        RegCloseKey(hKey);
        return true;
    }

    DWORD valueIndex = 0;
    TCHAR valueName[MAX_VALUE_NAME];
    DWORD valueNameSize;
    BYTE valueDataBuffer[MAX_PATH_LENGTH * sizeof(TCHAR)]; // Buffer for raw data
    DWORD valueDataSizeBytes;

    while (true) {
        valueNameSize = MAX_VALUE_NAME;
        valueDataSizeBytes = sizeof(valueDataBuffer);
        regResult = RegEnumValue(hKey, valueIndex, valueName, &valueNameSize, NULL, &dataType, valueDataBuffer, &valueDataSizeBytes);
        if (regResult == ERROR_NO_MORE_ITEMS) break;
        if (regResult != ERROR_SUCCESS) {
            valueIndex++;
            continue;
        }

        if (dataType == REG_SZ && valueDataSizeBytes > 0 && _tcsstr((TCHAR*)valueDataBuffer, TEXT(".xml")) != NULL) {
            StringCchCopy(configPath, bufferSizeInChars, (TCHAR*)valueDataBuffer);
            RegCloseKey(hKey);
            return true;
        }
        valueIndex++;
    }

    StringCchCopy(configPath, bufferSizeInChars, TEXT("Configuration path not found in registry values"));
    RegCloseKey(hKey);
    return false;
}

DWORD getSysmonConfigVersion(void) {
    TCHAR registryKey[MAX_PATH_LENGTH];
    DWORD version = 0;

    if (!findRegistryKeyWithSysmon(registryKey, MAX_PATH_LENGTH)) {
        return 0;
    }

    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, registryKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD dataType;
        DWORD dataSize = sizeof(DWORD);
        if (RegQueryValueEx(hKey, TEXT("RulesVersion"), NULL, &dataType, (LPBYTE)&version, &dataSize) == ERROR_SUCCESS) { // Sysmon 15+ uses RulesVersion
            if (dataType != REG_DWORD || dataSize != sizeof(DWORD)) version = 0;
        } else {
            dataSize = sizeof(DWORD); // Reset for next call
            if (RegQueryValueEx(hKey, TEXT("ConfigVersion"), NULL, &dataType, (LPBYTE)&version, &dataSize) == ERROR_SUCCESS) {
                if (dataType != REG_DWORD || dataSize != sizeof(DWORD)) version = 0;
            } else {
                dataSize = sizeof(DWORD); // Reset for next call
                if (RegQueryValueEx(hKey, TEXT("Version"), NULL, &dataType, (LPBYTE)&version, &dataSize) == ERROR_SUCCESS) {
                    if (dataType != REG_DWORD || dataSize != sizeof(DWORD)) version = 0;
                } else {
                     version = 0; // All attempts failed
                }
            }
        }
        RegCloseKey(hKey);
    }
    return version;
}

bool findSysmonExecutablePath(TCHAR *exePath, DWORD bufferSizeInChars) {
    if (exePath == NULL || bufferSizeInChars == 0) return false;
    exePath[0] = _T('\0');

    TCHAR tempPath[MAX_PATH_LENGTH];

    DWORD pathSize = GetSystemDirectory(tempPath, MAX_PATH_LENGTH);
    if (pathSize > 0 && pathSize < MAX_PATH_LENGTH) {
        StringCchCopy(exePath, bufferSizeInChars, tempPath);
        StringCchCat(exePath, bufferSizeInChars, TEXT("\\Sysmon.exe"));
        if (GetFileAttributes(exePath) != INVALID_FILE_ATTRIBUTES) return true;

        StringCchCopy(exePath, bufferSizeInChars, tempPath);
        StringCchCat(exePath, bufferSizeInChars, TEXT("\\Sysmon64.exe"));
        if (GetFileAttributes(exePath) != INVALID_FILE_ATTRIBUTES) return true;
    }

    pathSize = GetWindowsDirectory(tempPath, MAX_PATH_LENGTH);
    if (pathSize > 0 && pathSize < MAX_PATH_LENGTH) {
        StringCchCopy(exePath, bufferSizeInChars, tempPath);
        StringCchCat(exePath, bufferSizeInChars, TEXT("\\Sysmon.exe"));
        if (GetFileAttributes(exePath) != INVALID_FILE_ATTRIBUTES) return true;

        StringCchCopy(exePath, bufferSizeInChars, tempPath);
        StringCchCat(exePath, bufferSizeInChars, TEXT("\\Sysmon64.exe"));
        if (GetFileAttributes(exePath) != INVALID_FILE_ATTRIBUTES) return true;
    }

    // Fallback to SearchPath which checks PATH environment variable among others
    if (SearchPath(NULL, TEXT("Sysmon.exe"), NULL, bufferSizeInChars, exePath, NULL) > 0) {
         if (GetFileAttributes(exePath) != INVALID_FILE_ATTRIBUTES) return true;
    }
    if (SearchPath(NULL, TEXT("Sysmon64.exe"), NULL, bufferSizeInChars, exePath, NULL) > 0) {
         if (GetFileAttributes(exePath) != INVALID_FILE_ATTRIBUTES) return true;
    }

    exePath[0] = _T('\0');
    return false;
}

bool loadSysmonRules(const TCHAR *configFilePath) {
    if (configFilePath == NULL || configFilePath[0] == _T('\0')) {
        return false;
    }
    if (GetFileAttributes(configFilePath) == INVALID_FILE_ATTRIBUTES) {
        return false;
    }

    TCHAR commandLine[MAX_PATH_LENGTH * 2];
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    TCHAR sysmonExePath[MAX_PATH_LENGTH];
    if (!findSysmonExecutablePath(sysmonExePath, MAX_PATH_LENGTH)) {
        return false;
    }

    StringCchPrintf(commandLine, MAX_PATH_LENGTH * 2, TEXT("\"%s\" -c \"%s\""), sysmonExePath, configFilePath);

    bool success = false;
    if (CreateProcess(NULL, commandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exitCode;
        if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
            success = (exitCode == 0);
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return success;
}

void analyzeSysmonEventLogActivity(void) {
    TCHAR channelName[MAX_PATH_LENGTH];
    findSysmonEventLogChannel(channelName, MAX_PATH_LENGTH);

    if (channelName[0] == _T('\0')) {
        _tprintf(TEXT("Could not determine Sysmon event log channel name.\n"));
        return;
    }

    HANDLE hEventLog = OpenEventLog(NULL, channelName);
    if (hEventLog == NULL) {
        _tprintf(TEXT("Failed to open Sysmon event log '%s'. Error code: %lu\n"), channelName, GetLastError());
        // Try the absolute default as a last resort if dynamic finding fails completely
        StringCchCopy(channelName, MAX_PATH_LENGTH, TEXT("Microsoft-Windows-Sysmon/Operational"));
        hEventLog = OpenEventLog(NULL, channelName);
        if (hEventLog == NULL) {
            _tprintf(TEXT("Failed to open default Sysmon event log '%s' as fallback. Error code: %lu\n"), channelName, GetLastError());
            return;
        }
    }

    DWORD recordCount = 0;
    if (GetNumberOfEventLogRecords(hEventLog, &recordCount)) {
        _tprintf(TEXT("Total Sysmon events in '%s': %lu\n"), channelName, recordCount);
    } else {
        _tprintf(TEXT("Failed to get Sysmon event count for '%s'. Error code: %lu\n"), channelName, GetLastError());
    }

    DWORD oldestRecord = 0;
    if (GetOldestEventLogRecord(hEventLog, &oldestRecord) && recordCount > 0) {
        _tprintf(TEXT("Oldest event record number in '%s': %lu\n"), channelName, oldestRecord);
    }
    CloseEventLog(hEventLog);
}

bool isDriverServiceLoaded(const TCHAR *driverSvcName) {
    if (driverSvcName == NULL || driverSvcName[0] == _T('\0')) {
        return false;
    }

    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scManager) {
        return false;
    }

    SC_HANDLE driverService = OpenService(scManager, driverSvcName, SERVICE_QUERY_STATUS);
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

void gatherSysmonInformation(SysmonInfo *info) {
    if (info == NULL) return;
    ZeroMemory(info, sizeof(SysmonInfo));

    info->serviceName[0] = _T('\0'); // Initialize for isSysmonRunning to find it
    info->isRunning = isSysmonRunning(info->serviceName, MAX_PATH_LENGTH);

    if (info->isRunning && info->serviceName[0] != _T('\0')) {
        getSysmonDriverInfo(info->driverName, MAX_PATH_LENGTH, info->driverPath, MAX_PATH_LENGTH);
        getSysmonConfigPath(info->configPath, MAX_PATH_LENGTH);
        info->configVersion = getSysmonConfigVersion();
        if(info->driverName[0] != _T('\0')) {
            info->isDriverLoaded = isDriverServiceLoaded(info->driverName);
        }
    }
}

void printSysmonInformation(const SysmonInfo *info) {
    if (info == NULL) return;
    _tprintf(TEXT("Sysmon Status:\n"));
    _tprintf(TEXT("--------------\n"));
    _tprintf(TEXT("Is Running: %s\n"), info->isRunning ? TEXT("Yes") : TEXT("No"));
    if (info->isRunning) {
        _tprintf(TEXT("Service Name: %s\n"), info->serviceName[0] != _T('\0') ? info->serviceName : TEXT("N/A"));
    }

    if (info->driverName[0] != _T('\0')) {
        _tprintf(TEXT("Driver Name: %s\n"), info->driverName);
        _tprintf(TEXT("Driver Path: %s\n"), info->driverPath[0] != _T('\0') ? info->driverPath : TEXT("N/A"));
        _tprintf(TEXT("Driver Loaded: %s\n"), info->isDriverLoaded ? TEXT("Yes") : TEXT("No"));
    } else if (info->isRunning) {
        _tprintf(TEXT("Driver Name: Not Found\n"));
    }

    if (info->configPath[0] != _T('\0')) {
         _tprintf(TEXT("Config Path: %s\n"), info->configPath);
    } else if (info->isRunning) {
         _tprintf(TEXT("Config Path: Not Found\n"));
    }

    if (info->isRunning) {
        _tprintf(TEXT("Config Version: %lu\n"), info->configVersion);
    }


    if (!info->isRunning) {
        _tprintf(TEXT("Sysmon service not detected or not running on this system.\n"));
    }
}

int _tmain(int argc, _TCHAR *argv[]) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);

    SysmonInfo info;
    gatherSysmonInformation(&info);
    printSysmonInformation(&info);

    if (info.isRunning) {
        _tprintf(TEXT("\nAnalyzing Sysmon Event Log Activity:\n"));
        _tprintf(TEXT("-----------------------------------\n"));
        analyzeSysmonEventLogActivity();

        if (argc > 1) {
            _tprintf(TEXT("\nAttempting to load Sysmon rules from: %s\n"), argv[1]);
            if (loadSysmonRules(argv[1])) {
                _tprintf(TEXT("Successfully initiated Sysmon rules loading.\n"));
                 _tprintf(TEXT("Re-gather information to see changes if any immediately visible (e.g. config version):\n"));
                gatherSysmonInformation(&info); // Re-gather after potential update
                printSysmonInformation(&info);
            } else {
                DWORD error = GetLastError();
                _tprintf(TEXT("Failed to load Sysmon rules. Error code: %lu\n"), error);
                if (error == ERROR_ACCESS_DENIED) {
                    _tprintf(TEXT("Access denied - Administrator privileges are required to modify Sysmon configuration.\n"));
                } else if (error == ERROR_FILE_NOT_FOUND && argc > 1 && GetFileAttributes(argv[1]) == INVALID_FILE_ATTRIBUTES) {
                    _tprintf(TEXT("The specified configuration file '%s' was not found.\n"), argv[1]);
                }
            }
        }
    }
    return 0;
}
