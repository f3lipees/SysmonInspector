# Features

- Identifies Sysmon service and driver even when renamed or placed in non-standard locations.
- Locates and reports configuration file paths and version information.
- Dynamically searches various registry paths to find Sysmon components.
- Retrieves critical information about the Sysmon driver, useful for kernel-level analysis.
- Reports on Sysmon event logs including total event count and record information.
- Supports loading custom Sysmon rule configurations (requires administrator privileges).
- Works across different Windows versions with adaptive registry path detection.
  
| -- - -- - -- - - - - - -- - - - - - -- - - - - - - - - - - -  - - - - - - -- - - - - - -- - - - -|

- SysmonInspector employs a multi-layered detection approach:

- Queries the Service Control Manager for services with names or display names containing "Sysmon" or "System Monitor"
- Examines both standard and non-standard registry locations where Sysmon might store configuration information
- Searches for Sysmon executables across system directories and PATH locations
- Confirms the presence and loading status of the Sysmon driver in the kernel

![sysimage](https://github.com/user-attachments/assets/a2db459a-f7bc-4e5e-b52e-38d6c4c2d123)

# Compilation

- Using Visual Studio
  
      cl sysmon_inspect.c /link advapi32.lib

- Using MinGW
  
      gcc -o sysmon_inspect.exe sysmon_inspector.c -ladvapi32

# Registry Keys Examined

- The tool examines multiple registry locations including:

          SYSTEM\CurrentControlSet\Services\SysmonDrv
          SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational
          SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{5770385f-c22a-43e0-bf4c-06f5698ffbd9}
          SOFTWARE\Sysinternals\Sysmon

- Additionally, it performs dynamic searches for similarly named keys that might indicate Sysmon installations with different names.

# Future improvements

- [ ] Remote system analysis capabilities.
- [ ] Statistical analysis of Sysmon events and performance.

# Contributing

- We value the contribution made by the community, feel free to add improvements or suggestions.
