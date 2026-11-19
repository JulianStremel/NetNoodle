# Design: nn-agent on Windows

Status: in progress (collectors), proposal (service, matching). Refer to D-042.

## 1. Goal

`nn-agent` reports Windows hosts with the same protocol, the same server rules and the same least-privilege principle as Linux hosts.

## 2. Collectors

The collector list depends on the operating system. On Windows, `collectors::all()` returns these collectors:

| Collector | Data | Source (read only) |
|---|---|---|
| `os` | Product name, release (`DisplayVersion`), build and UBR, edition, client or server, VM detection, machine GUID | Registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, `HKLM\HARDWARE\DESCRIPTION\System\BIOS`, `HKLM\SOFTWARE\Microsoft\Cryptography` |
| `programs` | Installed programs (name, version, publisher, install location) | Registry `...\CurrentVersion\Uninstall` (64-bit and `WOW6432Node`) |
| `sockets` | Listening TCP and unconnected UDP sockets, owning process and program | `GetExtendedTcpTable`, `GetExtendedUdpTable`, `QueryFullProcessImageNameW`, Service Control Manager |
| `interfaces` | Adapters, MAC addresses, IP addresses | `GetAdaptersAddresses` |

Windows 11 reports `ProductName = "Windows 10 ..."`. The collector corrects the name when the build is 22000 or higher.

### 2.1 Package URLs

- Operating system: `pkg:generic/microsoft/windows@10.0.<build>.<ubr>?edition=<EditionID>&release=<DisplayVersion>&type=client|server`. A later MSRC matcher uses this component.
- Programs: `pkg:generic/<name>@<version>?publisher=<publisher>&arch=x64|x86`.

OSV has no data for these types. The `osv` matcher ignores them, so they give no false findings.

### 2.2 Program of a socket without administrator rights

1. `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` and `QueryFullProcessImageNameW`. This works for most processes of other users. It does not work for protected processes.
2. If step 1 fails: the Service Control Manager gives the process ID of each running service (`EnumServicesStatusExW`) and its binary path (`QueryServiceConfigW`). Authenticated users can read both. For `svchost.exe`, the service DLL comes from `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\ServiceDll`.
3. PID 4 (`System`) owns kernel listeners such as SMB (445) and `http.sys`.

This is the Windows equivalent of the cgroup method on Linux. No helper is necessary.

The `programs` collector maps an executable path to a program when the path is in the program's `InstallLocation`.

## 3. Operation

- Default paths: `C:\ProgramData\netnoodle\agent\config.json` and `C:\ProgramData\netnoodle\agent\credentials.json`.
- First version: a scheduled task runs `nn-agent run --once` each hour as `NT AUTHORITY\LOCAL SERVICE`. The credentials directory has an ACL for that account and for administrators only.
- Later: a Windows service (`windows-service` crate) with a virtual service account (`NT SERVICE\nn-agent`).
- Pull mode with the Windows OpenSSH server works as on Linux (refer to [pull-mode.md](pull-mode.md)).

## 4. Vulnerability matching (proposal)

- Windows itself: an `msrc` matcher reads the Microsoft Security Update Guide (CVRF API). It compares build and UBR with the fixed builds of each CVE.
- Third-party programs: no free database maps Windows program names to vulnerabilities reliably. Options: NVD CPE matching (needs an API key, gives false positives) or winget package IDs with a curated mapping. Decision later.
