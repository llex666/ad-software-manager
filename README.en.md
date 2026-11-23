# AD Software Manager

An interactive PowerShell console (`sconfig`-style menu) to **inventory and uninstall installed programs and apps** on all computers of an Active Directory domain: workstations, servers and virtual machines.

> [Русская версия](README.md)

## What is listed

- Programs from the `Uninstall` registry keys: `HKLM` (x64 and x86) and `HKU\<SID>` for **all user profiles** (unloaded `NTUSER.DAT` files are loaded temporarily).
- **Microsoft Store (Appx)** apps for all users.
- Name, version, publisher, size, install date, source.
- System components, updates and framework packages are hidden by default (key `S`).

## Features

- Separate tables for **user computers** and **servers / VMs** (by AD `OperatingSystem`).
- Choose what to scan: all / user computers / servers, or **individual OUs** (including child OUs). Results accumulate.
- **Progress bar** and `Esc` to abort.
- Summary view "program → how many computers" with the number of versions.
- **Uninstall by name** (with a version filter, wildcards like `11.*` allowed) from all or selected computers; per-row selection in `Out-GridView`.
- `YES` confirmation, a log (including the uninstall command), CSV export, unreachable-computer list.

## How uninstall works

| Entry type | Command |
|------------|---------|
| MSI | `msiexec /x {GUID} /qn /norestart` |
| Has `QuietUninstallString` | that string is executed |
| Inno Setup (`unins000.exe`) | `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART` is appended |
| Store app | `Remove-AppxPackage -AllUsers`; if the package remains (e.g. error `0x80073D19`) it is removed per user; optionally also from the system image. Success is verified by checking that the package is gone |
| Everything else | only if you supply extra arguments (e.g. `/S`); otherwise skipped |

Every uninstall has a time limit (`-UninstallTimeoutSec`, 900 s by default); a hung process is killed. Exit code `3010` means "reboot required"; the script never reboots computers.

## Requirements

- Windows PowerShell 5.1 (PowerShell 7 has not been tested).
- **ActiveDirectory** module (RSAT).
- Administrator rights on the target computers.
- **WinRM (TCP 5985)** enabled on the targets. There is no DCOM fallback.
- `Out-GridView` is needed for manual row selection.

## Quick start

```powershell
git clone https://github.com/llex666/ad-software-manager.git
cd ad-software-manager

powershell -ExecutionPolicy Bypass -File .\Manage-DomainSoftware.ps1
# or
.\Manage-DomainSoftware.ps1 -Domain corp.example.com -StaleDays 60 -UninstallTimeoutSec 600
```

The program **shows the menu first**; scanning starts with item `1`.

## Parameters

| Parameter              | Default                    | Description                                                   |
|------------------------|----------------------------|---------------------------------------------------------------|
| `-Domain`              | `$env:USERDNSDOMAIN`       | DNS name of the AD domain                                     |
| `-StaleDays`           | `90`                       | Skip computers that have not logged on to the domain for N days |
| `-UninstallTimeoutSec` | `900`                      | Maximum seconds for a single uninstall                        |

## Menu

The menu is displayed in Russian (see the Russian README for a sample). Items: scan (1), computer type (2), OU (3), clear (C), clients (4), servers (5), summary (6), unreachable (U), uninstall by name (7), pick rows and uninstall (8), toggle system components (S), toggle Store apps (A), CSV export (E), exit (0).

## Safety and limitations

- **Uninstalling is irreversible.** Test on a pilot OU, and on a single computer for programs that need their own silent switches.
- Per-user installs may fail to uninstall in the administrator context.
- Pressing `Esc` during an uninstall stops waiting, but uninstall processes already started on computers keep running.
- The log (`DomainSoftwareManager.log`) and CSV files contain computer and user names. Do not publish them (they are in `.gitignore`).
- Use at your own risk (see the license).

## Related projects

- [AD Scheduled Tasks Manager](https://github.com/llex666/ad-tasks-manager): scheduled tasks.
- [AD Startup Manager](https://github.com/llex666/ad-startup-manager): startup entries.

## License

[MIT](LICENSE)
