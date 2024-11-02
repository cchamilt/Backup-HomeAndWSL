# Backup-HomeAndWSL

## Windows Home and Windows Subsystem for Linux (WSL) Backup Scripts

PowerShell scripts for backing up Windows home directories, individual files, and WSL distributions with encryption and cloud storage support.

## Features

- 🔐 Encrypted 7-Zip archive creation
- 📦 Automatic archive splitting for cloud storage compatibility
- 🐧 WSL distribution backup and restore
- 🏠 Configurable home directory backup
- 🔄 Backup rotation with configurable retention
- ✅ Backup verification
- 📧 Email notifications for errors
- 🔔 Windows toast notifications
- 📝 Detailed logging
- 🔒 Secure password management

## Prerequisites

- Windows 10/11
- PowerShell 5.1 or later
- [7-Zip](https://www.7-zip.org/) installed
- [WSL](https://learn.microsoft.com/en-us/windows/wsl/install) (optional, for WSL backups)
- [PowerShell-Yaml](https://github.com/cloudbase/powershell-yaml) module

## Installation

1. Clone this repository:

``` powershell
git clone https://github.com/cchamilt/Backup-HomeAndWSL.git

#Optional: move to a directory you want to keep the files in
Move-Item .\Backup-HomeAndWSL -Destination "%USERPROFILE%\OneDrive\PCBackup\scripts"
```

2. Import the PowerShell-Yaml module:

``` powershell
Import-Module powershell-yaml -Scope CurrentUser
```

3. Copy the example configuration:

``` powershell
Copy-Item .\backup-config.yml.example .\backup-config.yml
```

4. Edit the configuration file to set your desired paths and options.

## Usage

To run the script manually/initialise passwords:

``` powershell
.\Backup-HomeAndWSL.ps1
```

To run the script as a scheduled task:

``` powershell
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PWD\Backup-HomeAndWSL.ps1`""
$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2am
$Principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Password -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "Weekly PC Backup" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Description "Weekly backup of home directory and WSL distributions to OneDrive"
```

## Configuration

Example configuration (backup-config.yml):

```yaml
# Paths to backup (both files and directories)
HomeItems:
  - "C:/Users/username/Documents"          # Directory
  - "C:/Users/username/Pictures"           # Directory
  - "C:/Users/username/.gitconfig"         # File
  - "C:/Users/username/.ssh/config"        # File
```

## Backup Structure

```
BackupRoot
└── computername
    └── 2024-01-20_14-30
        ├── backup.7z.001              # Contains both directories and individual files
        ├── backup.7z.002
        ├── wsl-ubuntu.7z
        ├── verification.txt
        └── backup_summary.txt
```

## Restore

Safe restore (to separate location):

```powershell
.\Restore-HomeAndWSL.ps1 -BackupPath "C:\path\to\backup\2024-01-20_14-30"
```

Restore with overwrite (both files and directories):

```powershell
.\Restore-HomeAndWSL.ps1 -BackupPath "C:\path\to\backup\2024-01-20_14-30" -OverwriteHomeDirectories
```

## License

BSD 3-Clause License. See LICENSE file for details.
