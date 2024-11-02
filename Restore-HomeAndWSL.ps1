<#
.SYNOPSIS
    Restore script for encrypted Windows and WSL backups created by Backup-HomeAndWSL.ps1.

.DESCRIPTION
    This script restores backups created by the Backup-HomeAndWSL.ps1 script.
    Features include:
    - Restore to custom location
    - Optionally restore/overwrite home directories and files
    - Optionally import WSL distributions
    - Split archive support
    - Backup verification before restore
    - Detailed logging
    - Error handling and notifications

    Restore structure:
    RestoreLocation (default: %USERPROFILE%\BackupRestore)
    ├── home
    │   ├── .ssh
    │   ├── Saved Games
    │   ├── .vscode
    │   ├── .gitconfig
    │   └── ... (other backed up items)
    └── wsl
        └── ... (WSL distribution backups)

.NOTES
    File Name      : Restore-HomeAndWSL.ps1
    Prerequisite   : - PowerShell 5.1 or later
                    - 7-Zip installed
                    - WSL (optional, for WSL restores)
                    - Original backup password

.PARAMETER BackupPath
    The path to the encrypted backup files to restore.

.PARAMETER ConfigPath
    Optional. The path to the backup-config.yml file.
    Default: ./backup-config.yml

.PARAMETER RestoreLocation
    Optional. The directory where files will be restored.
    Default: $env:USERPROFILE\BackupRestore

.PARAMETER OverwriteHome
    Optional. Overwrite existing home directories and files with restored items (Dangerous).

.PARAMETER ImportWSL
    Optional. Import WSL distributions.

.EXAMPLE
    # Restore to default location
    ./restore-backup.ps1 -BackupPath "C:\path\to\backup\2024-11-01_08-24"

    # Restore to custom location
    ./restore-backup.ps1 -BackupPath "C:\path\to\backup\2024-11-01_08-24" -RestoreLocation "D:\CustomRestore"

Copyright (c) 2024, Chris Hamilton
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$BackupPath,
    
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = "backup-config.yml",
    
    [Parameter(Mandatory=$false)]
    [string]$RestoreLocation = "$env:USERPROFILE\BackupRestore",
    
    [Parameter(Mandatory=$false)]
    [switch]$OverwriteHome,

    [Parameter(Mandatory=$false)]
    [switch]$ImportWSL
)

# Initialize error collection
$restoreErrors = @()

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Output to console with color coding
    switch ($Level) {
        'Info'    { Write-Host $logMessage -ForegroundColor Green }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
    }
    
    # Append to log file
    $logFile = Join-Path $PSScriptRoot "restore.log"
    $logMessage | Out-File -FilePath $logFile -Append
    
    # Collect errors
    if ($Level -in @('Error')) {
        $script:restoreErrors += "$Level`: $Message"
    }
}

function Send-ToastNotification {
    param(
        [string]$Title,
        [string]$Message
    )
    
    if (-not $configBackup.Notifications.Toast.Enable) {
        return
    }

    try {
        powershell {

        # Toast notification template
        $template = @"
<toast>
    <visual>
        <binding template="ToastGeneric">
            <text>$Title</text>
            <text>$Message</text>
        </binding>
    </visual>
</toast>
"@
            # Load Windows Runtime assemblies
            $null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
            $null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
            
            # Register AppId in the registry for notifications
            $appId = "Backup Script"
            $regPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"
            $appRegPath = "$regPath\$appId"
            
            if (-not (Test-Path $appRegPath)) {
                New-Item -Path $appRegPath -Force | Out-Null
                New-ItemProperty -Path $appRegPath -Name "ShowInActionCenter" -Value 1 -PropertyType DWORD -Force | Out-Null
            }
        
            # Create and show notification
            $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
            $xml.LoadXml($template)
            $toast = New-Object Windows.UI.Notifications.ToastNotification($xml)
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
        }
        Write-Log "Sent toast notification" -Level Info
    }
    catch {
        Write-Log "Failed to send toast notification: $_" -Level Error
        
        # Fallback to standard Windows notification
        try {
            Add-Type -AssemblyName System.Windows.Forms
            $global:balloon = New-Object System.Windows.Forms.NotifyIcon
            $balloon.Icon = [System.Drawing.SystemIcons]::Information
            $balloon.Visible = $true
            $balloon.ShowBalloonTip(
                5000,
                $Title,
                $Message,
                [System.Windows.Forms.ToolTipIcon]::Info
            )
            Start-Sleep -Seconds 1  # Keep balloon alive briefly
            $balloon.Dispose()
        }
        catch {
            Write-Log "Failed to send fallback notification: $_" -Level Error
        }
    }
}

function Send-ErrorNotification {
    param(
        [string[]]$ErrorMessages,
        [string]$BackupPath
    )
    
    if ($ErrorMessages.Count -eq 0) {
        return
    }

    # Send toast notification
    if ($configBackup.Notifications.Toast.Enable) {
        Send-ToastNotification -Title "Backup Warning - $computerName" -Message "Backup completed with $($ErrorMessages.Count) warnings/errors"
    }
}

# Function to get or create encryption password
function Get-Password {
    param(
        [string]$PasswordFile
    )
    
    if (Test-Path $PasswordFile) {
        $encryptedPassword = Get-Content $PasswordFile
        try {
            $securePassword = ConvertTo-SecureString $encryptedPassword
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
            return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        }
        catch {
            Write-Log "Stored password is invalid. Requesting new password."
        }
    }
    return ""
}

# Install and import PowerShell-Yaml module if not present
if (-not (Get-Module -ListAvailable -Name PowerShell-Yaml)) {
    Write-Host "Installing PowerShell-Yaml module..."
    Install-Module -Name PowerShell-Yaml -Force -Scope CurrentUser
}
Import-Module PowerShell-Yaml

# Load and validate configuration
function Get-ValidatedConfig {
    param([string]$ConfigPath)
    
    if (-not (Test-Path $ConfigPath)) {
        throw "Configuration file not found: $ConfigPath"
    }
    
    try {
        $config = Get-Content $ConfigPath -Raw | ConvertFrom-Yaml
        
        # Validate required settings
        $requiredSettings = @{
            'BackupRoot' = { param($c) $c.BackupRoot }
            'TempBackupDir' = { param($c) $c.TempBackupDir }
            'Tools.SevenZip' = { param($c) $c.Tools.SevenZip }
        }
        
        # Validate each required setting
        foreach ($setting in $requiredSettings.Keys) {
            $value = & $requiredSettings[$setting] $config
            if ($null -eq $value) {
                throw "Missing required configuration: $setting"
            }
        }
        
        # Expand environment variables in paths
        $config.BackupRoot = [Environment]::ExpandEnvironmentVariables($config.BackupRoot)

        # Get computer name for backup organization
        $computerName = $env:COMPUTERNAME.ToLower()
        $config.BackupRoot = Join-Path $config.BackupRoot $computerName

        $config.TempBackupDir = [Environment]::ExpandEnvironmentVariables($config.TempBackupDir)
        $config.Tools.SevenZip = [Environment]::ExpandEnvironmentVariables($config.Tools.SevenZip)
        

        $config.BackupPasswordPath = [Environment]::ExpandEnvironmentVariables($config.BackupPasswordPath)
        # Check for BackupPasswordPath and whether it already exists, if not prompt to securely generate it
        $config.BackupPassword = Get-Password -PasswordFile $config.BackupPasswordPath

        return $config
    }
    catch {
        throw "Error loading configuration: $($_.Exception.Message)"
    }
}

# Load configuration
try {
    $configBackup = Get-ValidatedConfig -ConfigPath $ConfigPath
    Write-Log "Loaded configuration from $ConfigPath" -Level Info
}
catch {
    Write-Log "Failed to load configuration: $_" -Level Error
    throw
}

# Check for 7-Zip installation
$7zipPath = $configBackup.Tools.SevenZip
if (-not (Test-Path $7zipPath)) {
    Write-Log "7-Zip is not installed in the default location. Please install 7-Zip first." -Level Error
    throw "7-Zip not found"
}

# Add verification function for restore
function Test-RestoreArchive {
    param(
        [string]$ArchivePath,
        [string]$Password
    )
    
    # Check if this is a split archive
    $volumeFiles = Get-ChildItem -Path "$ArchivePath.*" -ErrorAction SilentlyContinue
    
    if ($volumeFiles) {
        # For split archives, use the first volume file
        $firstVolume = $volumeFiles | Sort-Object Name | Select-Object -First 1
        $testFile = $firstVolume.FullName
        Write-Log "Testing split archive using first volume: $testFile" -Level Info
    } elseif (Test-Path $ArchivePath) {
        # For single file archives, use the base file
        $testFile = $ArchivePath
        Write-Log "Testing single file archive: $testFile" -Level Info
    } else {
        Write-Log "No archive files found at $ArchivePath" -Level Error
        return $false
    }
    
    $testArgs = @(
        't'  # Test archive
        "$testFile"
        "-p$Password"
    )
    
    Write-Log "Testing archive: $testFile" -Level Info
    & $7zipPath $testArgs
    
    if ($LASTEXITCODE -eq 0) {
        Write-Log "Archive verification successful" -Level Info
        return $true
    } else {
        Write-Log "Archive verification failed (Exit code: $LASTEXITCODE)" -Level Error
        return $false
    }
}

# Main restore function
function Restore-Backup {
    param(
        [string]$BackupPath,
        [string]$RestoreLocation,
        [string]$Password,
        [switch]$RestoreHome,
        [switch]$RestoreWSL,
        [switch]$OverwriteHome,
        [switch]$ImportWSL
    )
    
    Write-Log "Starting restore from: $BackupPath" -Level Info
    Write-Log "Restore location: $RestoreLocation" -Level Info
    
    # Create restore directory
    New-Item -ItemType Directory -Path $RestoreLocation -Force | Out-Null
    Write-Log "Created restore directory: $RestoreLocation" -Level Info
    
    try {
        # Restore Home Items
        if ($RestoreHome) {
            $homeBackupFile = Join-Path $BackupPath "backup.7z"
            Write-Log "Restoring home items from: $homeBackupFile" -Level Info
            
            if (Test-RestoreArchive -ArchivePath $homeBackupFile -Password $Password) {
                # Get the first volume if split archive
                $volumeFiles = Get-ChildItem -Path "$homeBackupFile.*" -ErrorAction SilentlyContinue
                $extractFile = if ($volumeFiles) {
                    ($volumeFiles | Sort-Object Name | Select-Object -First 1).FullName
                } else {
                    $homeBackupFile
                }
                
                $homeRestoreDir = Join-Path $RestoreLocation "home"
                New-Item -ItemType Directory -Path $homeRestoreDir -Force | Out-Null
                
                # Extract to restore directory
                $extractArgs = @(
                    'x'                     # Extract with full paths
                    "$extractFile"          # Archive to extract
                    "-p$Password"           # Password
                    "-o$homeRestoreDir"     # Output directory
                    '-y'                    # Yes to all prompts
                )
                
                Write-Log "Extracting home backup..." -Level Info
                & $7zipPath $extractArgs
                
                if ($LASTEXITCODE -eq 0) {
                    if ($OverwriteHome) {
                        Write-Log "OVERWRITE MODE: Restoring directories and files to original locations" -Level Warning
                        foreach ($item in $configBackup.HomeItems) {
                            $sourcePath = Join-Path $homeRestoreDir (Split-Path $item -Leaf)
                            if (Test-Path $sourcePath) {
                                $itemInfo = Get-Item $sourcePath
                                if ($itemInfo.PSIsContainer) {
                                    # Existing directory restore code
                                    Write-Log "Restoring directory to: $item" -Level Info
                                    
                                    $robocopyArgs = @(
                                        $sourcePath
                                        $item
                                        '/E'        # Copy subdirectories
                                        '/Z'        # Restartable mode
                                        '/B'        # Backup mode
                                        '/R:3'      # Retries
                                        '/W:5'      # Wait time
                                        '/NFL'      # No File List
                                        '/NDL'      # No Directory List
                                        '/NP'      # No Progress
                                    )
                                    
                                    & robocopy @robocopyArgs
                                    
                                    switch ($LASTEXITCODE) {
                                        { $_ -lt 8 } {
                                            Write-Log "Successfully restored to $item" -Level Info
                                        }
                                        { $_ -eq 8 -or $_ -eq 9 } {
                                            Write-Log "Some files in $item could not be restored (access denied/locks)" -Level Warning
                                        }
                                        default {
                                            Write-Log "Error restoring to $item. Exit code: $LASTEXITCODE" -Level Error
                                        }
                                    }
                                } else {
                                    # Simple file copy using same overwrite logic
                                    $targetPath = if ($OverwriteHome) {
                                        $item  # Original location
                                    } else {
                                        Join-Path $RestoreLocation (Split-Path $item -Leaf)
                                    }
                                    
                                    try {
                                        Copy-Item -Path $sourcePath -Destination $targetPath -Force
                                        Write-Log "Successfully restored file to $targetPath" -Level Info
                                    }
                                    catch {
                                        Write-Log "Error restoring file to $targetPath`: $_" -Level Error
                                    }
                                }
                            }
                        }
                    } else {
                        Write-Log "Extracted home directories to: $homeRestoreDir" -Level Info
                        Write-Log "Use -OverwriteHome switch to restore to original locations" -Level Info
                    }
                }
            }
        }
        
        # Restore WSL Distributions
        if ($RestoreWSL) {
            Write-Log "Looking for WSL backups..." -Level Info
            $wslBackups = Get-ChildItem -Path $BackupPath -Filter "wsl-*.7z"
            
            foreach ($wslBackup in $wslBackups) {
                $distroName = $wslBackup.Name -replace '^wsl-(.+)\.7z$','$1'
                Write-Log "Found WSL backup for distribution: $distroName" -Level Info
                
                $wslRestoreDir = Join-Path $RestoreLocation "wsl\$distroName"
                New-Item -ItemType Directory -Path $wslRestoreDir -Force | Out-Null
                
                if (Test-RestoreArchive -ArchivePath $wslBackup.FullName -Password $Password) {
                    # Get the first volume if split archive
                    $volumeFiles = Get-ChildItem -Path "$($wslBackup.FullName).*" -ErrorAction SilentlyContinue
                    $extractFile = if ($volumeFiles) {
                        ($volumeFiles | Sort-Object Name | Select-Object -First 1).FullName
                    } else {
                        $wslBackup.FullName
                    }
                    
                    # Extract WSL backup
                    $extractArgs = @(
                        'x'
                        $extractFile
                        "-p$Password"
                        "-o$wslRestoreDir"
                        '-y'
                    )
                    
                    Write-Log "Extracting WSL backup for $distroName..." -Level Info
                    & $7zipPath $extractArgs
                    
                    if ($LASTEXITCODE -eq 0) {
                        $tarFile = Get-ChildItem -Path $wslRestoreDir -Filter "*.tar" | Select-Object -First 1
                        
                        if ($tarFile) {
                            if ($ImportWSL) {
                                Write-Log "IMPORT MODE: Importing WSL distribution $distroName" -Level Warning
                                $importCommand = "wsl.exe --import `"$distroName`" `"$env:LOCALAPPDATA\WSL\$distroName`" `"$($tarFile.FullName)`" --version 2"
                                Write-Log "Running: $importCommand" -Level Info
                                
                                Invoke-Expression $importCommand
                                
                                if ($LASTEXITCODE -eq 0) {
                                    Write-Log "Successfully imported WSL distribution: $distroName" -Level Info
                                } else {
                                    Write-Log "Failed to import WSL distribution: $distroName" -Level Error
                                }
                            } else {
                                Write-Log "Extracted WSL distribution to: $wslRestoreDir" -Level Info
                                Write-Log "Use -ImportWSL switch to import the distribution to WSL" -Level Info
                            }
                        } else {
                            Write-Log "No tar file found in extracted WSL backup for $distroName" -Level Error
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-Log "Error during restore: $_" -Level Error
    }
}

# Main script execution
try {
    Write-Log "Starting restore process..." -Level Info
    Write-Log "Backup path: $BackupPath" -Level Info
    Write-Log "Restore location: $RestoreLocation" -Level Info
    if ($OverwriteHome) { Write-Log "WARNING: Will overwrite original home directories and files" -Level Warning }
    if ($ImportWSL) { Write-Log "WARNING: Will import WSL distributions" -Level Warning }

    # Verify backup path exists
    if (-not (Test-Path $BackupPath)) {
        throw "Backup path not found: $BackupPath"
    }
    
    # Get restore options from user if not specified
    $restoreHome = Read-Host "Restore home directories? (y/n)"
    $restoreWSL = Read-Host "Restore WSL distributions? (y/n)"
    
    # Get password if not specified in config
    if ($configBackup.BackupPassword -eq "") {
        $securePassword = Read-Host "Enter backup password" -AsSecureString
        $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
        )
    } else {
        $password = $configBackup.BackupPassword
    }
    
    # Perform restore
    Restore-Backup  -BackupPath $BackupPath -Password $password `
                    -RestoreLocation $RestoreLocation `
                    -RestoreHome:($restoreHome -eq 'y') `
                    -RestoreWSL:($restoreWSL -eq 'y') `
                    -OverwriteHome:($OverwriteHome) `
                    -ImportWSL:($ImportWSL)
        
    if ($restoreErrors.Count -eq 0) {
        Write-Log "Restore completed successfully" -Level Info
    } else {
        Write-Log "Restore completed with $($restoreErrors.Count) errors" -Level Warning
    }
}
catch {
    Write-Log "Critical error during restore: $_" -Level Error
}
finally {
    if ($restoreErrors.Count -gt 0) {
        Send-ErrorNotification -ErrorMessages $restoreErrors -BackupPath $BackupPath
    }
}

if ($LASTEXITCODE -eq 0) {
    Write-Host "Backup restored successfully to: $RestoreLocation"
}
else {
    Write-Host "Error restoring backup. Please check the password and try again."
}
