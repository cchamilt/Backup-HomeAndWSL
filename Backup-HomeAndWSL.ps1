<#
.SYNOPSIS
    Backup script for Windows home directories, individual files, and WSL distributions.

.DESCRIPTION
    This script creates encrypted backups of specified Windows directories and files,
    as well as WSL distributions. Features include:
    - Encrypted 7-zip archive creation
    - Configurable directory inclusion/exclusion
    - WSL distribution export and backup
    - Backup rotation (keeps last N backups)
    - File size limits for OneDrive compatibility
    - Automatic archive splitting for cloud storage
    - Backup verification
    - Password management
    - Detailed logging
    - Email/toast notifications for errors
    
    Backup structure:
    BackupRoot
    └── computername
        └── 2024-01-20_14-30
            ├── wsl-ubuntu.7z.00x
            ├── wsl-ubuntu.txt
            ├── wsl-debian.7z
            ├── wsl-debian.txt
            ├── backup.7z.0xx (contains home directory backups)
            └── verification.txt

.NOTES
    File Name      : Backup-HomeAndWSL.ps1
    Prerequisite   : - PowerShell 5.1 or later
                    - 7-Zip installed
                    - OneDrive configured
                    - WSL (optional, for WSL backups)
    
.EXAMPLE
    Copy the example yaml file to backup-config.yml and edit the paths to your desired locations.
    To run the script manually/initialise passwords:
    ./Backup-HomeAndWSL.ps1

    To run the script as a scheduled task:
    $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PWD\Backup-HomeAndWSL.ps1`""
    $Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2am
    $Principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Password -RunLevel Highest
    $Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

    Register-ScheduledTask -TaskName "Weekly PC Backup" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Description "Weekly backup of home directory and WSL distributions"

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
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = "backup-config.yml"
)

# Add notification functions
function Send-ToastNotification {
    param(
        [string]$Title,
        [string]$Message
    )
    
    if (-not $configBackup.Notifications.Toast.Enable) {
        return
    }

    try {
        # Create the toast notification script block
        $toastScript = @"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

`$template = @'
<toast>
    <visual>
        <binding template="ToastGeneric">
            <text>$Title</text>
            <text>$Message</text>
        </binding>
    </visual>
</toast>
'@

`$appId = 'Backup Script'
`$regPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings'
`$appRegPath = "`$regPath\`$appId"

if (-not (Test-Path `$appRegPath)) {
    New-Item -Path `$appRegPath -Force | Out-Null
    New-ItemProperty -Path `$appRegPath -Name 'ShowInActionCenter' -Value 1 -PropertyType DWORD -Force | Out-Null
}

`$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
`$xml.LoadXml(`$template)
`$toast = New-Object Windows.UI.Notifications.ToastNotification(`$xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier(`$appId).Show(`$toast)
"@

        # Execute the toast notification in PowerShell 5.1
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($toastScript))
        $process = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-EncodedCommand", $encodedCommand -Wait -PassThru

        if ($process.ExitCode -eq 0) {
            Write-Log "Toast notification sent successfully" -Level Info
        } else {
            throw "PowerShell 5.1 process exited with code: $($process.ExitCode)"
        }
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
    
    $subject = "Backup Error - $computerName - $(Get-Date -Format 'yyyy-MM-dd')"
    $body = @"
Backup completed with errors on $computerName

Backup Location: $BackupPath
Date: $(Get-Date)

Errors:
$($ErrorMessages | ForEach-Object { "- $_" } | Out-String)

Please check the backup logs for more details.
"@
    
    # Send email if enabled
    if ($configBackup.Notifications.Email.Enable) {
        try {
            $smtpClient = New-Object Net.Mail.SmtpClient(
                $configBackup.Notifications.Email.SmtpServer, 
                $configBackup.Notifications.Email.SmtpPort
            )
            $smtpClient.EnableSsl = $true
            $smtpClient.Credentials = New-Object System.Net.NetworkCredential(
                $configBackup.Notifications.Email.SmtpUsername, 
                $configBackup.Notifications.Email.SmtpPassword
            )

            $mailMessage = New-Object System.Net.Mail.MailMessage
            $mailMessage.From = $configBackup.Notifications.Email.From
            $mailMessage.To.Add($configBackup.Notifications.Email.To)
            $mailMessage.Subject = $subject
            $mailMessage.Body = $body
            
            $smtpClient.Send($mailMessage)
            Write-Log "Sent error notification email" -Level Info
        }
        catch {
            Write-Log "Failed to send error notification email: $_" -Level Error
        }
    }
    
    # Send toast notification
    if ($configBackup.Notifications.Toast.Enable) {
        Send-ToastNotification -Title "Backup Warning - $computerName" -Message "Backup completed with $($ErrorMessages.Count) warnings/errors"
    }
}

# Modify the main script to collect errors
$backupErrors = @()

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
    $logFile = Join-Path $PSScriptRoot "backup.log"
    $logMessage | Out-File -FilePath $logFile -Append
    
    # Collect errors and warnings
    if ($Level -in @('Error')) {
        $script:backupErrors += "$Level`: $Message"
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

    $passwordDir = Split-Path $PasswordFile -Parent
    if (-not (Test-Path $passwordDir)) {
        New-Item -ItemType Directory -Path $passwordDir -Force | Out-Null
    }

    Write-Log "Storing new password in $PasswordFile" -Level Info
    $securePassword = Read-Host "Enter backup encryption password" -AsSecureString
    $encryptedPassword = ConvertFrom-SecureString $securePassword
    $encryptedPassword | Set-Content $PasswordFile

    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
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
            'RetentionCount' = { param($c) $c.RetentionCount }
            'MaxFileSizeMB' = { param($c) $c.MaxFileSizeMB }
            'HomeItems' = { param($c) $c.HomeItems }
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
        $config.HomeItems = $config.HomeItems | ForEach-Object {
            [Environment]::ExpandEnvironmentVariables($_)
        }
        $config.Tools.SevenZip = [Environment]::ExpandEnvironmentVariables($config.Tools.SevenZip)
        

        $config.BackupPasswordPath = [Environment]::ExpandEnvironmentVariables($config.BackupPasswordPath)
        $config.Notifications.Email.SmtpPasswordPath = [Environment]::ExpandEnvironmentVariables($config.Notifications.Email.SmtpPasswordPath)
        # Check for BackupPasswordPath and whether it already exists, if not prompt to securely generate it
        $config.BackupPassword = Get-Password -PasswordFile $config.BackupPasswordPath
        # Check for EmailPasswordPath and whether it already exists, if not prompt to securely generate it
        if ($config.Notifications.Email.Enable) {
            $config.Notifications.Email.SmtpPassword = Get-Password -PasswordFile $config.Notifications.Email.SmtpPasswordPath
        }
        
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

# Function to compress and encrypt a directory
function Compress-AndEncryptDirectory {
    param(
        [string]$SourcePath,
        [string]$DestinationFile,
        [string]$Password
    )
    
    $7zArgs = @(
        'a'  # Add to archive
        "-t$($configBackup.CompressionType)"  # Compression type
        "-mx=$($configBackup.CompressionLevel)"  # Compression level
        "-v$($configBackup.MaxFileSizeMB)m"  # Volume size
        "-p$Password"  # Password
        '-mhe=on'  # Enable header encryption
        "$DestinationFile"  # Output file
        "$SourcePath\*"  # Input files
    )
    
    & $7zipPath $7zArgs
    if ($LASTEXITCODE -eq 0) {
        # Verify all volume files exist
        $volumeFiles = Get-ChildItem -Path "$DestinationFile.*" -ErrorAction SilentlyContinue
        Write-Log "Successfully compressed and encrypted: $SourcePath" -Level Info

        if ($volumeFiles) {
            $totalSize = ($volumeFiles | Measure-Object -Property Length -Sum).Sum
            Write-Log "Successfully created split archive. Total size: $([math]::Round($totalSize / 1GB, 2)) GB in $($volumeFiles.Count) volumes" -Level Info
            return $true
        } else {
            # Single file was created (no splitting needed)
            $fileSize = (Get-Item $DestinationFile).Length
            Write-Log "Successfully created archive. Size: $([math]::Round($fileSize / 1GB, 2)) GB" -Level Info
            return $true
        }
    }
    else {
        Write-Log "Error compressing and encrypting: $SourcePath" -Level Error
        return $false
    }
}

Write-Log "Starting backup process for computer: $computerName" -Level Info

# Modified backup process
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$tempBackupDir = Join-Path $configBackup.TempBackupDir "backup_temp_$timestamp"
$finalBackupDir = Join-Path $configBackup.BackupRoot $timestamp

# Create temporary working directory
New-Item -ItemType Directory -Path $tempBackupDir -Force | Out-Null
Write-Log "Created temporary backup directory: $tempBackupDir" -Level Info

# Backup home items
$homeBackupDir = Join-Path $tempBackupDir "home"
New-Item -ItemType Directory -Path $homeBackupDir -Force | Out-Null

foreach ($item in $configBackup.HomeItems) {
    if (Test-Path $item) {
        Write-Log "Starting backup of item: $item" -Level Info
        $itemInfo = Get-Item $item
        
        if ($itemInfo.PSIsContainer) {
            # Directory backup with all existing features
            $targetDir = Join-Path $homeBackupDir (Split-Path $item -Leaf)
            
            # Add size filter to robocopy
            $maxSizeFilter = $configBackup.MaxFileSizeMB * 1024 * 1024 # Convert to bytes
            
            # Use robocopy for reliable copying
            $robocopyArgs = @(
                $item                 # Source
                $targetDir           # Destination
                "/MIR"               # Mirror directories
                "/R:3"               # Retry count
                "/W:10"              # Wait time between retries
                "/MT:16"             # Multi-threaded
                "/NFL"               # No file list
                "/NDL"               # No directory list
                "/NP"                # No progress
                "/MAX:$maxSizeFilter" # Max file size
                "/XF"                # Exclude files switch
            ) + $configBackup.ExcludeFilePatterns + @(
                "/XD"                # Exclude directories switch
            ) + $configBackup.ExcludeDirectoryPatterns
            
            & robocopy @robocopyArgs

            # Check exit code - robocopy uses a bitmap for exit codes
            # 8 indicates a file was locked and 1 indicates a file was not found (8+1=9), so we'll treat anything less than 10 as success
            # 0 = No errors, files copied
            # 1 = Files copied successfully, some files were skipped
            # 2 = Extra files or directories detected
            # 4 = Some mismatched files or directories
            # 8 = Some files or directories could not be copied
            # 16 = Serious error - failure
            switch ($LASTEXITCODE) {
                { $_ -lt 8 } {
                    Write-Log "Successfully backed up $item" -Level Info
                }
                { $_ -eq 8 -or $_ -eq 9 } {
                    Write-Log "Some files in $item could not be copied (typically due to access denied or file locks)" -Level Warning
                }
                { $_ -gt 9 } {
                    Write-Log "Error backing up $item. Exit code: $LASTEXITCODE" -Level Error
                }
            }
        } else {
            # File backup
            $targetDir = Join-Path $homeBackupDir (Split-Path (Split-Path $item -Parent) -Leaf)
            Write-Log "Backing up file: $item" -Level Info
            
            try {
                New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
                Copy-Item -Path $item -Destination (Join-Path $targetDir (Split-Path $item -Leaf)) -Force
                Write-Log "Successfully backed up file: $item" -Level Info
            }
            catch {
                Write-Log "Error backing up file $item`: $_" -Level Error
            }
        }
    } else {
        Write-Log "Item not found: $item" -Level Warning
    }
}

# Fixes an encoding issue with the output of the wsl.exe command
$env:WSL_UTF8 = 1
[System.Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Backup WSL distributions
$wslDistros = wsl --list --quiet | 
    ForEach-Object {
        $_.Trim()
    } | Where-Object { 
        $_ -ne "" -and 
        $_ -notmatch "^Windows" -and 
        $_ -notmatch "^This"
    } | Where-Object {
        $_ -notin $configBackup.ExcludeWslDistros
    }

if ($wslDistros) {
    Write-Log "Found WSL distributions: $($wslDistros -join ', ')" -Level Info
    
    foreach ($distro in $wslDistros) {
        $distroName = $distro  # Should now be clean UTF8
        Write-Log "Backing up WSL distribution: $distroName" -Level Info
        
        # Create temporary directory for this distro
        $tempDistroDir = Join-Path $tempBackupDir "wsl_$distroName"
        New-Item -ItemType Directory -Path $tempDistroDir -Force | Out-Null
        
        $wslBackupFile = Join-Path $tempDistroDir "$distroName.tar"
        
        try {
            # Export WSL distribution
            Write-Log "Exporting WSL distribution: $distroName" -Level Info
            $exportCommand = "wsl.exe --export `"$distroName`" `"$wslBackupFile`""
            Write-Log "Executing command: $exportCommand" -Level Info
            
            Invoke-Expression $exportCommand
            
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Successfully exported WSL distribution: $distroName" -Level Info
                    
                # Create encrypted archive with splitting
                $distroEncryptedFile = Join-Path $finalBackupDir "wsl-$($distroName -replace '[^\w\-]', '_').7z"
                Write-Log "Creating split encrypted archive for $distroName..." -Level Info
  
                if (Compress-AndEncryptDirectory -SourcePath $tempDistroDir -DestinationFile $distroEncryptedFile -Password $configBackup.BackupPassword) {
                    Write-Log "Successfully created split archive for $distroName" -Level Info
            
                    # Get all volume files for the verification file
                        $volumeFiles = Get-ChildItem -Path "$distroEncryptedFile.*"
                        $totalSize = ($volumeFiles | Measure-Object -Property Length -Sum).Sum
                        
                        # Create verification file
                        $distroVerificationFile = Join-Path $finalBackupDir "wsl-$($distroName -replace '[^\w\-]', '_').txt"
                        @"
WSL Distribution Backup Info
---------------------------
Distribution: $distroName
Created: $(Get-Date)
Base File: $(Split-Path $distroEncryptedFile -Leaf)
Volumes: $($volumeFiles.Count)
Total Size: $([math]::Round($totalSize / 1GB, 2)) GB
Volume Files:
$(($volumeFiles | ForEach-Object { "- $($_.Name)" }) -join "`n")

To restore: 
1. Ensure all volume files are in the same directory
2. Use 7-Zip to extract the first volume with the backup password
3. Use 'wsl --import' to restore the distribution
"@ | Out-File $distroVerificationFile

                }
            }
            else {
                Write-Log "Error creating split archive for $distroName (error code $LASTEXITCODE)" -Level Error
            }
        }
        catch {
            Write-Log "Error backing up WSL distribution: $distroName" -Level Error
        }
    }
}

# Create final encrypted backup
New-Item -ItemType Directory -Path $finalBackupDir -Force | Out-Null
$encryptedBackupFile = Join-Path $finalBackupDir "backup.7z"

# Final backup
Write-Log "Creating encrypted backup archive..." -Level Info
if (Compress-AndEncryptDirectory -SourcePath $tempBackupDir -DestinationFile $encryptedBackupFile -Password $configBackup.BackupPassword) {
    Write-Log "Backup encryption completed successfully" -Level Info
    
    # Calculate final backup size accounting for split volumes
    $volumeFiles = Get-ChildItem -Path "$encryptedBackupFile.*" -ErrorAction SilentlyContinue
    if ($volumeFiles) {
        $totalSize = ($volumeFiles | Measure-Object -Property Length -Sum).Sum / 1GB
        $volumeCount = $volumeFiles.Count
        Write-Log "Final encrypted backup size: $([math]::Round($totalSize, 2)) GB in $volumeCount volumes" -Level Info
    } else {
        $totalSize = (Get-Item $encryptedBackupFile).Length / 1GB
        Write-Log "Final encrypted backup size: $([math]::Round($totalSize, 2)) GB" -Level Info
    }

    # Create a verification file
    $verificationFile = Join-Path $finalBackupDir "verification.txt"
    @"
Backup Verification Info
-----------------------
Created: $(Get-Date)
Computer: $computerName
Base File: $(Split-Path $encryptedBackupFile -Leaf)
$(if ($volumeFiles) {
"Volumes: $($volumeFiles.Count)
Volume Files:
$(($volumeFiles | ForEach-Object { "- $($_.Name)" }) -join "`n")"
} else {
"Single File Backup"
})
Total Size: $([math]::Round($totalSize, 2)) GB
To restore: Use 7-Zip to extract with the backup password or the restore-backup.ps1 script
"@ | Out-File $verificationFile
}
else {
    Write-Log "Error creating encrypted backup" -Level Error
}

# Create backup summary
$summaryFile = Join-Path $finalBackupDir "backup_summary.txt"
@"
Backup Summary
-------------
Computer Name: $computerName
Backup Date: $(Get-Date)
Backup Root: $configBackup.BackupRoot

Home Items Backup:
$(
    $homeVolumes = Get-ChildItem -Path "$encryptedBackupFile.*" -ErrorAction SilentlyContinue
    if ($homeVolumes) {
        $totalSize = ($homeVolumes | Measure-Object -Property Length -Sum).Sum
        "Size: $([math]::Round($totalSize / 1GB, 2)) GB (Split into $($homeVolumes.Count) volumes)"
    } else {
        $singleSize = (Get-Item $encryptedBackupFile -ErrorAction SilentlyContinue).Length
        "Size: $([math]::Round($singleSize / 1GB, 2)) GB (Single file)"
    }
)
Backed up directories:
$(($configBackup.HomeItems | Where-Object { 
    $item = Get-Item $_ -ErrorAction SilentlyContinue
    if ($null -eq $item) {
        Write-Log "Warning: Item not found for summary: $_" -Level Warning
        return $false
    }
    $item.PSIsContainer 
} | ForEach-Object { "- $_" }) -join "`n")

Backed up files:
$(($configBackup.HomeItems | Where-Object { 
    $item = Get-Item $_ -ErrorAction SilentlyContinue
    if ($null -eq $item) {
        Write-Log "Warning: Item not found for summary: $_" -Level Warning
        return $false
    }
    !$item.PSIsContainer 
} | ForEach-Object { "- $_" }) -join "`n")

WSL Distributions:
$(($wslDistros | ForEach-Object { 
    $baseDistroFile = Join-Path $finalBackupDir "wsl-$_.7z"
    $distroVolumes = Get-ChildItem -Path "$baseDistroFile.*" -ErrorAction SilentlyContinue
    
    if ($distroVolumes) {
        $totalSize = ($distroVolumes | Measure-Object -Property Length -Sum).Sum
        "- $_ ($([math]::Round($totalSize / 1GB, 2)) GB in $($distroVolumes.Count) volumes)"
    } elseif (Test-Path $baseDistroFile) {
        $singleSize = (Get-Item $baseDistroFile).Length
        "- $_ ($([math]::Round($singleSize / 1GB, 2)) GB)"
    } else {
        "- $_ (backup failed)"
    }
}) -join "`n")
"@ | Out-File $summaryFile

# Cleanup temporary directory
Remove-Item -Path $tempBackupDir -Recurse -Force
Write-Log "Cleaned up temporary backup directory" -Level Info

# Cleanup old backups
$allBackups = Get-ChildItem -Path $configBackup.BackupRoot -Directory | 
    Where-Object { $_.Name -match '^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}$' } |
    Sort-Object CreationTime -Descending
    
Write-Log "Found $($allBackups.Count) total backups for $computerName" -Level Info

if ($allBackups.Count -gt $configBackup.RetentionCount) {
    $backupsToDelete = $allBackups | Select-Object -Skip $configBackup.RetentionCount
    Write-Log "Removing $($backupsToDelete.Count) old backup(s)..." -Level Info
    
    foreach ($backup in $backupsToDelete) {
        Write-Log "Removing old backup: $($backup.FullName)" -Level Info
        try {
            # Force removal and suppress errors
            Remove-Item -Path $backup.FullName -Recurse -Force -ErrorAction Stop
            Write-Log "Successfully removed: $($backup.FullName)" -Level Info
        }
        catch {
            Write-Log "Error removing backup directory $($backup.FullName): $_" -Level Error
            $backupErrors.Add("Failed to remove old backup: $($backup.FullName)")
        }
    }
    
    Write-Log "Cleanup of old backups completed" -Level Info
}
else {
    Write-Log "No old backups to clean up (current count: $($allBackups.Count), retention: $($configBackup.RetentionCount))" -Level Info
}

# Add a test function to verify the backup
function Test-BackupArchive {
    param(
        [string]$ArchivePath,
        [string]$Password
    )
    
    # Check if this is a split archive
    $baseFile = $ArchivePath
    $volumeFiles = Get-ChildItem -Path "$baseFile.*" -ErrorAction SilentlyContinue
    
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
    
    Write-Log "Testing archive: $ArchivePath" -Level Info
    & $7zipPath $testArgs
    if ($LASTEXITCODE -eq 0) {
        if ($volumeFiles) {
            Write-Log "Successfully verified split archive ($($volumeFiles.Count) volumes)" -Level Info
        } else {
            Write-Log "Successfully verified archive" -Level Info
        }
        return $true
    } else {
        Write-Log "Archive verification failed" -Level Error
        return $false
    }
}

# Verify the backup
Write-Log "Verifying backup archive..."
if (Test-BackupArchive -ArchivePath $encryptedBackupFile -Password $configBackup.BackupPassword) {
    Write-Log "Backup completed and verified successfully" -Level Info
}
else {
    Write-Log "Backup verification failed - please check the backup file" -Level Error
}

# At the end of the script, after all operations
if ($backupErrors.Count -gt 0) {
    Send-ErrorNotification -ErrorMessages $backupErrors -BackupPath $finalBackupDir
}
