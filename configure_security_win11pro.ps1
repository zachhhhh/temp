<#
.SYNOPSIS
Configures and verifies security settings on Windows 11 Professional (專業版), with zh-TW support.
.NOTES
Version: 1.95 (專業版 Enhanced - Auto-installs GroupPolicy if missing)
Author: Enhanced by Grok (xAI) with Professional Edition adjustments
Date: 2025-04-11
Requires: PowerShell 5.1+, RunAsAdministrator
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param (
    [bool]$DisableUsbStorage = $true,
    [ValidateRange(0, 14)][int]$MinPasswordLength = 15, # Default minimum password length is 14
    [ValidateRange(1, 999)][int]$MaxPasswordAge = 90,
    [ValidateRange(0, 999)][int]$MinPasswordAge = 0, # Default minimum password age is 0
    [ValidateSet('NoRequire', 'Require')][string]$PasswordComplexity = 'Require', # 新增: 密碼複雜度
    [ValidateRange(60, 3600)][int]$ScreenSaverTimeoutSeconds = 600,
    [string]$ScreenSaverExecutable = "$env:SystemRoot\System32\scrnsave.scr",
    [bool]$EnforcePasswordChangeOnNonAdmins = $true,
    [ValidateSet('Enabled', 'Disabled', 'NotConfigured')][string]$AutoUpdatesSetting = 'NotConfigured' # 新增: 自動更新設定
)

# --- Setup Logging with UTF-8 ---
$LogFile = "$env:TEMP\SecurityConfig_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8  # Ensure console handles Chinese
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$Level]: $Message"
    $color = switch ($Level) { "ERROR" { "Red" } "WARN" { "Yellow" } default { "White" } }
    Write-Host $logMessage -ForegroundColor $color
    Add-Content -Path $LogFile -Value $logMessage -Encoding UTF8 -ErrorAction SilentlyContinue
}

Write-Log "Starting configuration script for Windows 11 Professional..."
Write-Log "Running as user: $env:USERNAME (PowerShell x64)"
Write-Log "System language: $((Get-Culture).Name)"

# --- Disable USB Storage ---
Write-Log "Configuring USB storage (system-wide)..."
$usbStorPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor"
$expectedUsbStorStartValue = if ($DisableUsbStorage) { 4 } else { 3 }

try {
    if (-not (Test-Path $usbStorPath)) {
        Write-Log "USB Storage registry path '$usbStorPath' not found. Skipping." "WARN"
    } else {
        Set-ItemProperty -Path $usbStorPath -Name Start -Value $expectedUsbStorStartValue -Type DWord -Force -ErrorAction Stop
        if ($DisableUsbStorage) {
            Write-Log "USB storage set to disabled (Start=$expectedUsbStorStartValue)."
        } else {
            Write-Log "USB storage set to enabled/manual (Start=$expectedUsbStorStartValue)."
        }
    }
} catch {
    Write-Log "Failed to configure USB storage: $($_.Exception.Message)" "ERROR"
}

# --- 密碼原則 (使用 net accounts 和安全原則 - 專業版) ---
Write-Host "`n正在設定密碼原則..." -ForegroundColor Yellow

# 最小密碼長度
try {
    Write-Log "Setting minimum password length to $MinPasswordLength..."
    $process = Start-Process -FilePath "net.exe" -ArgumentList "accounts /minpwlen:$MinPasswordLength" -NoNewWindow -PassThru -Wait
    if ($process.ExitCode -ne 0) {
        Write-Warning "指令 'net accounts /minpwlen:$MinPasswordLength' 失敗，結束代碼: $($process.ExitCode)。請檢查值是否有效（0-14）。"
    } else {
        Write-Log "Minimum password length set to: $MinPasswordLength (system-wide)."
    }
} catch {
    Write-Log "Failed to execute 'net accounts' for minimum password length: $($_.Exception.Message)" "ERROR"
}

# 最長密碼有效期
try {
    Write-Log "Setting maximum password age to $MaxPasswordAge days..."
    if ($MaxPasswordAge -lt 1) {
        $MaxPasswordAge = 1
    } elseif ($MaxPasswordAge -gt 999) {
        $MaxPasswordAge = 999
    }
    # Check if current min password age is not greater than max password age
    $currentMinAgeResult = (net accounts | Select-String -Pattern "^Minimum password age").ToString().Split(":")[-1].Trim()
    if ($currentMinAgeResult -as [int] -gt $MaxPasswordAge) {
        Write-Warning "目前最小密碼有效期 ($currentMinAgeResult 天) 大於嘗試設定的最大密碼有效期 ($MaxPasswordAge 天)。請先調整最小密碼有效期。"
    } else {
        $process = Start-Process -FilePath "net.exe" -ArgumentList "accounts /maxpwage:$MaxPasswordAge" -NoNewWindow -PassThru -Wait
        if ($process.ExitCode -ne 0) {
            Write-Warning "指令 'net accounts /maxpwage:$MaxPasswordAge' 失敗，結束代碼: $($process.ExitCode)。請檢查值是否有效（1-999）。"
        } else {
            Write-Log "Maximum password age set to: $MaxPasswordAge days (system-wide)."
        }
    }
} catch {
    Write-Log "Failed to execute 'net accounts' for maximum password age: $($_.Exception.Message)" "ERROR"
}

# 最小密碼有效期 (新增 - Corrected parameter name)
try {
    Write-Log "Setting minimum password age to $MinPasswordAge days..."
    if ($MinPasswordAge -lt 0) {
        $MinPasswordAge = 0
    } elseif ($MinPasswordAge -gt 998) { # maxpwage - 1
        $MinPasswordAge = 998
    }
    $process = Start-Process -FilePath "net.exe" -ArgumentList "accounts /minpwage:$MinPasswordAge" -NoNewWindow -PassThru -Wait
    if ($process.ExitCode -ne 0) {
        Write-Warning "指令 'net accounts /minpwage:$MinPasswordAge' 失敗，結束代碼: $($process.ExitCode)。請檢查值是否有效（0-998）。"
    } else {
        Write-Log "Minimum password age set to: $MinPasswordAge days (system-wide)."
    }
} catch {
    Write-Log "Failed to execute 'net accounts' for minimum password age: $($_.Exception.Message)" "ERROR"
}

# 密碼複雜度 (新增 - Auto-install GroupPolicy if missing)
Write-Log "Checking for and importing GroupPolicy module..."
try {
    Import-Module -Name GroupPolicy -ErrorAction Stop
    Write-Log "GroupPolicy module imported successfully."
} catch {
    Write-Warning "GroupPolicy module not found. Attempting to install RSAT feature..."
    try {
        $gpFeature = Get-WindowsCapability -Online | Where-Object {$_.Name -Like "Rsat.GroupPolicy.Management.Tools*"}
        if ($gpFeature.State -ne 'Present') {
            Write-Log "Installing RSAT: Group Policy Management Tools..."
            Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0 -ErrorAction Stop | Out-Null
            Write-Log "RSAT: Group Policy Management Tools installed successfully. Attempting to import module again."
            Import-Module -Name GroupPolicy -ErrorAction Stop
            Write-Log "GroupPolicy module imported successfully after installation."
        } else {
            Write-Log "RSAT: Group Policy Management Tools is already present. Assuming GroupPolicy module is available now."
        }
    } catch {
        Write-Log "Failed to install RSAT feature or import GroupPolicy module: $($_.Exception.Message)" "ERROR"
        Write-Warning "Password complexity configuration via Group Policy will be skipped. Consider using 'secpol.msc'."
    }
}

if (Get-Module -Name GroupPolicy) {
    if ($PasswordComplexity -eq 'Require') {
        Write-Log "Enforcing password complexity requirements..."
        try {
            Set-GPRegistryValue -Name "LocalGPO" -Key "Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "PasswordComplexity" -Value 1 -Type DWord -ErrorAction Stop
            Write-Log "Password complexity required."
        } catch {
            Write-Log "Failed to enforce password complexity via Group Policy: $($_.Exception.Message)" "ERROR"
            Write-Warning "Consider using 'secpol.msc' to manually configure password complexity."
        }
    } else {
        Write-Log "Password complexity not required."
        try {
            Set-GPRegistryValue -Name "LocalGPO" -Key "Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "PasswordComplexity" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        } catch {
            Write-Log "Failed to disable password complexity via Group Policy: $($_.Exception.Message)" "WARN"
        }
    }
} else {
    Write-Warning "GroupPolicy module could not be loaded. Skipping password complexity configuration."
}

# --- 強制非系統管理員變更密碼 (強制) ---
Write-Host "`n正在嘗試標記非系統管理員使用者於下次登入時變更密碼..." -ForegroundColor Yellow
Write-Host "警告: 這將影響所有已啟用的本機使用者，除了內建的 Administrator (SID 結尾為 -500)。" -ForegroundColor Yellow

try {
    # 使用 Get-LocalUser 取得已啟用且非內建 Administrator 的本機帳戶
    $usersToFlag = Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.SID -notlike '*-500' } -ErrorAction Stop

    if ($null -eq $usersToFlag -or $usersToFlag.Count -eq 0) {
        Write-Host "找不到適用的使用者帳戶來標記變更密碼。" -ForegroundColor Green
    } else {
        # 確保 $usersToFlag 是陣列
        if ($usersToFlag -isnot [array]) { $usersToFlag = @($usersToFlag) }

        foreach ($user in $usersToFlag) {
            Write-Host "  正在嘗試標記使用者: $($user.Name)"
            try {
                $process = Start-Process -FilePath "net.exe" -ArgumentList "user `"$($user.Name)`" /logonpasswordchg:yes" -NoNewWindow -PassThru -Wait
                if ($process.ExitCode -eq 0) {
                    Write-Host "    [成功] 使用者 '$($user.Name)' 已被標記在下次登入時變更密碼。" -ForegroundColor Green
                } else {
                    Write-Warning "    [警告] 指令 'net user ""$($user.Name)"" /logonpasswordchg:yes' 以結束代碼 $($process.ExitCode) 完成。可能未成功。"
                }
            } catch {
                Write-Log "Failed to flag user '$($user.Name)' for password change: $($_.Exception.Message)" "ERROR"
            }
        }
    }
} catch {
    Write-Log "Failed to retrieve local users or execute 'net user' command: $($_.Exception.Message)" "ERROR"
    Write-Warning "Skipping force password change section due to an error."
}

# --- Automatic Updates (專業版 可以透過 Group Policy 設定) ---
Write-Log "Configuring Automatic Updates..."
if ($AutoUpdatesSetting -eq 'Enabled') {
    Write-Log "Enabling Automatic Updates (Notify for download and auto install)..."
    try {
        if (Get-Module -Name GroupPolicy) {
            Set-GPRegistryValue -Name "LocalGPO" -Key "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "AUOptions" -Value 3 -Type DWord -ErrorAction Stop
            Set-GPRegistryValue -Name "LocalGPO" -Key "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Write-Log "Automatic Updates configured to 'Notify for download and auto install'."
        } else {
            Write-Warning "GroupPolicy module not available. Skipping Automatic Updates configuration via Group Policy."
            Write-Log "Note: Consider using 'gpedit.msc' or Settings to configure Automatic Updates." "WARN"
        }
    } catch {
        Write-Log "Failed to enable Automatic Updates via Group Policy: $($_.Exception.Message)" "ERROR"
        Write-Warning "Consider using 'gpedit.msc' to manually configure Automatic Updates."
    }
} elseif ($AutoUpdatesSetting -eq 'Disabled') {
    Write-Log "Disabling Automatic Updates..."
    try {
        if (Get-Module -Name GroupPolicy) {
            Set-GPRegistryValue -Name "LocalGPO" -Key "Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "AUOptions" -Value 1 -Type DWord -ErrorAction Stop
            Write-Log "Automatic Updates disabled."
        } else {
            Write-Warning "GroupPolicy module not available. Skipping Automatic Updates configuration via Group Policy."
            Write-Log "Note: Consider using 'gpedit.msc' or Settings to configure Automatic Updates." "WARN"
        }
    } catch {
        Write-Log "Failed to disable Automatic Updates via Group Policy: $($_.Exception.Message)" "ERROR"
        Write-Warning "Consider using 'gpedit.msc' to manually configure Automatic Updates."
    }
} else {
    Write-Log "Automatic Updates configuration skipped (set to 'NotConfigured')."
}

# --- Screen Saver (Current User) ---
Write-Log "Configuring screen saver for current user ($env:USERNAME)..."
$controlPanelDesktopPath = "HKCU:\Control Panel\Desktop"

try {
    if (-not (Test-Path $controlPanelDesktopPath)) {
        New-Item -Path $controlPanelDesktopPath -Force -ErrorAction Stop | Out-Null
    }
    if (-not (Test-Path $ScreenSaverExecutable)) {
        Write-Log "Screen saver '$ScreenSaverExecutable' not found. Setting may not work." "WARN"
    }

    Set-ItemProperty -Path $controlPanelDesktopPath -Name "SCRNSAVE.EXE" -Value $ScreenSaverExecutable -Type String -Force -ErrorAction Stop
    Set-ItemProperty -Path $controlPanelDesktopPath -Name "ScreenSaveActive" -Value "1" -Type String -Force -ErrorAction Stop
    Set-ItemProperty -Path $controlPanelDesktopPath -Name "ScreenSaverTimeout" -Value $ScreenSaverTimeoutSeconds -Type String -Force -ErrorAction Stop
    Set-ItemProperty -Path $controlPanelDesktopPath -Name "ScreenSaverIsSecure" -Value "1" -Type String -Force -ErrorAction Stop

    Write-Log "Screen saver configured: Timeout=$ScreenSaverTimeoutSeconds seconds, Password required."
} catch {
    Write-Log "Failed to configure screen saver: $($_.Exception.Message)" "ERROR"
}

Write-Log "Security configuration script finished."
