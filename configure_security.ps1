<#
.SYNOPSIS
Configures and verifies security settings on Windows 11 Home, with zh-TW support.
.NOTES
Version: 1.8
Author: Enhanced by Grok (xAI)
Date: 2025-04-10
Requires: PowerShell 5.1+ (Windows 11 default), RunAsAdministrator
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param (
    [bool]$DisableUsbStorage = $true,
    [ValidateRange(0, 14)][int]$MinPasswordLength = 12,
    [ValidateRange(1, 999)][int]$MaxPasswordAge = 90,
    [ValidateRange(60, 3600)][int]$ScreenSaverTimeoutSeconds = 600,
    [string]$ScreenSaverExecutable = "$env:SystemRoot\System32\scrnsave.scr",
    [bool]$EnforcePasswordChangeOnNonAdmins = $true
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

Write-Log "Starting configuration script for Windows 11 Home..."
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

# --- 密碼原則 (使用 net accounts - 家用版有限) ---
Write-Host "`n正在使用 'net accounts' 設定密碼原則..." -ForegroundColor Yellow
Write-Host "注意: 無法在家用版上透過 'net accounts' 強制執行密碼複雜性。" -ForegroundColor Yellow

# 最小密碼長度
$MinPasswordLength = 14 # 設定最小密碼長度為 14
try {
    Write-Verbose "正在設定最小密碼長度為 $MinPasswordLength"
    $process = Start-Process -FilePath "net.exe" -ArgumentList "accounts /minpwlen:$MinPasswordLength" -NoNewWindow -PassThru -Wait
    if ($process.ExitCode -ne 0) {
        Write-Warning "指令 'net accounts /minpwlen:$MinPasswordLength' 失敗，結束代碼: $($process.ExitCode)。請檢查值是否有效（0-14）。"
    } else {
        Write-Host "已設定最小密碼長度為: $MinPasswordLength (系統範圍)。" -ForegroundColor Green
    }
} catch {
    Write-Error "執行 'net accounts' 設定最小密碼長度失敗。錯誤: $($_.Exception.Message)"
}

# 最長密碼有效期 (可選，您可以根據需要設定)
try {
    $MaxPasswordAge = 90 # 範例：設定最長密碼有效期為 90 天
    if ($MaxPasswordAge -lt 1) {
        $MaxPasswordAge = 1
    } elseif ($MaxPasswordAge -gt 999) {
        $MaxPasswordAge = 999
    }
    Write-Verbose "正在設定最長密碼有效期為 $MaxPasswordAge 天"
    $process = Start-Process -FilePath "net.exe" -ArgumentList "accounts /maxpwage:$MaxPasswordAge" -NoNewWindow -PassThru -Wait
    if ($process.ExitCode -ne 0) {
        Write-Warning "指令 'net accounts /maxpwage:$MaxPasswordAge' 失敗，結束代碼: $($process.ExitCode)。請檢查值是否有效（1-999）。"
    } else {
        Write-Host "已設定最長密碼有效期為: $MaxPasswordAge 天 (系統範圍)。" -ForegroundColor Green
    }
} catch {
    Write-Error "執行 'net accounts' 設定最長密碼有效期失敗。錯誤: $($_.Exception.Message)"
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
                Write-Error "    [失敗] 標記使用者 '$($user.Name)' 失敗。錯誤: $($_.Exception.Message)"
            }
        }
    }
} catch {
    Write-Error "擷取本機使用者或執行 'net user' 指令失敗。錯誤: $($_.Exception.Message)"
    Write-Warning "由於錯誤，正在跳過強制變更密碼區段。"
}

# --- Automatic Updates ---
Write-Log "Skipping Automatic Updates configuration..."
Write-Log "Note: Use Settings > Windows Update for configuration on Windows 11 Home." "WARN"

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
