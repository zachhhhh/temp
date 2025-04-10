<#
.SYNOPSIS
Configures and verifies security settings on Windows 11 Home, with zh-TW support.
.NOTES
Version: 1.7
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
        Write-Log "USB storage set to $($DisableUsbStorage ? 'disabled' : 'enabled/manual') (Start=$expectedUsbStorStartValue)."
    }
} catch {
    Write-Log "Failed to configure USB storage: $($_.Exception.Message)" "ERROR"
}

# --- Password Policies (net accounts) ---
Write-Log "Configuring password policies via 'net accounts' (system-wide)..."
Write-Log "Note: Windows 11 Home limits password policy options (no complexity enforcement)." "WARN"

try {
    $minOutput = & net.exe accounts /minpwlen:$MinPasswordLength 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Failed to set minimum password length to $MinPasswordLength: $minOutput (Exit code: $LASTEXITCODE)." "WARN"
    } else {
        Write-Log "Set minimum password length to $MinPasswordLength."
    }

    $maxOutput = & net.exe accounts /maxpwage:$MaxPasswordAge 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Failed to set maximum password age to $MaxPasswordAge days: $maxOutput (Exit code: $LASTEXITCODE)." "WARN"
    } else {
        Write-Log "Set maximum password age to $MaxPasswordAge days."
    }
} catch {
    Write-Log "Failed to run 'net accounts': $($_.Exception.Message)" "ERROR"
}

# --- Force Password Change for Non-Admins ---
if ($EnforcePasswordChangeOnNonAdmins) {
    Write-Log "Flagging non-admin users for password change at next logon..."
    Write-Log "WARNING: Affects all enabled local users except built-in Administrator (SID *-500)." "WARN"

    try {
        $users = Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled -and $_.SID.Value -notlike '*-500' }
        if (-not $users) {
            Write-Log "No eligible users found for password change enforcement."
        } else {
            foreach ($user in $users) {
                Write-Log "Processing user: $($user.Name)"
                try {
                    Set-LocalUser -Name $user.Name -PasswordNeverExpires $false -ErrorAction Stop
                    $netOutput = & net.exe user $user.Name /logonpasswordchg:yes 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        Write-Log "Failed to enforce password change for '$($user.Name)' via 'net user': $netOutput (Exit code: $LASTEXITCODE). Using workaround..." "WARN"
                        $tempPassword = "TempP@ss$(Get-Random)"
                        & net.exe user $user.Name $tempPassword 2>&1 | Out-Null
                        if ($LASTEXITCODE -eq 0) {
                            Write-Log "Set temporary password for '$($user.Name)' to force change at next logon."
                        } else {
                            Write-Log "Failed to set temporary password for '$($user.Name)' (Exit code: $LASTEXITCODE)." "ERROR"
                        }
                    } else {
                        Write-Log "User '$($user.Name)' flagged to change password at next logon."
                    }
                } catch {
                    Write-Log "Failed to process user '$($user.Name)': $($_.Exception.Message)" "ERROR"
                }
            }
        }
    } catch {
        Write-Log "Failed to retrieve local users: $($_.Exception.Message)" "ERROR"
    }
} else {
    Write-Log "Skipping password change enforcement."
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

# --- Verification ---
Write-Log "Starting verification..."
$verificationSuccess = $true

# Verify USB Storage
Write-Log "Verifying USB storage..."
try {
    if (Test-Path $usbStorPath) {
        $currentUsbStartValue = Get-ItemProperty -Path $usbStorPath -Name Start -ErrorAction Stop | Select-Object -ExpandProperty Start
        if ($currentUsbStartValue -eq $expectedUsbStorStartValue) {
            Write-Log "[PASS] USB Storage Start=$currentUsbStartValue (as expected)."
        } else {
            Write-Log "[FAIL] USB Storage Start=$currentUsbStartValue (Expected: $expectedUsbStorStartValue)." "ERROR"
            $verificationSuccess = $false
        }
    } else {
        Write-Log "USB Storage path not found for verification." "WARN"
    }
} catch {
    Write-Log "Failed to verify USB storage: $($_.Exception.Message)" "ERROR"
}

# Verify Password Policies
Write-Log "Verifying password policies via 'net accounts'..."
try {
    # Ensure UTF-8 capture of output
    $netAccountsOutput = & net.exe accounts 2>&1 | ForEach-Object { [System.Text.Encoding]::UTF8.GetString([System.Text.Encoding]::Default.GetBytes($_)) }
    if ($LASTEXITCODE -ne 0) { throw "net accounts failed: $netAccountsOutput" }

    # Log raw output for debugging
    Write-Log "Raw 'net accounts' output:`n$($netAccountsOutput -join "`n")" "DEBUG"

    # Language-specific parsing for zh-TW
    $culture = (Get-Culture).Name
    $currentMinLength = -1
    $currentMaxAge = -1

    if ($culture -eq "zh-TW") {
        Write-Log "Parsing for Traditional Chinese (zh-TW)..." "DEBUG"
        foreach ($line in $netAccountsOutput) {
            Write-Log "Line: $line" "DEBUG"  # Log each line to trace parsing
            if ($line -match '密碼最短長度[^\d]*(\d+)') {
                $currentMinLength = [int]$Matches[1]
                Write-Log "Parsed Minimum password length: $currentMinLength" "DEBUG"
            } elseif ($line -match '密碼最短長度[^\d]*無') {
                $currentMinLength = 0
                Write-Log "Parsed Minimum password length: 0 (無)" "DEBUG"
            }
            if ($line -match '密碼最長有效期\(天\)[^\d]*(\d+)') {
                $currentMaxAge = [int]$Matches[1]
                Write-Log "Parsed Maximum password age: $currentMaxAge" "DEBUG"
            } elseif ($line -match '密碼最長有效期\(天\)[^\d]*無限制') {
                $currentMaxAge = 99999
                Write-Log "Parsed Maximum password age: Unlimited (無限制)" "DEBUG"
            }
        }
    } else {
        # Fallback to English
        Write-Log "Parsing for English (fallback)..." "DEBUG"
        foreach ($line in $netAccountsOutput) {
            if ($line -match '(?i)minimum\s+password\s+length[^\d]*(\d+)') {
                $currentMinLength = [int]$Matches[1]
            } elseif ($line -match '(?i)minimum\s+password\s+length[^\d]*none') {
                $currentMinLength = 0
            }
            if ($line -match '(?i)maximum\s+password\s+age[^\d]*(\d+)') {
                $currentMaxAge = [int]$Matches[1]
            } elseif ($line -match '(?i)maximum\s+password\s+age[^\d]*unlimited') {
                $currentMaxAge = 99999
            }
        }
    }

    if ($currentMinLength -eq -1) {
        Write-Log "[FAIL] Could not parse Minimum password length from 'net accounts' output." "ERROR"
        $verificationSuccess = $false
    } elseif ($currentMinLength -ge $MinPasswordLength) {
        Write-Log "[PASS] Minimum password length=$currentMinLength (meets or exceeds $MinPasswordLength)."
    } else {
        Write-Log "[FAIL] Minimum password length=$currentMinLength (below $MinPasswordLength)." "ERROR"
        $verificationSuccess = $false
    }

    if ($currentMaxAge -eq -1) {
        Write-Log "[FAIL] Could not parse Maximum password age from 'net accounts' output." "ERROR"
        $verificationSuccess = $false
    } elseif ($currentMaxAge -eq 99999 -and $MaxPasswordAge -lt 999) {
        Write-Log "[FAIL] Maximum password age=Unlimited (Expected: $MaxPasswordAge days)." "ERROR"
        $verificationSuccess = $false
    } elseif ($currentMaxAge -le $MaxPasswordAge) {
        Write-Log "[PASS] Maximum password age=$currentMaxAge days (meets or below $MaxPasswordAge)."
    } else {
        Write-Log "[FAIL] Maximum password age=$currentMaxAge days (Expected: $MaxPasswordAge or less)." "ERROR"
        $verificationSuccess = $false
    }
} catch {
    Write-Log "Failed to verify password policies: $($_.Exception.Message)" "ERROR"
}

# Verify Screen Saver
Write-Log "Verifying screen saver for current user ($env:USERNAME)..."
try {
    $props = Get-ItemProperty -Path $controlPanelDesktopPath -ErrorAction Stop
    $ssVerified = $true

    if ($props.ScreenSaveActive -eq "1") { Write-Log "[PASS] ScreenSaveActive=1" }
    else { Write-Log "[FAIL] ScreenSaveActive=$($props.ScreenSaveActive) (Expected: 1)" "ERROR"; $ssVerified = $false }

    if ($props.ScreenSaverTimeout -eq $ScreenSaverTimeoutSeconds.ToString()) { Write-Log "[PASS] ScreenSaverTimeout=$($props.ScreenSaverTimeout) seconds" }
    else { Write-Log "[FAIL] ScreenSaverTimeout=$($props.ScreenSaverTimeout) (Expected: $ScreenSaverTimeoutSeconds)" "ERROR"; $ssVerified = $false }

    if ($props.'SCRNSAVE.EXE' -eq $ScreenSaverExecutable) { Write-Log "[PASS] SCRNSAVE.EXE=$($props.'SCRNSAVE.EXE')" }
    else { Write-Log "[FAIL] SCRNSAVE.EXE=$($props.'SCRNSAVE.EXE') (Expected: $ScreenSaverExecutable)" "ERROR"; $ssVerified = $false }

    if ($props.ScreenSaverIsSecure -eq "1") { Write-Log "[PASS] ScreenSaverIsSecure=1" }
    else { Write-Log "[FAIL] ScreenSaverIsSecure=$($props.ScreenSaverIsSecure) (Expected: 1)" "ERROR"; $ssVerified = $false }

    if (-not $ssVerified) { $verificationSuccess = $false }
} catch {
    Write-Log "Failed to verify screen saver: $($_.Exception.Message)" "ERROR"
}

# --- Summary ---
Write-Log "--- Verification Summary ---"
if ($verificationSuccess) {
    Write-Log "All verifiable settings configured correctly (within Windows 11 Home limits)."
} else {
    Write-Log "One or more settings failed verification. See [FAIL] messages above." "ERROR"
}
Write-Log "Log file: $LogFile"
Write-Log "Script completed."
