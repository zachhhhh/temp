# PowerShell script to configure security policies and settings.

# --- Configuration Variables ---
$DisableUsbStorage = $true
$MinPasswordLength = 16
$MaxPasswordAge = 180
$ScreenSaverTimeout = 300 # 5 minutes in seconds
$LogFile = "$env:TEMP\SecurityConfig_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# --- Function to Write Log ---
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$Level]: $Message"
    Write-Host $logMessage
    Add-Content -Path $LogFile -Value $logMessage -ErrorAction SilentlyContinue
}

# --- Check for Administrative Privileges ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "This script requires administrative privileges. Please run as Administrator." "ERROR"
    exit 1
}

# --- Disable USB Storage ---
Write-Log "Configuring USB storage..."
$usbStorPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor"

try {
    if ($DisableUsbStorage) {
        Set-ItemProperty -Path $usbStorPath -Name Start -Value 4 -ErrorAction Stop
        $startValue = Get-ItemProperty -Path $usbStorPath -Name Start -ErrorAction Stop
        if ($startValue.Start -eq 4) {
            Write-Log "USB storage successfully disabled."
        } else {
            Write-Log "USB storage registry key not set to disabled as expected." "WARNING"
        }
    } else {
        Write-Log "USB storage disable variable is set to false; no changes made."
    }
} catch {
    Write-Log "Failed to configure USB storage: $($_.Exception.Message)" "WARNING"
}

# --- Password Policies (Using secedit) ---
Write-Log "Configuring password policies..."
$tempCfgPath = "$env:TEMP\temp.cfg"
$tempDbPath = "$env:TEMP\temp.sdb"

try {
    secedit /export /cfg $tempCfgPath /quiet
    if (-not (Test-Path $tempCfgPath)) {
        throw "Failed to export security policy configuration."
    }

    $content = Get-Content $tempCfgPath -Raw
    if ($content -match "MinimumPasswordLength = (\d+)") {
        $content = $content -replace "MinimumPasswordLength = \d+", "MinimumPasswordLength = $MinPasswordLength"
    } else {
        $content += "`nMinimumPasswordLength = $MinPasswordLength"
    }
    if ($content -match "PasswordComplexity = (\d+)") {
        $content = $content -replace "PasswordComplexity = \d+", "PasswordComplexity = 1"
    } else {
        $content += "`nPasswordComplexity = 1"
    }
    if ($content -match "MaximumPasswordAge = (\d+)") {
        $content = $content -replace "MaximumPasswordAge = \d+", "MaximumPasswordAge = $MaxPasswordAge"
    } else {
        $content += "`nMaximumPasswordAge = $MaxPasswordAge"
    }
    $content | Set-Content $tempCfgPath -ErrorAction Stop

    secedit /configure /db $tempDbPath /cfg $tempCfgPath /areas SECURITYPOLICY /quiet
    Write-Log "Minimum password length set to: $MinPasswordLength"
    Write-Log "Password complexity enabled."
    Write-Log "Maximum password age set to: $MaxPasswordAge days"
} catch {
    Write-Log "Failed to configure password policies: $($_.Exception.Message)" "WARNING"
} finally {
    try {
        if (Test-Path $tempCfgPath) { Remove-Item $tempCfgPath -ErrorAction Stop }
        if (Test-Path $tempDbPath) { Remove-Item $tempDbPath -ErrorAction Stop }
    } catch {
        Write-Log "Failed to delete temporary files: $($_.Exception.Message)" "WARNING"
    }
}

# --- Force Password Change for Non-Compliant Users ---
Write-Log "Checking and enforcing password changes for users..."
try {
    $users = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    foreach ($user in $users) {
        # Force password change at next login
        Set-LocalUser -Name $user.Name -PasswordNeverExpires $false -PasswordChangeRequired $true -ErrorAction Stop
        Write-Log "User $($user.Name): Password change required at next login."
    }
} catch {
    Write-Log "Failed to enforce password changes: $($_.Exception.Message)" "WARNING"
}

# --- Automatic Updates ---
Write-Log "Configuring automatic updates..."
$auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

try {
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
    }
    if (-not (Test-Path $auPath)) {
        New-Item -Path $auPath -Force | Out-Null
    }

    Set-ItemProperty -Path $auPath -Name AUOptions -Value 4 -ErrorAction Stop
    Set-ItemProperty -Path $auPath -Name NoAutoRebootWithLoggedOnUsers -Value 1 -ErrorAction Stop
    $auOptions = Get-ItemProperty -Path $auPath -Name AUOptions -ErrorAction Stop
    if ($auOptions.AUOptions -eq 4) {
        Write-Log "Automatic updates configured to auto-download and install."
    } else {
        Write-Log "Automatic updates not set as expected." "WARNING"
    }
} catch {
    Write-Log "Failed to configure automatic updates: $($_.Exception.Message)" "WARNING"
}

# --- Screen Saver ---
Write-Log "Configuring screen saver..."
$controlPanelDesktopPath = "HKCU:\Control Panel\Desktop"
$screenSaverPath = "$env:SystemRoot\system32\logon.scr"

try {
    Set-ItemProperty -Path $controlPanelDesktopPath -Name ScreenSaveActive -Value 1 -ErrorAction Stop
    Set-ItemProperty -Path $controlPanelDesktopPath -Name ScreenSaveTimeOut -Value $ScreenSaverTimeout -ErrorAction Stop
    Set-ItemProperty -Path $controlPanelDesktopPath -Name ScreenSaverIsSecure -Value 1 -ErrorAction Stop
    Set-ItemProperty -Path $controlPanelDesktopPath -Name SCRNSAVE.EXE -Value $screenSaverPath -ErrorAction Stop

    if (Test-Path $screenSaverPath) {
        Write-Log "Screen saver enabled with a $([math]::Round($ScreenSaverTimeout / 60, 2)) minute timeout and password protection."
    } else {
        Write-Log "Screen saver not found at $screenSaverPath; using fallback configuration." "WARNING"
    }
} catch {
    Write-Log "Failed to configure screen saver: $($_.Exception.Message)" "WARNING"
}

# --- Verification Section ---
Write-Log "Verifying configuration settings..."

# Verify USB Storage
try {
    $usbStartValue = Get-ItemProperty -Path $usbStorPath -Name Start -ErrorAction Stop
    if ($DisableUsbStorage -and $usbStartValue.Start -eq 4) {
        Write-Log "Verification: USB storage is correctly disabled."
    } elseif (-not $DisableUsbStorage -and $usbStartValue.Start -ne 4) {
        Write-Log "Verification: USB storage is correctly enabled (not disabled)."
    } else {
        Write-Log "Verification Failed: USB storage setting does not match expected state." "WARNING"
    }
} catch {
    Write-Log "Verification Failed: Could not check USB storage setting: $($_.Exception.Message)" "WARNING"
}

# Verify Password Policies
try {
    $verifyCfgPath = "$env:TEMP\verify_temp.cfg"
    secedit /export /cfg $verifyCfgPath /quiet
    if (Test-Path $verifyCfgPath) {
        $verifyContent = Get-Content $verifyCfgPath -Raw
        if ($verifyContent -match "MinimumPasswordLength = (\d+)") {
            $minLength = [int]$Matches[1]
            if ($minLength -eq $MinPasswordLength) {
                Write-Log "Verification: Minimum password length is correctly set to $MinPasswordLength."
            } else {
                Write-Log "Verification Failed: Minimum password length is set to $minLength, expected $MinPasswordLength." "WARNING"
            }
        } else {
            Write-Log "Verification Failed: Minimum password length not found in policy." "WARNING"
        }
        if ($verifyContent -match "PasswordComplexity = (\d+)") {
            $complexity = [int]$Matches[1]
            if ($complexity -eq 1) {
                Write-Log "Verification: Password complexity is correctly enabled."
            } else {
                Write-Log "Verification Failed: Password complexity is set to $complexity, expected 1." "WARNING"
            }
        } else {
            Write-Log "Verification Failed: Password complexity not found in policy." "WARNING"
        }
        if ($verifyContent -match "MaximumPasswordAge = (\d+)") {
            $maxAge = [int]$Matches[1]
            if ($maxAge -eq $MaxPasswordAge) {
                Write-Log "Verification: Maximum password age is correctly set to $MaxPasswordAge days."
            } else {
                Write-Log "Verification Failed: Maximum password age is set to $maxAge, expected $MaxPasswordAge." "WARNING"
            }
        } else {
            Write-Log "Verification Failed: Maximum password age not found in policy." "WARNING"
        }
        Remove-Item $verifyCfgPath -ErrorAction SilentlyContinue
    } else {
        Write-Log "Verification Failed: Could not export security policy for verification." "WARNING"
    }
} catch {
    Write-Log "Verification Failed: Error verifying password policies: $($_.Exception.Message)" "WARNING"
}

# Verify Automatic Updates
try {
    $auValues = Get-ItemProperty -Path $auPath -ErrorAction Stop
    if ($auValues.AUOptions -eq 4) {
        Write-Log "Verification: Automatic updates are correctly set to auto-download and install."
    } else {
        Write-Log "Verification Failed: Automatic updates are not set to auto-download and install." "WARNING"
    }
    if ($auValues.NoAutoRebootWithLoggedOnUsers -eq 1) {
        Write-Log "Verification: Auto-reboot with logged-on users is correctly disabled."
    } else {
        Write-Log "Verification Failed: Auto-reboot with logged-on users is not disabled." "WARNING"
    }
} catch {
    Write-Log "Verification Failed: Could not check automatic updates settings: $($_.Exception.Message)" "WARNING"
}

# Verify Screen Saver
try {
    $screenSaverValues = Get-ItemProperty -Path $controlPanelDesktopPath -ErrorAction Stop
    if ($screenSaverValues.ScreenSaveActive -eq 1) {
        Write-Log "Verification: Screen saver is correctly enabled."
    } else {
        Write-Log "Verification Failed: Screen saver is not enabled." "WARNING"
    }
    if ($screenSaverValues.ScreenSaveTimeOut -eq $ScreenSaverTimeout) {
        Write-Log "Verification: Screen saver timeout is correctly set to $([math]::Round($ScreenSaverTimeout / 60, 2)) minutes."
    } else {
        Write-Log "Verification Failed: Screen saver timeout is not set to $ScreenSaverTimeout seconds." "WARNING"
    }
    if ($screenSaverValues.ScreenSaverIsSecure -eq 1) {
        Write-Log "Verification: Screen saver password protection is correctly enabled."
    } else {
        Write-Log "Verification Failed: Screen saver password protection is not enabled." "WARNING"
    }
    if ($screenSaverValues.'SCRNSAVE.EXE' -eq $screenSaverPath -and (Test-Path $screenSaverPath)) {
        Write-Log "Verification: Screen saver executable is correctly set to $screenSaverPath."
    } else {
        Write-Log "Verification Failed: Screen saver executable is not set to $screenSaverPath or file is missing." "WARNING"
    }
} catch {
    Write-Log "Verification Failed: Could not check screen saver settings: $($_.Exception.Message)" "WARNING"
}

# --- Final Message ---
Write-Log "Security configuration and verification complete."
Write-Log "Log file saved to: $LogFile"
