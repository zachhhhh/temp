#Requires -RunAsAdministrator

<#
.SYNOPSIS
Configures and verifies security settings on Windows 11 Home, optionally enforcing password changes.
.DESCRIPTION
This script attempts to configure the following on Windows 11 Home:
- Disable USB mass storage devices (System-wide).
- Set basic password policies using 'net accounts' (System-wide, limited options on Home).
- Configure screen saver settings for the *current user* running the script.
- Optionally flags all standard local users to change their password at next logon.

It then attempts to verify the configured settings.
.NOTES
Version: 1.3
Author: Gemini AI (Modified from user input)
Date: 2025-04-10

IMPORTANT WINDOWS HOME LIMITATIONS:
- Full password policies (like complexity) cannot be enforced via script on Windows Home.
- Group Policy registry keys (like those for Automatic Updates) are not reliably supported on Windows Home.
- Settings applied to HKCU only affect the user running the script.
- Forced password change flags ALL non-built-in-admin users, regardless of current password compliance.
- Verification of 'net accounts' output relies on string parsing and may be affected by system language.
- Requires PowerShell 5.1+ for Get-LocalUser cmdlet.
#>

# --- Configuration Variables ---
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [bool]$DisableUsbStorage = $true,

    [Parameter(Mandatory=$false)]
    [int]$MinPasswordLength = 12,

    [Parameter(Mandatory=$false)]
    [int]$MaxPasswordAge = 90,

    [Parameter(Mandatory=$false)]
    [int]$ScreenSaverTimeoutSeconds = 600, # 10 minutes

    [Parameter(Mandatory=$false)]
    [string]$ScreenSaverExecutable = "$($env:SystemRoot)\System32\scrnsave.scr",

    [Parameter(Mandatory=$false)]
    [bool]$EnforcePasswordChangeOnNonAdmins = $true # Set to $false to disable forced change
)

# =============================================
# --- Configuration Section ---
# =============================================
Write-Host "Starting configuration script..." -ForegroundColor Yellow
Write-Host "Running as user: $($env:USERNAME)" -ForegroundColor Gray

# --- Disable USB Storage ---
# (Code remains the same as previous version - omitted for brevity)
Write-Host "Configuring USB storage..."
$usbStorPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor"
$expectedUsbStorStartValue = if ($DisableUsbStorage) { 4 } else { 3 } # 4 = Disabled, 3 = Enabled (Manual Start)

try {
    if (!(Test-Path $usbStorPath)) {
        Write-Warning "USB Storage registry path not found: $usbStorPath. Skipping configuration."
    } else {
        Set-ItemProperty -Path $usbStorPath -Name Start -Value $expectedUsbStorStartValue -ErrorAction Stop
        if ($DisableUsbStorage) {
            Write-Host "USB storage driver disabled (System-wide)." -ForegroundColor Green
        } else {
            Write-Host "USB storage driver set to enabled/manual start (System-wide)." -ForegroundColor Green
        }
    }
} catch {
    Write-Error "Failed to configure USB storage. Error: $($_.Exception.Message)"
}


# --- Password Policies (Using net accounts - Limited for Windows Home) ---
# (Code remains the same as previous version - omitted for brevity)
Write-Host "Configuring password policies using 'net accounts'..."
Write-Host "Note: Password complexity cannot be enforced via 'net accounts' on Windows Home." -ForegroundColor Yellow

# Minimum Password Length
try {
    Write-Verbose "Setting Minimum Password Length to $MinPasswordLength"
    net accounts /minpwlen:$MinPasswordLength
    if ($lasterrorcode -ne 0) { # Check exit code
         Write-Warning "Command 'net accounts /minpwlen' may have encountered an issue (Exit code: $lasterrorcode). Verification step will check current value."
    } else {
         Write-Host "Attempted to set Minimum password length to: $MinPasswordLength (System-wide)." -ForegroundColor Green
    }
} catch {
    Write-Error "Failed to run 'net accounts' for Minimum Password Length. Error: $($_.Exception.Message)"
}

# Maximum Password Age
try {
    Write-Verbose "Setting Maximum Password Age to $MaxPasswordAge days"
    net accounts /maxpwage:$MaxPasswordAge
    if ($lasterrorcode -ne 0) { # Check exit code
        Write-Warning "Command 'net accounts /maxpwage' may have encountered an issue (Exit code: $lasterrorcode). Verification step will check current value."
    } else {
        Write-Host "Attempted to set Maximum password age to: $MaxPasswordAge days (System-wide)." -ForegroundColor Green
    }
} catch {
    Write-Error "Failed to run 'net accounts' for Maximum Password Age. Error: $($_.Exception.Message)"
}

# --- Force Password Change for Non-Admins (Optional) ---
if ($EnforcePasswordChangeOnNonAdmins) {
    Write-Host "`nAttempting to flag non-administrator users for password change at next logon..." -ForegroundColor Yellow
    Write-Host "WARNING: This affects ALL enabled local users except the built-in Administrator (SID ending -500)." -ForegroundColor Yellow

    try {
        # Get enabled local users, excluding the built-in administrator account (SID typically ends in -500)
        $usersToFlag = Get-LocalUser -PrincipalSource Local | Where-Object { $_.Enabled -eq $true -and $_.SID.Value -notlike 'S-1-5-*-500' } -ErrorAction Stop

        if ($null -eq $usersToFlag) {
             Write-Host "No applicable user accounts found to flag for password change." -ForegroundColor Green
        } else {
            foreach ($user in $usersToFlag) {
                Write-Host "  Attempting to flag user: $($user.Name)"
                try {
                    # Use net user to force password change at next logon
                    net user $user.Name /logonpasswordchg:yes
                    if ($lasterrorcode -eq 0) {
                        Write-Host "    [SUCCESS] User '$($user.Name)' flagged to change password at next logon." -ForegroundColor Green
                    } else {
                         Write-Warning "    [WARN] Command 'net user $($user.Name) /logonpasswordchg:yes' finished with exit code $lasterrorcode. May not have succeeded."
                    }
                } catch {
                    Write-Error "    [FAIL] Failed to flag user '$($user.Name)'. Error: $($_.Exception.Message)"
                }
            }
        }
    } catch {
        Write-Error "Failed to retrieve local users or run 'net user' command. Error: $($_.Exception.Message)"
        Write-Warning "Skipping the forced password change section due to error."
    }
} else {
    Write-Host "`nSkipping the step to force password change for non-admins as requested." -ForegroundColor Cyan
}


# --- Automatic Updates (Information Only) ---
# (Code remains the same as previous version - omitted for brevity)
Write-Host "`nSkipping configuration of automatic updates..."
Write-Host "Note: Forcing specific Automatic Update behavior via registry policies is unreliable on Windows Home." -ForegroundColor Yellow
Write-Host "Recommend managing update settings via the Windows Settings app (Settings > Windows Update)." -ForegroundColor Cyan


# --- Screen Saver (For Current User Only) ---
# (Code remains the same as previous version - omitted for brevity)
Write-Host "`nConfiguring screen saver for the *current user* ($env:USERNAME)..."
$controlPanelDesktopPath = "HKCU:\Control Panel\Desktop"
$expectedScreenSaverActive = "1"
$expectedScreenSaverSecure = "1"
$expectedScreenSaverTimeoutString = $ScreenSaverTimeoutSeconds.ToString()
$expectedScreenSaverExe = $ScreenSaverExecutable

try {
    # Ensure the path exists (it almost always will for HKCU Control Panel)
    if (!(Test-Path $controlPanelDesktopPath)) {
        New-Item -Path $controlPanelDesktopPath -Force -ErrorAction Stop | Out-Null
    }

    Write-Verbose "Setting ScreenSaver executable to $expectedScreenSaverExe"
    Set-ItemProperty -Path $controlPanelDesktopPath -Name SCRNSAVE.EXE -Value $expectedScreenSaverExe -ErrorAction Stop

    Write-Verbose "Enabling Screen Saver Active flag"
    Set-ItemProperty -Path $controlPanelDesktopPath -Name ScreenSaveActive -Value $expectedScreenSaverActive -ErrorAction Stop

    Write-Verbose "Setting Screen Saver Timeout to $expectedScreenSaverTimeoutString seconds"
    Set-ItemProperty -Path $controlPanelDesktopPath -Name ScreenSaverTimeout -Value $expectedScreenSaverTimeoutString -ErrorAction Stop

    Write-Verbose "Setting Screen Saver Secure flag (require password)"
    Set-ItemProperty -Path $controlPanelDesktopPath -Name ScreenSaverIsSecure -Value $expectedScreenSaverSecure -ErrorAction Stop

    Write-Host "Screen saver configured for user '$($env:USERNAME)' with a $expectedScreenSaverTimeoutString second timeout and password requirement." -ForegroundColor Green

} catch {
    Write-Error "Failed to configure screen saver for user '$($env:USERNAME)'. Error: $($_.Exception.Message)"
}


# =============================================
# --- Verification Section ---
# =============================================
Write-Host "`nConfiguration attempt complete. Starting verification..." -ForegroundColor Yellow
# (Verification code remains the same as previous version - omitted for brevity)
# ... includes verification for USB, Password Policy, Auto Updates Info, Screen Saver ...

$verificationSuccess = $true # Track overall success

# --- Verify USB Storage ---
Write-Host "`nVerifying USB Storage setting..."
try {
    $currentUsbStartValue = Get-ItemProperty -Path $usbStorPath -Name Start -ErrorAction Stop | Select-Object -ExpandProperty Start
    if ($currentUsbStartValue -eq $expectedUsbStorStartValue) {
        Write-Host "  [PASS] USB Storage 'Start' value is correctly set to $currentUsbStartValue." -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] USB Storage 'Start' value is $currentUsbStartValue. Expected $expectedUsbStorStartValue." -ForegroundColor Red
        $verificationSuccess = $false
    }
} catch {
    Write-Host "  [WARN] Could not verify USB storage setting. Error reading registry: $($_.Exception.Message)" -ForegroundColor Yellow
}

# --- Verify Password Policies (net accounts) ---
Write-Host "Verifying Password Policy settings (via 'net accounts')..."
Write-Host "  Note: Verification depends on parsing English command output." -ForegroundColor Yellow
try {
    $netAccountsOutput = net accounts
    $currentMinLength = -1 # Default to invalid value
    $currentMaxAge = -1    # Default to invalid value

    # Parse Minimum Password Length
    if ($netAccountsOutput -match 'Minimum password length:\s*(\d+)') {
        $currentMinLength = [int]$matches[1]
    } elseif ($netAccountsOutput -match 'Minimum password length:\s*None') {
        $currentMinLength = 0 # Special case for 'None'
    }

    # Parse Maximum Password Age
    if ($netAccountsOutput -match 'Maximum password age \(days\):\s*(\d+)') {
        $currentMaxAge = [int]$matches[1]
    } elseif ($netAccountsOutput -match 'Maximum password age \(days\):\s*Unlimited') {
         if ($MaxPasswordAge -gt 999) { # Assuming large number implies 'Unlimited' intention
             $currentMaxAge = $MaxPasswordAge
         } else {
             $currentMaxAge = 99999 # Assign a distinct value indicating 'Unlimited' read from system
         }
    }

    # Check Minimum Length
    if ($currentMinLength -eq $MinPasswordLength) {
        Write-Host "  [PASS] Minimum password length is correctly set to $currentMinLength." -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Minimum password length is $currentMinLength. Expected $MinPasswordLength." -ForegroundColor Red
        $verificationSuccess = $false
    }

    # Check Maximum Age
    if ($currentMaxAge -eq 99999 -and $MaxPasswordAge -lt 999) { # Read 'Unlimited' but expected a specific number
        Write-Host "  [FAIL] Maximum password age is Unlimited. Expected $MaxPasswordAge days." -ForegroundColor Red
        $verificationSuccess = $false
    } elseif ($currentMaxAge -ne 99999 -and $currentMaxAge -eq $MaxPasswordAge) { # Read a number and it matches
         Write-Host "  [PASS] Maximum password age is correctly set to $currentMaxAge days." -ForegroundColor Green
    } elseif ($currentMaxAge -eq 99999 -and $MaxPasswordAge -ge 999) { # Read 'Unlimited' and expected 'Unlimited'
         Write-Host "  [PASS] Maximum password age is correctly set to Unlimited (as expected)." -ForegroundColor Green
    } else { # Read a number but it doesn't match, or other mismatch
        Write-Host "  [FAIL] Maximum password age is $currentMaxAge days. Expected $MaxPasswordAge days." -ForegroundColor Red
        $verificationSuccess = $false
    }

    Write-Host "  Note: Password complexity cannot be verified via 'net accounts'." -ForegroundColor Yellow

} catch {
    Write-Host "  [WARN] Could not verify password policy settings. Error running or parsing 'net accounts': $($_.Exception.Message)" -ForegroundColor Yellow
}

# --- Verify Automatic Updates ---
Write-Host "Verifying Automatic Updates setting..."
Write-Host "  [INFO] Automatic Update configuration was skipped due to Windows Home limitations." -ForegroundColor Cyan
Write-Host "  Please verify manually in Settings > Windows Update." -ForegroundColor Cyan

# --- Verify Screen Saver (Current User) ---
Write-Host "Verifying Screen Saver settings for the *current user* ($env:USERNAME)..."
try {
    $props = Get-ItemProperty -Path $controlPanelDesktopPath -ErrorAction Stop
    $ssVerified = $true

    # Check Active
    $currentSSActive = $props.'ScreenSaveActive'
    if ($currentSSActive -eq $expectedScreenSaverActive) {
        Write-Host "  [PASS] ScreenSaveActive is correctly set to '$currentSSActive'." -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] ScreenSaveActive is '$($currentSSActive)'. Expected '$expectedScreenSaverActive'." -ForegroundColor Red
        $ssVerified = $false; $verificationSuccess = $false
    }

    # Check Timeout
    $currentSSTimeout = $props.'ScreenSaverTimeout'
    if ($currentSSTimeout -eq $expectedScreenSaverTimeoutString) {
        Write-Host "  [PASS] ScreenSaverTimeout is correctly set to '$currentSSTimeout' seconds." -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] ScreenSaverTimeout is '$($currentSSTimeout)'. Expected '$expectedScreenSaverTimeoutString'." -ForegroundColor Red
        $ssVerified = $false; $verificationSuccess = $false
    }

    # Check Executable
    $currentSSExe = $props.'SCRNSAVE.EXE'
    if ($currentSSExe -eq $expectedScreenSaverExe) {
        Write-Host "  [PASS] SCRNSAVE.EXE is correctly set to '$currentSSExe'." -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] SCRNSAVE.EXE is '$($currentSSExe)'. Expected '$expectedScreenSaverExe'." -ForegroundColor Red
        $ssVerified = $false; $verificationSuccess = $false
    }

    # Check Secure (Password Required)
    $currentSSSecure = $props.'ScreenSaverIsSecure'
    if ($currentSSSecure -eq $expectedScreenSaverSecure) {
        Write-Host "  [PASS] ScreenSaverIsSecure (Require password) is correctly set to '$currentSSSecure'." -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] ScreenSaverIsSecure is '$($currentSSSecure)'. Expected '$expectedScreenSaverSecure'." -ForegroundColor Red
        $ssVerified = $false; $verificationSuccess = $false
    }

    if (-not $ssVerified) {
         Write-Host "  One or more screen saver settings for user '$($env:USERNAME)' are incorrect." -ForegroundColor Yellow
    }

} catch {
    Write-Host "  [WARN] Could not verify screen saver settings for user '$($env:USERNAME)'. Error reading registry: $($_.Exception.Message)" -ForegroundColor Yellow
}


# --- Final Summary ---
Write-Host "`n--- Verification Summary ---" -ForegroundColor Cyan
if ($verificationSuccess) {
    Write-Host "All verifiable settings appear to be correctly configured (within Windows Home limits)." -ForegroundColor Green
} else {
    Write-Host "One or more verifiable settings were NOT configured as expected. Please review the [FAIL] messages above." -ForegroundColor Red
}
Write-Host "Remember to manually verify Automatic Updates settings."
Write-Host "Screen saver settings verified only for user: $env:USERNAME"
if ($EnforcePasswordChangeOnNonAdmins) {
    Write-Host "Attempted to flag non-admin users for password change at next logon (check messages above for details)." -ForegroundColor Yellow
}

Write-Host "`nScript finished." -ForegroundColor Yellow
