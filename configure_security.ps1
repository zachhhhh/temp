#Requires -RunAsAdministrator

<#
.SYNOPSIS
Configures security and preference settings on Windows 11 Home, optionally enforcing password changes.
.DESCRIPTION
This script attempts to configure the following on Windows 11 Home:
- Disable USB mass storage devices (System-wide).
- Set basic password policies using 'net accounts' (System-wide, limited options on Home).
- Optionally flags all standard local users to change their password at next logon.
- Configure screen saver settings for the *current user* running the script.
.NOTES
Version: 1.6
Author: Gemini AI (Modified from user input)
Date: 2025-04-10

IMPORTANT: It's recommended to save this script file with UTF-8 with BOM encoding if using non-English characters in comments or strings.

IMPORTANT WINDOWS HOME LIMITATIONS:
- Full password policies (like complexity) cannot be enforced via script on Windows Home.
- Group Policy registry keys (like those for Automatic Updates) are not reliably supported on Windows Home.
- Settings applied to HKCU (Screen Saver) only affect the user running the script.
- Forced password change flags ALL non-built-in-admin users, regardless of current password compliance.
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
Write-Host "System Time: $(Get-Date)" -ForegroundColor Gray
Write-Host "System Culture: $(Get-Culture).Name" -ForegroundColor Gray

# --- Disable USB Storage ---
Write-Host "`nConfiguring USB storage..."
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
Write-Host "`nConfiguring password policies using 'net accounts'..."
Write-Host "Note: Password complexity cannot be enforced via 'net accounts' on Windows Home." -ForegroundColor Yellow

# Minimum Password Length
try {
    Write-Verbose "Setting Minimum Password Length to $MinPasswordLength"
    net accounts /minpwlen:$MinPasswordLength
    if ($lasterrorcode -ne 0) { # Check exit code
         Write-Warning "Command 'net accounts /minpwlen' may have encountered an issue (Exit code: $lasterrorcode)."
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
        Write-Warning "Command 'net accounts /maxpwage' may have encountered an issue (Exit code: $lasterrorcode)."
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

        if ($null -eq $usersToFlag -or $usersToFlag.Count -eq 0) {
             Write-Host "No applicable user accounts found to flag for password change." -ForegroundColor Green
        } else {
            # Ensure $usersToFlag is an array even if only one user is found
            if ($usersToFlag -isnot [array]) { $usersToFlag = @($usersToFlag) }

            foreach ($user in $usersToFlag) {
                Write-Host "  Attempting to flag user: $($user.Name)"
                try {
                    # Use net user to force password change at next logon
                    # Enclose username in quotes in case it contains spaces
                    net user "$($user.Name)" /logonpasswordchg:yes
                    if ($lasterrorcode -eq 0) {
                        Write-Host "    [SUCCESS] User '$($user.Name)' flagged to change password at next logon." -ForegroundColor Green
                    } else {
                         Write-Warning "    [WARN] Command 'net user ""$($user.Name)"" /logonpasswordchg:yes' finished with exit code $lasterrorcode. May not have succeeded."
                    }
                } catch {
                    Write-Error "    [FAIL] Failed to flag user '$($user.Name)'. Error: $($_.Exception.Message)"
                }
            }
        }
    } catch {
        # Catch errors from Get-LocalUser specifically if command not found etc.
         if ($_.Exception.CommandNotFound) {
            Write-Error "Failed to execute 'Get-LocalUser'. This cmdlet requires PowerShell 5.1 or newer. Cannot flag users."
        } else {
            Write-Error "Failed to retrieve local users or run 'net user' command. Error: $($_.Exception.Message)"
        }
        Write-Warning "Skipping the forced password change section due to error."
    }
} else {
    Write-Host "`nSkipping the step to force password change for non-admins as requested." -ForegroundColor Cyan
}


# --- Automatic Updates (Information Only) ---
Write-Host "`nSkipping configuration of automatic updates..."
Write-Host "Note: Forcing specific Automatic Update behavior via registry policies is unreliable on Windows Home." -ForegroundColor Yellow
Write-Host "Recommend managing update settings via the Windows Settings app (Settings > Windows Update)." -ForegroundColor Cyan


# --- Screen Saver (For Current User Only) ---
Write-Host "`nConfiguring screen saver for the *current user* ($env:USERNAME)..."
$controlPanelDesktopPath = "HKCU:\Control Panel\Desktop"
$expectedScreenSaverActive = "1"
$expectedScreenSaverSecure = "1"
$expectedScreenSaverTimeoutString = $ScreenSaverTimeoutSeconds.ToString()
$expectedScreenSaverExe = $ScreenSaverExecutable

try {
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
# --- End of Configuration ---
# =============================================

Write-Host "`nConfiguration script finished." -ForegroundColor Yellow
# End of Script
