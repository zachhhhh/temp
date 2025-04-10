#Requires -RunAsAdministrator

<#
.SYNOPSIS
Configures security and preference settings on Windows 11 Home.
.DESCRIPTION
This script attempts to configure the following on Windows 11 Home:
- Disable USB mass storage devices (System-wide).
- Set basic password policies using 'net accounts' (System-wide, limited options on Home).
- Configure screen saver settings for the *current user* running the script.
.NOTES
Version: 1.1
Author: Gemini AI (Modified from user input)
Date: 2025-04-10

IMPORTANT WINDOWS HOME LIMITATIONS:
- Full password policies (like complexity) cannot be enforced via script on Windows Home.
- Group Policy registry keys (like those for Automatic Updates) are not reliably supported on Windows Home.
- Settings applied to HKCU only affect the user running the script. Applying to all non-admin users requires more advanced techniques (e.g., modifying default profile, running as each user) not included here.
#>

# --- Configuration Variables ---
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [bool]$DisableUsbStorage = $true,

    [Parameter(Mandatory=$false)]
    [int]$MinPasswordLength = 12, # Reduced default as 16 might be high without complexity enforcement

    [Parameter(Mandatory=$false)]
    [int]$MaxPasswordAge = 90,  # Common default

    [Parameter(Mandatory=$false)]
    [int]$ScreenSaverTimeoutSeconds = 600, # 10 minutes

    [Parameter(Mandatory=$false)]
    [string]$ScreenSaverExecutable = "$($env:SystemRoot)\System32\scrnsave.scr" # Bubbles.scr, Mystify.scr, Ribbons.scr are other options
)

Write-Host "Starting configuration script..." -ForegroundColor Yellow

# --- Disable USB Storage ---
Write-Host "Configuring USB storage..."
$usbStorPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor"
$usbStorStartValue = if ($DisableUsbStorage) { 4 } else { 3 } # 4 = Disabled, 3 = Enabled (Manual Start)

try {
    if (!(Test-Path $usbStorPath)) {
        Write-Warning "USB Storage registry path not found: $usbStorPath. Skipping."
    } else {
        Set-ItemProperty -Path $usbStorPath -Name Start -Value $usbStorStartValue -ErrorAction Stop
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
Write-Host "Configuring password policies using 'net accounts'..."
Write-Host "Note: Password complexity cannot be enforced via 'net accounts' on Windows Home." -ForegroundColor Yellow

# Minimum Password Length
try {
    Write-Verbose "Setting Minimum Password Length to $MinPasswordLength"
    net accounts /minpwlen:$MinPasswordLength
    # Check for errors (net accounts often returns 0 even on failure, so checking output might be needed if crucial)
    # $lasterrorcode can sometimes be useful after external commands
    if ($lasterrorcode -eq 0) {
         Write-Host "Minimum password length set to: $MinPasswordLength (System-wide)." -ForegroundColor Green
    } else {
         Write-Warning "Command 'net accounts /minpwlen' may have encountered an issue (Exit code: $lasterrorcode). Verify setting manually."
    }
} catch {
    Write-Error "Failed to set Minimum Password Length using 'net accounts'. Error: $($_.Exception.Message)"
}

# Maximum Password Age
try {
    Write-Verbose "Setting Maximum Password Age to $MaxPasswordAge days"
    net accounts /maxpwage:$MaxPasswordAge
    if ($lasterrorcode -eq 0) {
        Write-Host "Maximum password age set to: $MaxPasswordAge days (System-wide)." -ForegroundColor Green
    } else {
         Write-Warning "Command 'net accounts /maxpwage' may have encountered an issue (Exit code: $lasterrorcode). Verify setting manually."
    }
} catch {
    Write-Error "Failed to set Maximum Password Age using 'net accounts'. Error: $($_.Exception.Message)"
}

# --- Automatic Updates (Information Only) ---
Write-Host "Configuring automatic updates..."
Write-Host "Note: Forcing specific Automatic Update behavior via registry policies is unreliable on Windows Home." -ForegroundColor Yellow
Write-Host "Recommend managing update settings via the Windows Settings app (Settings > Windows Update)." -ForegroundColor Cyan
# Optional: Trigger an update check
# Write-Host "Attempting to trigger a Windows Update check..."
# try {
#   Start-Process "ms-settings:windowsupdate" # Opens the Settings page
#   # Alternative (more aggressive, uses COM object):
#   # $updateSession = New-Object -ComObject Microsoft.Update.Session
#   # $updateSearcher = $updateSession.CreateUpdateSearcher()
#   # Write-Host "Searching for updates..."
#   # $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
#   # Write-Host ("Found {0} updates." -f $searchResult.Updates.Count)
# } catch {
#   Write-Warning "Could not trigger update check. Error: $($_.Exception.Message)"
# }


# --- Screen Saver (For Current User Only) ---
Write-Host "Configuring screen saver for the *current user* ($env:USERNAME)..."
$controlPanelDesktopPath = "HKCU:\Control Panel\Desktop"

try {
    # Ensure the path exists (it almost always will for HKCU Control Panel)
    if (!(Test-Path $controlPanelDesktopPath)) {
        New-Item -Path $controlPanelDesktopPath -Force -ErrorAction Stop | Out-Null
    }

    # Set Screen Saver Executable (.scr file)
    Write-Verbose "Setting ScreenSaver executable to $ScreenSaverExecutable"
    Set-ItemProperty -Path $controlPanelDesktopPath -Name SCRNSAVE.EXE -Value $ScreenSaverExecutable -ErrorAction Stop

    # Enable Screen Saver
    Write-Verbose "Enabling Screen Saver Active flag"
    Set-ItemProperty -Path $controlPanelDesktopPath -Name ScreenSaveActive -Value "1" -ErrorAction Stop # Value should be string "1"

    # Set Timeout
    Write-Verbose "Setting Screen Saver Timeout to $ScreenSaverTimeoutSeconds seconds"
    Set-ItemProperty -Path $controlPanelDesktopPath -Name ScreenSaverTimeout -Value $ScreenSaverTimeoutSeconds -ErrorAction Stop # Value should be string

    # Optional: Require password on resume (ScreenSaverIsSecure)
    Write-Verbose "Setting Screen Saver Secure flag (require password)"
    Set-ItemProperty -Path $controlPanelDesktopPath -Name ScreenSaverIsSecure -Value "1" -ErrorAction Stop # Value should be string "1"

    Write-Host "Screen saver configured for user '$($env:USERNAME)' with a $ScreenSaverTimeoutSeconds second timeout and password requirement." -ForegroundColor Green

} catch {
    Write-Error "Failed to configure screen saver for user '$($env:USERNAME)'. Error: $($_.Exception.Message)"
}

Write-Host "Configuration script finished." -ForegroundColor Yellow
