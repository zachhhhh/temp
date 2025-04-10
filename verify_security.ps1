# PowerShell script to check security policies and settings applied by configure_security.ps1

# --- Check USB Storage ---
Write-Host "Checking USB storage configuration..."
$usbStorPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor"
$usbStorageStatus = Get-ItemProperty -Path $usbStorPath -Name Start -ErrorAction SilentlyContinue
if ($usbStorageStatus) {
    if ($usbStorageStatus.Start -eq 4) {
        Write-Host "USB storage is disabled (Start value is 4)."
    } else {
        Write-Host "USB storage is NOT disabled (Start value is $($usbStorageStatus.Start))."
    }
} else {
    Write-Host "USB storage configuration not found. Check if the path is correct or if the policy was applied."
}

# --- Check Password Policies ---
Write-Host "Checking password policies..."
$minPasswordLength = (secedit /export /cfg temp.cfg | Select-String -Pattern "MinimumPasswordLength") -split "=" | Select-Object -Last 1
$passwordComplexity = (secedit /export /cfg temp.cfg | Select-String -Pattern "PasswordComplexity") -split "=" | Select-Object -Last 1
$maxPasswordAge = (secedit /export /cfg temp.cfg | Select-String -Pattern "MaximumPasswordAge") -split "=" | Select-Object -Last 1
Remove-Item temp.cfg

if ($minPasswordLength -eq $null) {
    Write-Host "Minimum password length not found. Check if the policy was applied."
} else {
    Write-Host "Minimum password length is set to: $($minPasswordLength.Trim())"
}

if ($passwordComplexity -eq $null) {
    Write-Host "Password complexity setting not found. Check if the policy was applied."
} else {
    if ($passwordComplexity.Trim() -eq "1") {
        Write-Host "Password complexity is enabled."
    } else {
        Write-Host "Password complexity is NOT enabled."
    }
}

if ($maxPasswordAge -eq $null) {
    Write-Host "Maximum password age setting not found. Check if the policy was applied."
} else {
    Write-Host "Maximum password age is set to: $($maxPasswordAge.Trim()) days"
}

# --- Check Automatic Updates ---
Write-Host "Checking automatic updates configuration..."
$auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
$auOptions = Get-ItemProperty -Path $auPath -Name AUOptions -ErrorAction SilentlyContinue
$noAutoReboot = Get-ItemProperty -Path $auPath -Name NoAutoRebootWithLoggedOnUsers -ErrorAction SilentlyContinue

if ($auOptions) {
    if ($auOptions.AUOptions -eq 4) {
        Write-Host "Automatic updates are configured to auto download and install (AUOptions = 4)."
    } else {
        Write-Host "Automatic updates are NOT configured to auto download and install (AUOptions = $($auOptions.AUOptions))."
    }
} else {
    Write-Host "Automatic updates configuration (AUOptions) not found. Check if the policy was applied."
}

if ($noAutoReboot) {
    if ($noAutoReboot.NoAutoRebootWithLoggedOnUsers -eq 1) {
        Write-Host "Automatic reboot with logged-on users is prevented (NoAutoRebootWithLoggedOnUsers = 1)."
    } else {
        Write-Host "Automatic reboot with logged-on users is NOT prevented (NoAutoRebootWithLoggedOnUsers = $($noAutoReboot.NoAutoRebootWithLoggedOnUsers))."
    }
} else {
    Write-Host "Automatic reboot configuration (NoAutoRebootWithLoggedOnUsers) not found. Check if the policy was applied."
}

# --- Check Screen Saver ---
Write-Host "Checking screen saver configuration..."
$controlPanelDesktopPath = "HKCU:\Control Panel\Desktop"
$screenSaveActive = Get-ItemProperty -Path $controlPanelDesktopPath -Name ScreenSaveActive -ErrorAction SilentlyContinue
$screenSaverTimeout = Get-ItemProperty -Path $controlPanelDesktopPath -Name ScreenSaverTimeout -ErrorAction SilentlyContinue

if ($screenSaveActive) {
    if ($screenSaveActive.ScreenSaveActive -eq 1) {
        Write-Host "Screen saver is enabled."
    } else {
        Write-Host "Screen saver is NOT enabled."
    }
} else {
    Write-Host "Screen saver (ScreenSaveActive) setting not found. Check if the policy was applied."
}

if ($screenSaverTimeout) {
    Write-Host "Screen saver timeout is set to: $($screenSaverTimeout.ScreenSaverTimeout) seconds"
} else {
    Write-Host "Screen saver timeout setting not found. Check if the policy was applied."
}

Write-Host "Verification complete."
