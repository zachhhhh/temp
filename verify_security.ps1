# PowerShell script to verify security policies and settings.

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
    Write-Host "USB storage configuration not found. Check if the policy was applied."
}

# --- Check Password Policies (Direct Registry Check) ---
Write-Host "Checking password policies..."
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

try {
    $minPasswordLength = Get-ItemProperty -Path $lsaPath -Name "MinimumPasswordLength" -ErrorAction Stop
    Write-Host "Minimum password length is set to: $($minPasswordLength.MinimumPasswordLength)"
} catch {
    Write-Warning "Minimum password length not found. Check if the policy was applied."
}

try {
    $passwordComplexity = Get-ItemProperty -Path $lsaPath -Name "PasswordComplexity" -ErrorAction Stop
    if ($passwordComplexity.PasswordComplexity -eq 1) {
        Write-Host "Password complexity is enabled."
    } else {
        Write-Host "Password complexity is NOT enabled."
    }
} catch {
    Write-Warning "Password complexity setting not found. Check if the policy was applied."
}

try {
    $maxPasswordAge = Get-ItemProperty -Path $lsaPath -Name "MaxPasswordAge" -ErrorAction Stop
    $maxPasswordAgeDays = [math]::Round($maxPasswordAge.MaxPasswordAge / (24 * 60 * 60))
    Write-Host "Maximum password age is set to: $($maxPasswordAgeDays) days"
} catch {
    Write-Warning "Maximum password age setting not found. Check if the policy was applied."
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
$scrnsaveExe = Get-ItemProperty -Path $controlPanelDesktopPath -Name SCRNSAVE.EXE -ErrorAction SilentlyContinue

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
    Write-Host "Screen saver timeout is set to: $($screenSaverTimeout.ScreenSaverTimeout / 60) minutes"
} else {
    Write-Host "Screen saver timeout setting not found. Check if the policy was applied."
}

if ($scrnsaveExe) {
    Write-Host "Screen saver executable is set to: $($scrnsaveExe.SCRNSAVE.EXE)"
} else {
    Write-Host "Screen saver executable (SCRNSAVE.EXE) setting not found. Check if the policy was applied."
}

Write-Host "Verification complete."
