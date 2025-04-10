# PowerShell script to configure security policies and settings.

# --- Configuration Variables ---
$DisableUsbStorage = $true
$MinPasswordLength = 16
$MaxPasswordAge = 180
$ScreenSaverTimeout = 300 # 5 minutes in seconds

# --- Disable USB Storage ---
Write-Host "Configuring USB storage..."
$usbStorPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor"

try {
    Set-ItemProperty -Path $usbStorPath -Name Start -Value 4 -ErrorAction Stop
    if ($DisableUsbStorage) {
        Write-Host "USB storage disabled."
    } else {
        Write-Host "USB Storage Disable variable is set to false, therefore USB storage will not be disabled."
    }
} catch {
    Write-Warning "Failed to configure USB storage: $($_.Exception.Message)"
}

# --- Password Policies (Direct Registry Manipulation) ---
Write-Host "Configuring password policies..."

try {
    # Minimum Password Length
    $minPwdPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $minPwdPath -Name "MinimumPasswordLength" -Value $MinPasswordLength -Force -ErrorAction Stop
    Write-Host "Minimum password length set to: $MinPasswordLength"

    # Password Complexity
    $complexityPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $complexityPath -Name "restrictanonymous" -Value 0 -Force -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "everyoneincludesanonymous" -Value 0 -Force -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLmHosts" -Value 1 -Force -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Force -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "PasswordComplexity" -Value 1 -Force -ErrorAction Stop
    Write-Host "Password complexity enabled."

    # Maximum Password Age
    $maxPwdAgePath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $maxPwdAgePath -Name "MaxPasswordAge" -Value ($MaxPasswordAge * 24 * 60 * 60) -Force -ErrorAction Stop # Convert days to seconds
    Write-Host "Maximum password age set to: $MaxPasswordAge days"

} catch {
    Write-Warning "Failed to configure password policies: $($_.Exception.Message)"
}

# --- Automatic Updates ---
Write-Host "Configuring automatic updates..."
$auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

try {
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
    }
    if (-not (Test-Path $auPath)) {
        New-Item -Path $auPath -Force | Out-Null
    }

    Set-ItemProperty -Path $auPath -Name AUOptions -Value 4 -Force -ErrorAction Stop # Auto download and install
    Set-ItemProperty -Path $auPath -Name NoAutoRebootWithLoggedOnUsers -Value 1 -Force -ErrorAction Stop # Prevents automatic reboot if users are logged on.
    Write-Host "Automatic updates configured."

} catch {
    Write-Warning "Failed to configure automatic updates: $($_.Exception.Message)"
}

# --- Screen Saver ---
Write-Host "Configuring screen saver..."
$controlPanelDesktopPath = "HKCU:\Control Panel\Desktop"

try {
    Set-ItemProperty -Path $controlPanelDesktopPath -Name ScreenSaveActive -Value 1 -Force -ErrorAction Stop
    Set-ItemProperty -Path $controlPanelDesktopPath -Name ScreenSaverTimeout -Value $ScreenSaverTimeout -Force -ErrorAction Stop
    Set-ItemProperty -Path $controlPanelDesktopPath -Name SCRNSAVE.EXE -Value "%SystemRoot%\system32\scrnsave.scr" -Force -ErrorAction Stop # Default screen saver
    Write-Host "Screen saver enabled with a $($ScreenSaverTimeout / 60) minute timeout."

} catch {
    Write-Warning "Failed to configure screen saver: $($_.Exception.Message)"
}

Write-Host "Configuration complete."
