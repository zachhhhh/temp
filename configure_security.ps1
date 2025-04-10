#存以下script為configure_security.ps1
#用admin執行
.\configure_security.ps1

# PowerShell script to disable USB storage, enforce password policies, enable automatic updates, and screen saver.

# --- Configuration Variables ---
$DisableUsbStorage = $true
$MinPasswordLength = 16
$MaxPasswordAge = 180
$ScreenSaverTimeout = 300 # 5 minutes in seconds

# --- Disable USB Storage ---
Write-Host "Configuring USB storage..."
$usbStorPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor"

if ($DisableUsbStorage) {
    Set-ItemProperty -Path $usbStorPath -Name Start -Value 4
    Write-Host "USB storage disabled."
} else {
    Write-Host "USB Storage Disable variable is set to false, therefore USB storage will not be disabled."
}

# --- Password Policies (Using secedit) ---
Write-Host "Configuring password policies..."
secedit /export /cfg temp.cfg
$content = Get-Content temp.cfg

# Minimum Password Length & Complexity & Max Age
$content = $content -replace "MinimumPasswordLength = 0", "MinimumPasswordLength = $MinPasswordLength"
$content = $content -replace "PasswordComplexity = 0", "PasswordComplexity = 1" # Enable complexity
$content = $content -replace "MaximumPasswordAge = 0", "MaximumPasswordAge = $MaxPasswordAge"
$content | Set-Content temp.cfg

secedit /configure /db temp.sdb /cfg temp.cfg /areas SECURITYPOLICY
Remove-Item temp.cfg, temp.sdb

Write-Host "Minimum password length set to: $MinPasswordLength"
Write-Host "Password complexity enabled."
Write-Host "Maximum password age set to: $MaxPasswordAge days"

# --- Automatic Updates ---
Write-Host "Configuring automatic updates..."
$auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
New-Item -Path $auPath -Force | Out-Null
Set-ItemProperty -Path $auPath -Name AUOptions -Value 4 # Auto download and install
Set-ItemProperty -Path $auPath -Name NoAutoRebootWithLoggedOnUsers -Value 1 # Prevents automatic reboot if users are logged in.
Write-Host "Automatic updates configured."

# --- Screen Saver ---
Write-Host "Configuring screen saver..."
$controlPanelDesktopPath = "HKCU:\Control Panel\Desktop"
Set-ItemProperty -Path $controlPanelDesktopPath -Name ScreenSaveActive -Value 1
Set-ItemProperty -Path $controlPanelDesktopPath -Name ScreenSaverTimeout -Value $ScreenSaverTimeout
Set-ItemProperty -Path $controlPanelDesktopPath -Name SCRNSAVE.EXE -Value "%SystemRoot%\system32\scrnsave.scr" # Default screen saver
Write-Host "Screen saver enabled with a $ScreenSaverTimeout second timeout."

Write-Host "Configuration complete."
