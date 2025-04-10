#Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

#Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope CurrentUser

#Right click script property to unlock before execution

#存以下script為configure_security.ps1
#用admin執行
#.\configure_security.ps1

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

# --- Password Policies (Using secedit) ---
Write-Host "Configuring password policies..."
$tempCfgPath = "$env:TEMP\temp.cfg"
$tempDbPath = "$env:TEMP\temp.sdb"

try {
    secedit /export /cfg "$tempCfgPath"
    $content = Get-Content "$tempCfgPath"

    # Minimum Password Length & Complexity & Max Age
    $content = $content -replace "MinimumPasswordLength = \d+", "MinimumPasswordLength = $MinPasswordLength"
    $content = $content -replace "PasswordComplexity = \d+", "PasswordComplexity = 1" # Enable complexity
    $content = $content -replace "MaximumPasswordAge = \d+", "MaximumPasswordAge = $MaxPasswordAge"
    $content | Set-Content "$tempCfgPath"

    secedit /configure /db "$tempDbPath" /cfg "$tempCfgPath" /areas SECURITYPOLICY

    Write-Host "Minimum password length set to: $MinPasswordLength"
    Write-Host "Password complexity enabled."
    Write-Host "Maximum password age set to: $MaxPasswordAge days"

} catch {
    Write-Warning "Failed to configure password policies: $($_.Exception.Message)"
} finally {
    if (Test-Path $tempCfgPath) { Remove-Item $tempCfgPath }
    if (Test-Path $tempDbPath) { Remove-Item $tempDbPath }
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

    Set-ItemProperty -Path $auPath -Name AUOptions -Value 4 -ErrorAction Stop # Auto download and install
    Set-ItemProperty -Path $auPath -Name NoAutoRebootWithLoggedOnUsers -Value 1 -ErrorAction Stop # Prevents automatic reboot if users are logged in.
    Write-Host "Automatic updates configured."

} catch {
    Write-Warning "Failed to configure automatic updates: $($_.Exception.Message)"
}

# --- Screen Saver ---
Write-Host "Configuring screen saver..."
$controlPanelDesktopPath = "HKCU:\Control Panel\Desktop"

try {
    Set-ItemProperty -Path $controlPanelDesktopPath -Name ScreenSaveActive -Value 1 -ErrorAction Stop
    Set-ItemProperty -Path $controlPanelDesktopPath -Name ScreenSaverTimeout -Value $ScreenSaverTimeout -ErrorAction Stop
    Set-ItemProperty -Path $controlPanelDesktopPath -Name SCRNSAVE.EXE -Value "%SystemRoot%\system32\scrnsave.scr" -ErrorAction Stop # Default screen saver
    Write-Host "Screen saver enabled with a $($ScreenSaverTimeout / 60) minute timeout."

} catch {
    Write-Warning "Failed to configure screen saver: $($_.Exception.Message)"
}

Write-Host "Configuration complete."
