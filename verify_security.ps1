# PowerShell script to verify security policies and settings.

# --- Function to Check Registry Value ---
function Check-RegistryValue {
    param(
        [string]$path,
        [string]$name,
        [string]$friendlyName,
        [string]$expectedValue,
        [scriptblock]$valueTransform = {$_.Value} # Default: return the raw value
    )

    try {
        $value = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop
        $actualValue = &$valueTransform $value
        Write-Host "$friendlyName: $($actualValue)"
    } catch {
        Write-Warning "$friendlyName setting not found. Check registry path or key name."
        Write-Verbose "Error: $($_.Exception.Message)" -Verbose
        # List available properties for debugging
        if (Test-Path $path) {
          Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSDrive,PSProvider | Format-List | Out-String | Write-Host
        }
    }
}

# --- Configuration Variables ---
$DisableUsbStorage = $true
$MinPasswordLength = 16
$MaxPasswordAge = 180

# --- Check USB Storage ---
Write-Host "Checking USB storage configuration..."
$usbStorPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor"
Check-RegistryValue -Path $usbStorPath -Name "Start" -friendlyName "USB Storage Start Value" -expectedValue 4

# --- Check Password Policies (Direct Registry Check) ---
Write-Host "Checking password policies..."
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

Check-RegistryValue -Path $lsaPath -Name "MinimumPasswordLength" -friendlyName "Minimum Password Length" -expectedValue $MinPasswordLength

Check-RegistryValue -Path $lsaPath -Name "PasswordComplexity" -friendlyName "Password Complexity" -expectedValue 1 -valueTransform {$_.PasswordComplexity}

Check-RegistryValue -Path $lsaPath -Name "MaxPasswordAge" -friendlyName "Maximum Password Age" -expectedValue ($MaxPasswordAge * 24 * 60 * 60) -valueTransform { [math]::Round($_.MaxPasswordAge / (24 * 60 * 60)) }

# --- Check Automatic Updates ---
Write-Host "Checking automatic updates configuration..."
$auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
Check-RegistryValue -Path $auPath -Name "AUOptions" -friendlyName "Automatic Updates Options" -expectedValue 4
Check-RegistryValue -Path $auPath -Name "NoAutoRebootWithLoggedOnUsers" -friendlyName "No Auto Reboot With LoggedOn Users" -expectedValue 1

# --- Check Screen Saver ---
Write-Host "Checking screen saver configuration..."
$controlPanelDesktopPath = "HKCU:\Control Panel\Desktop"
Check-RegistryValue -Path $controlPanelDesktopPath -Name "ScreenSaveActive" -friendlyName "Screen Saver Active" -expectedValue 1
Check-RegistryValue -Path $controlPanelDesktopPath -Name "ScreenSaverTimeout" -friendlyName "Screen Saver Timeout" -expectedValue $ScreenSaverTimeout
Check-RegistryValue -Path $controlPanelDesktopPath -Name "SCRNSAVE.EXE" -friendlyName "Screen Saver Executable" -expectedValue "%SystemRoot%\system32\scrnsave.scr"

Write-Host "Verification complete."
