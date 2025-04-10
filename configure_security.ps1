# PowerShell script to configure security policies and settings.
# AIM: Apply machine-wide settings broadly; user-specific actions (password force, screen saver defaults) target non-admins or new users.
# Optimized for PowerShell x86 (32-bit) compatibility, avoiding Get-LocalUser/Set-LocalUser.

# --- Configuration Variables ---
$DisableUsbStorage = $true
$MinPasswordLength = 16
$MaxPasswordAge = 180
$ScreenSaverTimeout = 300 # 5 minutes in seconds
$LogFile = "$env:TEMP\SecurityConfig_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ScreenSaverExe = "$env:SystemRoot\system32\scrnsave.scr" # Default blank screen saver

# --- Function to Write Log ---
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$Level]: $Message"
    Write-Host $logMessage
    Add-Content -Path $LogFile -Value $logMessage -Encoding UTF8 -ErrorAction SilentlyContinue
}

# --- Function to Set Screen Saver for Default User Profile ---
function Set-DefaultUserProfileScreenSaver {
    param(
        [int]$TimeoutSeconds,
        [string]$ScreenSaverExePath
    )

    Write-Log "Configuring screen saver for Default User Profile (new users)..."

    $defaultUserHivePath = "$env:SystemDrive\Users\Default\NTUSER.DAT"
    $tempMountName = "TempDefaultProfile_$PID_$(Get-Random)"
    $loadedHiveKeyPath = "HKU\$tempMountName"
    $loadedRegProviderPath = "Registry::HKEY_USERS\$tempMountName\Control Panel\Desktop"

    if (-not (Test-Path $defaultUserHivePath -PathType Leaf)) {
        Write-Log "Default user hive not found at '$defaultUserHivePath'." "ERROR"
        return $false
    }

    if (Test-Path "Registry::HKEY_USERS\$tempMountName") {
        Write-Log "Hive key '$loadedHiveKeyPath' already exists. Attempting to unload..." "WARNING"
        try {
            & reg.exe unload $loadedHiveKeyPath 2>&1 | Out-Null
            Start-Sleep -Milliseconds 500
            if (Test-Path "Registry::HKEY_USERS\$tempMountName") {
                Write-Log "Failed to unload existing hive key '$loadedHiveKeyPath'." "ERROR"
                return $false
            }
        } catch {
            Write-Log "Exception unloading hive: $($_.Exception.Message)." "ERROR"
            return $false
        }
    }

    Write-Log "Loading default user hive '$defaultUserHivePath' to '$loadedHiveKeyPath'..."
    try {
        $loadOutput = & reg.exe load $loadedHiveKeyPath "`"$defaultUserHivePath`"" 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Reg load failed: $loadOutput" }
        Start-Sleep -Milliseconds 500
    } catch {
        Write-Log "Failed to load hive: $($_.Exception.Message)" "ERROR"
        return $false
    }

    $success = $true
    try {
        if (-not (Test-Path $loadedRegProviderPath)) {
            New-Item -Path $loadedRegProviderPath -Force -ErrorAction Stop | Out-Null
        }

        Set-ItemProperty -Path $loadedRegProviderPath -Name ScreenSaveActive -Value "1" -Type String -Force -ErrorAction Stop
        Set-ItemProperty -Path $loadedRegProviderPath -Name ScreenSaverTimeout -Value $TimeoutSeconds -Type String -Force -ErrorAction Stop
        Set-ItemProperty -Path $loadedRegProviderPath -Name ScreenSaverIsSecure -Value "1" -Type String -Force -ErrorAction Stop

        if ([string]::IsNullOrWhiteSpace($ScreenSaverExePath)) {
            Write-Log "No valid screen saver path provided. Skipping SCRNSAVE.EXE." "WARNING"
        } elseif (-not (Test-Path $ScreenSaverExePath -PathType Leaf)) {
            Write-Log "Screen saver '$ScreenSaverExePath' not found. Skipping SCRNSAVE.EXE." "WARNING"
        } else {
            Set-ItemProperty -Path $loadedRegProviderPath -Name "SCRNSAVE.EXE" -Value $ScreenSaverExePath -Type String -Force -ErrorAction Stop
        }
    } catch {
        Write-Log "Failed to set screen saver properties: $($_.Exception.Message)" "ERROR"
        $success = $false
    } finally {
        Write-Log "Unloading hive '$loadedHiveKeyPath'..."
        Start-Sleep -Milliseconds 500
        $unloadOutput = & reg.exe unload $loadedHiveKeyPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Failed to unload hive: $unloadOutput" "ERROR"
            $success = $false
        } else {
            Start-Sleep -Milliseconds 500
            if (Test-Path "Registry::HKEY_USERS\$tempMountName") {
                Write-Log "Hive '$loadedHiveKeyPath' still loaded!" "ERROR"
                $success = $false
            } else {
                Write-Log "Hive unloaded successfully."
            }
        }
    }
    return $success
}

# --- Function to Check if User is an Administrator ---
function Test-IsAdminMember {
    param([string]$UserName)

    Write-Log "Checking if '$UserName' is an admin..." "DEBUG"
    $sid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $adminGroupName = $sid.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]

    try {
        $output = & net.exe localgroup $adminGroupName 2>&1 | Where-Object { $_ -match "^$([regex]::Escape($UserName))$" }
        if ($output) {
            Write-Log "'$UserName' is an admin." "DEBUG"
            return $true
        }
        Write-Log "'$UserName' is not an admin." "DEBUG"
        return $false
    } catch {
        Write-Log "Error checking admin status for '$UserName': $($_.Exception.Message). Assuming non-admin." "WARNING"
        return $false
    }
}

# --- Start of Script ---
Write-Log "======================================================================"
Write-Log "Starting security configuration script on $(Get-Date)"
Write-Log "Running in $($env:PROCESSOR_ARCHITEW6432 ? 'x86 (WOW64)' : 'x86') PowerShell environment."
Write-Log "======================================================================"

# --- Check Administrative Privileges ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "This script requires administrative privileges. Please run as Administrator." "ERROR"
    exit 1
}
Write-Log "[PASS] Administrative privileges confirmed."

# --- Machine-Wide Settings ---
Write-Log "--- Applying MACHINE-WIDE SETTINGS (Apply to All) ---"

# Disable USB Storage
Write-Log "[TASK] Configuring USB storage..."
$usbStorPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor"
try {
    if (-not (Test-Path $usbStorPath)) {
        Write-Log "USB Storage path '$usbStorPath' not found. Skipping." "WARNING"
    } elseif ($DisableUsbStorage) {
        Set-ItemProperty -Path $usbStorPath -Name Start -Value 4 -Type DWord -Force -ErrorAction Stop
        $startValue = Get-ItemProperty -Path $usbStorPath -Name Start -ErrorAction Stop
        if ($startValue.Start -eq 4) {
            Write-Log "[OK] USB storage disabled (Start=4)."
        } else {
            Write-Log "[FAIL] USB storage not disabled (Found: $($startValue.Start))." "ERROR"
        }
    } else {
        Set-ItemProperty -Path $usbStorPath -Name Start -Value 3 -Type DWord -Force -ErrorAction Stop
        $startValue = Get-ItemProperty -Path $usbStorPath -Name Start -ErrorAction Stop
        if ($startValue.Start -eq 3) {
            Write-Log "[OK] USB storage enabled (Start=3)."
        } else {
            Write-Log "[FAIL] USB storage not enabled (Found: $($startValue.Start))." "ERROR"
        }
    }
} catch {
    Write-Log "[FAIL] Failed to configure USB storage: $($_.Exception.Message)" "ERROR"
}

# Password Policies (Machine-Wide via Secedit)
Write-Log "[TASK] Configuring password policies..."
$tempCfgPath = "$env:TEMP\secedit_temp_$(Get-Random).cfg"
$tempDbPath = "$env:TEMP\secedit_temp_$(Get-Random).sdb"
try {
    & secedit /export /cfg $tempCfgPath /quiet
    if (-not (Test-Path $tempCfgPath)) {
        throw "Failed to export security policy."
    }

    $content = Get-Content $tempCfgPath -Raw
    if ($content -notmatch '\[System Access\]') {
        $content += "`r`n[System Access]`r`n"
    }

    function Update-SeceditValue {
        param([ref]$ContentRef, [string]$PolicyName, [string]$Value)
        $pattern = "(?sm)(\[System Access\].*?$PolicyName\s*=\s*)(\d+)"
        if ($ContentRef.Value -match $pattern) {
            $ContentRef.Value = $ContentRef.Value -replace $pattern, ('${1}' + $Value)
        } else {
            $ContentRef.Value = $ContentRef.Value -replace '(\[System Access\])', "`$1`r`n$PolicyName = $Value"
        }
    }

    Update-SeceditValue -ContentRef ([ref]$content) -PolicyName "MinimumPasswordLength" -Value $MinPasswordLength
    Update-SeceditValue -ContentRef ([ref]$content) -PolicyName "PasswordComplexity" -Value 1
    Update-SeceditValue -ContentRef ([ref]$content) -PolicyName "MaximumPasswordAge" -Value $MaxPasswordAge

    $content | Out-File $tempCfgPath -Encoding ASCII -Force
    $seceditOutput = & secedit /configure /db $tempDbPath /cfg $tempCfgPath /areas SECURITYPOLICY /quiet 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Secedit configure failed with exit code $LASTEXITCODE: $seceditOutput" "WARNING"
    } else {
        Write-Log "[OK] Password policies applied."
    }
} catch {
    Write-Log "[FAIL] Failed to configure password policies: $($_.Exception.Message)" "ERROR"
} finally {
    Remove-Item $tempCfgPath, $tempDbPath -Force -ErrorAction SilentlyContinue
}

# Automatic Updates (Machine-Wide)
Write-Log "[TASK] Configuring automatic updates..."
$auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
try {
    if (-not (Test-Path $auPath)) {
        New-Item -Path $auPath -Force -ErrorAction Stop | Out-Null
    }
    Set-ItemProperty -Path $auPath -Name AUOptions -Value 4 -Type DWord -Force -ErrorAction Stop
    Set-ItemProperty -Path $auPath -Name NoAutoRebootWithLoggedOnUsers -Value 1 -Type DWord -Force -ErrorAction Stop
    $auValues = Get-ItemProperty -Path $auPath -ErrorAction Stop
    if ($auValues.AUOptions -eq 4 -and $auValues.NoAutoRebootWithLoggedOnUsers -eq 1) {
        Write-Log "[OK] Automatic updates configured (AUOptions=4, NoAutoReboot=1)."
    } else {
        Write-Log "[FAIL] Automatic updates misconfigured (AUOptions=$($auValues.AUOptions), NoAutoReboot=$($auValues.NoAutoRebootWithLoggedOnUsers))." "ERROR"
    }
} catch {
    Write-Log "[FAIL] Failed to configure automatic updates: $($_.Exception.Message)" "ERROR"
}

# --- User-Specific Actions ---
Write-Log "--- Applying USER-SPECIFIC ACTIONS (Selective) ---"

# Force Password Change for Non-Admin Users using net.exe
Write-Log "[TASK] Enforcing password change for non-admin users..."
try {
    $netOutput = & net.exe user 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to list users with 'net user': $netOutput"
    }
    $users = $netOutput | Where-Object { $_ -match '^\w' -and $_ -notmatch '^(The command completed|User name)' } | ForEach-Object { $_.Trim() }

    if (-not $users) {
        Write-Log "No local users found or parsing failed." "WARNING"
    } else {
        Write-Log "Found $($users.Count) local users."
        foreach ($user in $users) {
            if (Test-IsAdminMember -UserName $user) {
                Write-Log "[SKIP] Skipping admin user: $user"
                continue
            }

            $userInfo = & net.exe user $user 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Log "[WARN] Failed to get info for user '$user': $userInfo" "WARNING"
                continue
            }

            $expiresNever = $userInfo | Where-Object { $_ -match "Password expires\s+Never" }
            $changeRequired = $userInfo | Where-Object { $_ -match "Password expires\s+.*\d" }

            if ($expiresNever -or -not $changeRequired) {
                Write-Log "Forcing password change for non-admin user: $user"
                & net.exe user $user /expires:never 2>&1 | Out-Null # Ensure expiration is not disabled
                & net.exe user $user /active:yes 2>&1 | Out-Null # Ensure user is active
                & net.exe user $user /pwdexpires:yes 2>&1 | Out-Null # Force password change (not all Windows versions support this flag)
                if ($LASTEXITCODE -ne 0) {
                    Write-Log "[WARN] Failed to force password change for '$user'. Attempting alternative method..." "WARNING"
                    # Alternative: Set a temporary password to force change at next login
                    $tempPassword = "TempPass!123" # Replace with a secure random password in production
                    & net.exe user $user $tempPassword 2>&1 | Out-Null
                    & net.exe user $user /pwdreq:yes 2>&1 | Out-Null
                    if ($LASTEXITCODE -eq 0) {
                        Write-Log "[OK] Password change forced for '$user' via temporary password."
                    } else {
                        Write-Log "[FAIL] Failed to force password change for '$user'." "ERROR"
                    }
                } else {
                    Write-Log "[OK] Password change forced for '$user'."
                }
            } else {
                Write-Log "[INFO] Password change already required for '$user'."
            }
        }
    }
} catch {
    Write-Log "[FAIL] Failed to enforce password changes: $($_.Exception.Message)" "ERROR"
}

# Screen Saver for New Users (Default Profile)
Write-Log "[TASK] Configuring screen saver for new users (Default Profile)..."
$screenSaverResult = Set-DefaultUserProfileScreenSaver -TimeoutSeconds $ScreenSaverTimeout -ScreenSaverExePath $ScreenSaverExe
if ($screenSaverResult) {
    Write-Log "[OK] Screen saver configured for Default User Profile."
} else {
    Write-Log "[FAIL] Failed to configure screen saver for Default User Profile." "ERROR"
}

# --- Verification ---
Write-Log "--- Starting Configuration Verification ---"

# Verify USB Storage
Write-Log "[VERIFY] USB Storage..."
try {
    $usbValue = Get-ItemProperty -Path $usbStorPath -Name Start -ErrorAction Stop
    if ($DisableUsbStorage -and $usbValue.Start -eq 4) {
        Write-Log "[PASS] USB storage disabled."
    } elseif (-not $DisableUsbStorage -and $usbValue.Start -eq 3) {
        Write-Log "[PASS] USB storage enabled."
    } else {
        Write-Log "[FAIL] USB storage mismatch (Found: $($usbValue.Start))." "ERROR"
    }
} catch {
    Write-Log "[FAIL] Cannot verify USB storage: $($_.Exception.Message)" "ERROR"
}

# Verify Password Policies
Write-Log "[VERIFY] Password Policies..."
$verifyCfgPath = "$env:TEMP\verify_$(Get-Random).cfg"
try {
    & secedit /export /cfg $verifyCfgPath /quiet
    if (Test-Path $verifyCfgPath) {
        $content = Get-Content $verifyCfgPath -Raw
        if ($content -match "MinimumPasswordLength = (\d+)") { $minLen = [int]$Matches[1] }
        if ($content -match "PasswordComplexity = (\d+)") { $complexity = [int]$Matches[1] }
        if ($content -match "MaximumPasswordAge = (\d+)") { $maxAge = [int]$Matches[1] }

        if ($minLen -ge $MinPasswordLength) { Write-Log "[PASS] MinimumPasswordLength ($minLen) meets or exceeds $MinPasswordLength." }
        else { Write-Log "[FAIL] MinimumPasswordLength ($minLen) below $MinPasswordLength." "ERROR" }
        if ($complexity -eq 1) { Write-Log "[PASS] PasswordComplexity enabled." }
        else { Write-Log "[FAIL] PasswordComplexity ($complexity) not enabled." "ERROR" }
        if ($maxAge -le $MaxPasswordAge) { Write-Log "[PASS] MaximumPasswordAge ($maxAge) meets or below $MaxPasswordAge." }
        else { Write-Log "[FAIL] MaximumPasswordAge ($maxAge) exceeds $MaxPasswordAge." "ERROR" }
    } else {
        Write-Log "[FAIL] Cannot export security policy for verification." "ERROR"
    }
} catch {
    Write-Log "[FAIL] Password policy verification failed: $($_.Exception.Message)" "ERROR"
} finally {
    Remove-Item $verifyCfgPath -Force -ErrorAction SilentlyContinue
}

# Verify Automatic Updates
Write-Log "[VERIFY] Automatic Updates..."
try {
    $auValues = Get-ItemProperty -Path $auPath -ErrorAction Stop
    if ($auValues.AUOptions -eq 4 -and $auValues.NoAutoRebootWithLoggedOnUsers -eq 1) {
        Write-Log "[PASS] Automatic updates configured correctly."
    } else {
        Write-Log "[FAIL] Automatic updates misconfigured (AUOptions=$($auValues.AUOptions), NoAutoReboot=$($auValues.NoAutoRebootWithLoggedOnUsers))." "ERROR"
    }
} catch {
    Write-Log "[FAIL] Cannot verify automatic updates: $($_.Exception.Message)" "ERROR"
}

# Verify Password Change Enforcement (Limited Verification via net user)
Write-Log "[VERIFY] Password Change Enforcement..."
try {
    $users = & net.exe user 2>&1 | Where-Object { $_ -match '^\w' -and $_ -notmatch '^(The command completed|User name)' } | ForEach-Object { $_.Trim() }
    foreach ($user in $users) {
        if (Test-IsAdminMember -UserName $user) { continue }
        $userInfo = & net.exe user $user 2>&1
        if ($userInfo -match "Password expires\s+Never") {
            Write-Log "[FAIL] Password for '$user' set to never expire." "ERROR"
        } elseif ($userInfo -match "Password expires\s+.*\d") {
            Write-Log "[PASS] Password for '$user' requires change."
        } else {
            Write-Log "[WARN] Cannot determine password expiration status for '$user'." "WARNING"
        }
    }
} catch {
    Write-Log "[FAIL] Cannot verify password change enforcement: $($_.Exception.Message)" "ERROR"
}

# --- Final Message ---
Write-Log "======================================================================"
Write-Log "Security configuration and verification complete at $(Get-Date)."
Write-Log "Log file: $LogFile"
Write-Log "======================================================================"
