# PowerShell script to configure security policies and settings.
# AIM: Apply settings broadly, but user-specific actions (password force, screen saver defaults) target non-admins or new users.

# --- Configuration Variables ---
$DisableUsbStorage = $true
$MinPasswordLength = 16
$MaxPasswordAge = 180
$ScreenSaverTimeout = 300 # 5 minutes in seconds
$LogFile = "$env:TEMP\SecurityConfig_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
# Use a common, likely available screensaver like Blank
$ScreenSaverExe = "$env:SystemRoot\system32\scrnsave.scr"

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
        [string]$ScreenSaverExePath # Should be the full path like "$env:SystemRoot\system32\scrnsave.scr"
    )

    Write-Log "Attempting to configure screen saver settings for the Default User Profile (template for NEW users)..."

    $defaultUserHivePath = Join-Path $env:SystemDrive "Users\Default\NTUSER.DAT"
    $tempMountName = "TempDefaultProfile_$($PID)_$(Get-Random)" # Unique temporary name
    $loadedHiveKeyPath = "HKEY_USERS\$tempMountName" # Path for reg command (note: HKU is alias)
    $loadedRegProviderPath = "Registry::$loadedHiveKeyPath\Control Panel\Desktop" # Path for PowerShell provider

    if (-not (Test-Path $defaultUserHivePath -PathType Leaf)) {
        Write-Log "Default user profile hive file not found at '$defaultUserHivePath'. Cannot configure default user settings." "ERROR"
        return $false # Indicate failure
    }

    # Check if already loaded (unlikely but good practice)
    if (Test-Path -Path "Registry::$loadedHiveKeyPath") {
         Write-Log "Temporary hive key '$loadedHiveKeyPath' already exists. Attempting to unload first." "WARNING"
         try {
             $unloadOutput = & reg.exe unload $loadedHiveKeyPath 2>&1
             Start-Sleep -Milliseconds 500 # Give it a moment
             if (Test-Path -Path "Registry::$loadedHiveKeyPath"){
                 Write-Log "Failed to unload existing temporary hive key '$loadedHiveKeyPath'. Output: $unloadOutput. Aborting default profile modification." "ERROR"
                 return $false
             }
             Write-Log "Successfully unloaded pre-existing mount." "INFO"
         } catch {
              Write-Log "Exception while trying to unload existing temporary hive key '$loadedHiveKeyPath': $($_.Exception.Message). Aborting." "ERROR"
              return $false
         }
    }

    Write-Log "Loading default user hive '$defaultUserHivePath' to '$loadedHiveKeyPath'..." "INFO"
    try {
        # Ensure quotes around path for reg.exe
        $loadOutput = & reg.exe load $loadedHiveKeyPath "`"$defaultUserHivePath`"" 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Reg Load failed with exit code $LASTEXITCODE. Output: $loadOutput" }
        Write-Log "Default user hive loaded successfully." "INFO"
        Start-Sleep -Milliseconds 500 # Give it a moment to settle
    } catch {
        Write-Log "Failed to load default user hive: $($_.Exception.Message)." "ERROR"
        # Attempt cleanup just in case it partially loaded
        & reg.exe unload $loadedHiveKeyPath 2>&1 | Out-Null
        return $false
    }

    # Check if load *really* worked and target path exists or can be created
    if (!(Test-Path -Path "Registry::$loadedHiveKeyPath")) {
         Write-Log "Failed to verify loaded hive key '$loadedHiveKeyPath' after loading. Aborting." "ERROR"
         # Attempt unload
         & reg.exe unload $loadedHiveKeyPath 2>&1 | Out-Null
         return $false
    }

    $success = $true
    try {
        # Ensure the target key exists within the loaded hive
        if (-not (Test-Path $loadedRegProviderPath)) {
            Write-Log "Creating key '$loadedRegProviderPath' in loaded hive." "INFO"
            New-Item -Path $loadedRegProviderPath -Force -ErrorAction Stop | Out-Null
        }

        Write-Log "Setting Default Profile: ScreenSaveActive = 1" "INFO"
        Set-ItemProperty -Path $loadedRegProviderPath -Name ScreenSaveActive -Value '1' -Type String -Force -ErrorAction Stop
        Write-Log "Setting Default Profile: ScreenSaveTimeOut = $TimeoutSeconds" "INFO"
        Set-ItemProperty -Path $loadedRegProviderPath -Name ScreenSaveTimeOut -Value $TimeoutSeconds.ToString() -Type String -Force -ErrorAction Stop
        Write-Log "Setting Default Profile: ScreenSaverIsSecure = 1" "INFO"
        Set-ItemProperty -Path $loadedRegProviderPath -Name ScreenSaverIsSecure -Value '1' -Type String -Force -ErrorAction Stop

        if ([string]::IsNullOrWhiteSpace($ScreenSaverExePath)) {
             Write-Log "Default Profile: No valid screen saver executable path provided. Skipping SCRNSAVE.EXE setting." "WARNING"
        } elseif (-not (Test-Path $ScreenSaverExePath -PathType Leaf)) { # Check if it's a file
             Write-Log "Default Profile: Screen saver executable '$ScreenSaverExePath' not found or is not a file. Skipping SCRNSAVE.EXE setting." "WARNING"
        } else {
             Write-Log "Setting Default Profile: SCRNSAVE.EXE = $ScreenSaverExePath" "INFO"
            Set-ItemProperty -Path $loadedRegProviderPath -Name SCRNSAVE.EXE -Value $ScreenSaverExePath -Type String -Force -ErrorAction Stop
        }
         Write-Log "Default user profile screen saver settings updated successfully in loaded hive."

    } catch {
        Write-Log "Failed to set screen saver properties in the loaded default user hive: $($_.Exception.Message)" "ERROR"
        $success = $false # Mark as failed
    } finally {
        # --- CRITICAL: Unload the hive ---
        Write-Log "Unloading default user hive '$loadedHiveKeyPath'..." "INFO"
        # Short pause before unload might help
        Start-Sleep -Milliseconds 500
        $unloadOutput = & reg.exe unload $loadedHiveKeyPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Failed to unload default user hive '$loadedHiveKeyPath'. Exit code: $LASTEXITCODE. Output: $unloadOutput. Manual intervention might be required!" "ERROR"
            $success = $false # Mark as failed if unload fails
        } else {
            # Verify unload worked
            Start-Sleep -Milliseconds 500
             if (Test-Path -Path "Registry::$loadedHiveKeyPath"){
                 Write-Log "Verification FAILED: Hive '$loadedHiveKeyPath' still appears loaded after unload command!" "ERROR"
                 $success = $false
             } else {
                  Write-Log "Default user hive unloaded successfully." "INFO"
             }
        }
    }
    return $success
}

# --- Function to Check if User is Administrator ---
function Test-IsAdminMember {
    param([string]$UserName)

    Write-Log "Checking admin membership for user: '$UserName'" "DEBUG"

    # Handle built-in administrator account name variations
    $sid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544") # Well-known SID for Administrators group
    $adminGroupName = $sid.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1] # Get localized name
    Write-Log "Using localized Administrators group name: '$adminGroupName'" "DEBUG"


    # Method 1: Get-LocalGroupMember (Preferred if available - PS 5.1+)
    if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
        try {
            # Check if the user *is* the Administrators group (edge case)
             if ($UserName -eq $adminGroupName) { return $false } # Group itself isn't a user member

            $members = Get-LocalGroupMember -Group $adminGroupName -ErrorAction Stop
            foreach ($member in $members) {
                 # Compare Name and SID for robustness
                 if ($member.Name -eq $UserName -or ($member.SID -ne $null -and $member.SID.Value -eq (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue)?.SID.Value)) {
                     Write-Log "User '$UserName' IS a member of '$adminGroupName' (checked via Get-LocalGroupMember)." "DEBUG"
                     return $true
                 }
            }
            Write-Log "User '$UserName' is NOT a member of '$adminGroupName' (checked via Get-LocalGroupMember)." "DEBUG"
            return $false
        } catch {
             Write-Log "Error checking admin membership for '$UserName' with Get-LocalGroupMember: $($_.Exception.Message). Falling back to 'net' command." "WARNING"
        }
    }

    # Method 2: Fallback using net localgroup (less reliable for complex names/domains but more compatible)
    Write-Log "Checking admin membership for '$UserName' using fallback 'net localgroup'..." "DEBUG"
    try {
        $output = net localgroup $adminGroupName | Select-String -Pattern "^$([regex]::Escape($UserName))\s*$" -SimpleMatch # Match whole line exactly
        if ($output) {
             Write-Log "User '$UserName' IS likely a member of '$adminGroupName' (found via 'net localgroup')." "DEBUG"
            return $true
        } else {
             Write-Log "User '$UserName' is likely NOT a member of '$adminGroupName' (checked via 'net localgroup')." "DEBUG"
            return $false
        }
    } catch {
         Write-Log "Error checking admin membership for '$UserName' using 'net localgroup $adminGroupName': $($_.Exception.Message)" "WARNING"
        return $false # Assume not admin if check fails
    }
}


# --- Start of Script ---
Write-Log "======================================================================"
Write-Log "Starting security configuration script on $(Get-Date)"
Write-Log "======================================================================"

# --- Check for Administrative Privileges ---
Write-Log "Checking for administrative privileges..."
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "This script requires administrative privileges. Please run as Administrator." "ERROR"
    exit 1
} else {
    Write-Log "[PASS] Administrative privileges confirmed."
}

# --- Check PowerShell Architecture ---
if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    Write-Log "[WARN] Running in non-64-bit PowerShell ($($env:PROCESSOR_ARCHITECTURE)). Some features (like Get-LocalUser) might require the 64-bit version." "WARNING"
} else {
     Write-Log "[INFO] Running in 64-bit PowerShell."
}


Write-Log "--- Applying MACHINE-WIDE SETTINGS (Apply to All) ---"

# --- Disable USB Storage ---
Write-Log "[TASK] Configuring USB storage (Machine-Wide)..."
$usbStorPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor"
try {
    if (!(Test-Path $usbStorPath)) {
         Write-Log "[WARN] USB Storage service registry path not found: $usbStorPath. Skipping USB configuration." "WARNING"
    } elseif ($DisableUsbStorage) {
        Write-Log "[INFO] Disabling USB Storage (Setting Start=4)."
        Set-ItemProperty -Path $usbStorPath -Name Start -Value 4 -Type DWord -Force -ErrorAction Stop
        # Verify after setting
        $startValue = Get-ItemProperty -Path $usbStorPath -Name Start -ErrorAction Stop
        if ($startValue.Start -eq 4) {
            Write-Log "[OK] USB storage successfully disabled (Registry Start value set to 4)."
        } else {
            Write-Log "[FAIL] Failed to verify USB storage registry key was set to disabled (Expected 4, got $($startValue.Start))." "ERROR"
        }
    } else {
        Write-Log "[INFO] USB storage disable variable is false. Ensuring USB is enabled (Setting Start=3)."
        # Optionally re-enable if set to false (default is usually 3)
        Set-ItemProperty -Path $usbStorPath -Name Start -Value 3 -Type DWord -Force -ErrorAction Stop
        $startValue = Get-ItemProperty -Path $usbStorPath -Name Start -ErrorAction Stop
         if ($startValue.Start -eq 3) {
             Write-Log "[OK] USB storage successfully enabled (Registry Start value set to 3)."
         } else {
             Write-Log "[FAIL] Failed to verify USB storage registry key was set to enabled (Expected 3, got $($startValue.Start))." "ERROR"
         }
    }
} catch {
    Write-Log "[FAIL] Failed to configure USB storage: $($_.Exception.Message)" "ERROR"
}

# --- Password Policies (Using secedit - Machine-Wide) ---
Write-Log "[TASK] Configuring password policies (Machine-Wide via Secedit)..."
$tempCfgPath = "$env:TEMP\secedit_temp_$(Get-Random).cfg"
$tempDbPath = "$env:TEMP\secedit_temp_$(Get-Random).sdb"
try {
    # Export current settings
    Write-Log "[INFO] Exporting current security policy to $tempCfgPath"
    & secedit /export /cfg "$tempCfgPath" /quiet
    if (-not (Test-Path $tempCfgPath)) {
        throw "Failed to export initial security policy configuration."
    }

    # Read content, ensure required section exists if needed
    $content = Get-Content $tempCfgPath -Raw
    if ($content -notmatch '\[System Access\]') {
         Write-Log "[INFO] Adding '[System Access]' section header to exported policy file."
         # Use Windows line endings
         $content += "`r`n[System Access]`r`n"
    }

    # Function to replace or add policy value under [System Access]
    function Update-SeceditValue {
        param($ContentRef, [string]$PolicyName, [string]$PolicyValue)
        $pattern = "(?sm)(\[System Access\].*?$PolicyName\s*=\s*)(\d+)"
        if ($ContentRef.Value -match $pattern) {
            $currentValue = $Matches[2]
            if ($currentValue -ne $PolicyValue) {
                Write-Log "[INFO] Updating $PolicyName from $currentValue to $PolicyValue."
                $ContentRef.Value = $ContentRef.Value -replace $pattern, ('${1}' + $PolicyValue)
            } else {
                 Write-Log "[INFO] $PolicyName already set to $PolicyValue."
            }
        } else {
            Write-Log "[INFO] Adding $PolicyName = $PolicyValue."
            $ContentRef.Value = $ContentRef.Value -replace '(\[System Access\])', "`$1`r`n$PolicyName = $PolicyValue"
        }
    }

    # Update policies
    Update-SeceditValue -ContentRef ([ref]$content) -PolicyName "MinimumPasswordLength" -PolicyValue $MinPasswordLength
    Update-SeceditValue -ContentRef ([ref]$content) -PolicyName "PasswordComplexity" -PolicyValue 1
    Update-SeceditValue -ContentRef ([ref]$content) -PolicyName "MaximumPasswordAge" -PolicyValue $MaxPasswordAge

    # Write the modified content back
    Write-Log "[INFO] Writing updated policy to $tempCfgPath"
    $content | Out-File $tempCfgPath -Encoding ASCII -Force # Secedit often prefers ASCII

    # Apply the configuration
    Write-Log "[INFO] Applying security policy changes using secedit..."
    # Create dummy DB first if it doesn't exist? Sometimes helps.
    if (!(Test-Path $tempDbPath)) { New-Item $tempDbPath -ItemType File -Force | Out-Null }
    $secEditOutput = & secedit /configure /db "$tempDbPath" /cfg "$tempCfgPath" /areas SECURITYPOLICY /log "$env:TEMP\secedit_apply.log" /quiet
     if ($LASTEXITCODE -ne 0) {
         Write-Log "[WARN] Secedit configure command exited with code $LASTEXITCODE. Check log $env:TEMP\secedit_apply.log for details." "WARNING"
     } else {
          Write-Log "[OK] Secedit configure command completed successfully."
     }
    Write-Log "[INFO] Minimum password length set request sent ($MinPasswordLength)."
    Write-Log "[INFO] Password complexity enabled request sent."
    Write-Log "[INFO] Maximum password age set request sent ($MaxPasswordAge days)."
    Write-Log "[NOTE] Secedit changes might take time or a 'gpupdate /force' to fully reflect." "INFO"

} catch {
    Write-Log "[FAIL] Failed to configure password policies: $($_.Exception.Message)" "ERROR"
} finally {
    # Clean up temporary files
    if (Test-Path $tempCfgPath) { Remove-Item $tempCfgPath -Force -ErrorAction SilentlyContinue }
    if (Test-Path $tempDbPath) { Remove-Item $tempDbPath -Force -ErrorAction SilentlyContinue }
    if (Test-Path "$env:TEMP\secedit_apply.log") { Remove-Item "$env:TEMP\secedit_apply.log" -Force -ErrorAction SilentlyContinue }
}

# --- Automatic Updates (Machine-Wide) ---
Write-Log "[TASK] Configuring automatic updates (Machine-Wide)..."
$auPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$auPath = "$auPolicyPath\AU"
try {
    # Ensure parent path exists
    if (-not (Test-Path $auPolicyPath)) {
        Write-Log "[INFO] Creating registry path: $auPolicyPath"
        New-Item -Path $auPolicyPath -Force -ErrorAction Stop | Out-Null
    }
    # Ensure AU path exists
    if (-not (Test-Path $auPath)) {
         Write-Log "[INFO] Creating registry path: $auPath"
        New-Item -Path $auPath -Force -ErrorAction Stop | Out-Null
    }

    # Set properties
    Write-Log "[INFO] Setting AUOptions to 4 (Auto download and schedule install)."
    Set-ItemProperty -Path $auPath -Name AUOptions -Value 4 -Type DWord -Force -ErrorAction Stop
    Write-Log "[INFO] Setting NoAutoRebootWithLoggedOnUsers to 1."
    Set-ItemProperty -Path $auPath -Name NoAutoRebootWithLoggedOnUsers -Value 1 -Type DWord -Force -ErrorAction Stop

    # Verify
    $auOptions = Get-ItemProperty -Path $auPath -Name AUOptions -ErrorAction Stop
    $noReboot = Get-ItemProperty -Path $auPath -Name NoAutoRebootWithLoggedOnUsers -ErrorAction Stop
    if ($auOptions.AUOptions -eq 4 -and $noReboot.NoAutoRebootWithLoggedOnUsers -eq 1) {
        Write-Log "[OK] Automatic updates successfully configured (AUOptions=4, NoAutoReboot=1)."
    } else {
        Write-Log "[FAIL] Failed to verify Automatic Updates configuration (Expected AUOptions=4, NoAutoReboot=1. Found AUOptions=$($auOptions.AUOptions), NoAutoReboot=$($noReboot.NoAutoRebootWithLoggedOnUsers))." "ERROR"
    }
} catch {
    Write-Log "[FAIL] Failed to configure automatic updates: $($_.Exception.Message)" "ERROR"
}


Write-Log "--- Applying USER-SPECIFIC ACTIONS (Apply Selectively) ---"

# --- Force Password Change for Non-Compliant NON-ADMIN Users ---
Write-Log "[TASK] Enforcing password changes for enabled, non-administrator local users..."
# Attempt to load the required module
Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue

if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
    try {
        $users = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
        Write-Log "[INFO] Found $($users.Count) enabled local users to check."

        foreach ($user in $users) {
            Write-Log "[INFO] Checking user: $($user.Name)"
            # Check if the user is an Administrator
            if (Test-IsAdminMember -UserName $user.Name) {
                Write-Log "[SKIP] Skipping password change enforcement for Administrator: $($user.Name)"
                continue # Skip to the next user
            }

            # Proceed for non-admin users
            try {
                 $currentUser = Get-LocalUser -Name $user.Name -ErrorAction Stop
                 if ($currentUser.PasswordChangeRequired -ne $true -or $currentUser.PasswordNeverExpires -eq $true) {
                     Write-Log "[ACTION] Setting password change required for non-admin user: $($user.Name)"
                     Set-LocalUser -Name $user.Name -PasswordNeverExpires $false -PasswordChangeRequired $true -ErrorAction Stop
                     Write-Log "[OK] User $($user.Name): Password change successfully set as required at next login."
                 } else {
                     Write-Log "[INFO] User $($user.Name): Password change already required or password expiration already configured correctly."
                 }
            } catch {
                 Write-Log "[WARN] Failed to set password change for user '$($user.Name)': $($_.Exception.Message)" "WARNING"
            }
        } # End foreach user
    } catch {
        # Catch errors from the Get-LocalUser | Where-Object pipeline itself
        Write-Log "[FAIL] Failed during user processing loop: $($_.Exception.Message)" "ERROR"
    }
} else {
    Write-Log "[WARN] Cmdlet 'Get-LocalUser' not found. Skipping enforcement of password change for local users. This requires PowerShell 5.1+ or the 'Microsoft.PowerShell.LocalAccounts' module." "WARNING"
}

# --- Screen Saver (Apply to Default User Profile for NEW Users Only) ---
Write-Log "[TASK] Configuring screen saver settings for the Default User Profile (for NEW users)..."
Write-Log "[NOTE] This will NOT affect existing users or the current admin user's interactive session." "INFO"
Write-Log "[NOTE] Group Policy is recommended for enforcing settings on existing users." "INFO"

# Configure Default User Profile (Affects NEW users)
if (-not (Test-Path $ScreenSaverExe -PathType Leaf)) {
     Write-Log "[WARN] Screen saver executable '$ScreenSaverExe' not found or not a file. Default profile SCRNSAVE.EXE setting will be skipped." "WARNING"
     $effectiveScreenSaverExe = $null
} else {
    $effectiveScreenSaverExe = $ScreenSaverExe
    Write-Log "[INFO] Target screen saver executable: $effectiveScreenSaverExe"
}

$setDefaultResult = Set-DefaultUserProfileScreenSaver -TimeoutSeconds $ScreenSaverTimeout -ScreenSaverExePath $effectiveScreenSaverExe
if (-not $setDefaultResult) {
    Write-Log "[WARN] Setting default user profile screen saver encountered errors. Check logs above." "WARNING"
} else {
    Write-Log "[OK] Attempt to set default user profile screen saver settings completed."
}


Write-Log "--- Starting Configuration Verification ---"
# Verify MACHINE-WIDE settings

# Verify USB Storage
Write-Log "[VERIFY] Verifying USB storage setting..."
try {
    if (!(Test-Path $usbStorPath)) {
        Write-Log "[WARN] Verification Skipped: USB Storage path '$usbStorPath' not found." "WARNING"
    } else {
        $usbStartValue = Get-ItemProperty -Path $usbStorPath -Name Start -ErrorAction Stop
        if ($DisableUsbStorage) {
             if ($usbStartValue.Start -eq 4) { Write-Log "[PASS] Verification: USB storage is correctly disabled (Start=4)." }
             else { Write-Log "[FAIL] Verification: USB storage setting mismatch (Expected 4, Found $($usbStartValue.Start))." "ERROR" }
        } else { # Checking if it's enabled (assuming Start=3)
             if ($usbStartValue.Start -eq 3) { Write-Log "[PASS] Verification: USB storage is correctly enabled (Start=3)." }
             else { Write-Log "[FAIL] Verification: USB storage setting mismatch (Expected 3, Found $($usbStartValue.Start))." "ERROR" }
        }
    }
} catch {
    Write-Log "[FAIL] Verification: Could not check USB storage setting: $($_.Exception.Message)" "ERROR"
}

# Verify Password Policies (Re-export and check)
Write-Log "[VERIFY] Verifying password policies (via re-export)..."
$verifyCfgPath = "$env:TEMP\verify_secedit_$(Get-Random).cfg"
try {
    & secedit /export /cfg "$verifyCfgPath" /quiet
    if (Test-Path $verifyCfgPath) {
        $verifyContent = Get-Content $verifyCfgPath -Encoding ASCII -Raw # Match encoding used for setting

        # Function to verify a value
        function Test-SeceditValue {
            param($Content, [string]$PolicyName, [int]$ExpectedValue, [string]$Comparison = "eq") # Comparison: eq, ge, le
            $pattern = "(?sm)\[System Access\].*?$PolicyName\s*=\s*(\d+)"
            if ($Content -match $pattern) {
                $currentValue = [int]$Matches[1]
                $result = $false
                switch ($Comparison) {
                    "eq" { $result = ($currentValue -eq $ExpectedValue) }
                    "ge" { $result = ($currentValue -ge $ExpectedValue) }
                    "le" { $result = ($currentValue -le $ExpectedValue) }
                    default { Write-Log "[FAIL] Verification Error: Invalid comparison '$Comparison' for $PolicyName." "ERROR"; return $false }
                }
                if ($result) {
                    Write-Log "[PASS] Verification: $PolicyName ($currentValue) meets requirement ($Comparison $ExpectedValue)."
                    return $true
                } else {
                    Write-Log "[FAIL] Verification: $PolicyName ($currentValue) does NOT meet requirement ($Comparison $ExpectedValue)." "ERROR"
                    return $false
                }
            } else {
                Write-Log "[FAIL] Verification: $PolicyName not found in exported policy." "ERROR"
                return $false
            }
        }

        # Verify Policies
        Test-SeceditValue -Content $verifyContent -PolicyName "MinimumPasswordLength" -ExpectedValue $MinPasswordLength -Comparison "ge" # Meets or exceeds
        Test-SeceditValue -Content $verifyContent -PolicyName "PasswordComplexity" -ExpectedValue 1 -Comparison "eq"
        Test-SeceditValue -Content $verifyContent -PolicyName "MaximumPasswordAge" -ExpectedValue $MaxPasswordAge -Comparison "le" # Is less than or equal to

        Remove-Item $verifyCfgPath -Force -ErrorAction SilentlyContinue
    } else {
        Write-Log "[FAIL] Verification: Could not export security policy for verification." "ERROR"
    }
} catch {
    Write-Log "[FAIL] Verification: Error during password policy verification: $($_.Exception.Message)" "ERROR"
} finally {
     if (Test-Path $verifyCfgPath) { Remove-Item $verifyCfgPath -Force -ErrorAction SilentlyContinue }
}

# Verify Automatic Updates
Write-Log "[VERIFY] Verifying Automatic Updates settings..."
try {
    if (!(Test-Path $auPath)) {
        Write-Log "[FAIL] Verification: Automatic Updates registry path '$auPath' not found." "ERROR"
    } else {
        $auValues = Get-ItemProperty -Path $auPath -ErrorAction SilentlyContinue # Continue even if one key is missing
        $optionsOk = $false
        $rebootOk = $false
        if ($auValues -ne $null -and $auValues.PSObject.Properties.Name -contains 'AUOptions') {
             if ($auValues.AUOptions -eq 4) { Write-Log "[PASS] Verification: AUOptions is correctly set to 4."; $optionsOk = $true }
             else { Write-Log "[FAIL] Verification: AUOptions is '$($auValues.AUOptions)', expected 4." "ERROR" }
        } else { Write-Log "[FAIL] Verification: AUOptions registry value not found or path inaccessible." "ERROR" }

        if ($auValues -ne $null -and $auValues.PSObject.Properties.Name -contains 'NoAutoRebootWithLoggedOnUsers') {
             if ($auValues.NoAutoRebootWithLoggedOnUsers -eq 1) { Write-Log "[PASS] Verification: NoAutoRebootWithLoggedOnUsers is correctly set to 1."; $rebootOk = $true }
             else { Write-Log "[FAIL] Verification: NoAutoRebootWithLoggedOnUsers is '$($auValues.NoAutoRebootWithLoggedOnUsers)', expected 1." "ERROR" }
        } else { Write-Log "[FAIL] Verification: NoAutoRebootWithLoggedOnUsers registry value not found or path inaccessible." "ERROR" }
    }
} catch {
    Write-Log "[FAIL] Verification: Could not check automatic updates settings: $($_.Exception.Message)" "ERROR"
}


# Verification for user-specific actions relies on logs
Write-Log "[VERIFY] Verification of user-specific actions (Password Change Force, Default Profile Screen Saver) relies on reviewing script logs above." "INFO"

# --- Final Message ---
Write-Log "======================================================================"
Write-Log "Security configuration and verification complete at $(Get-Date)."
Write-Log "Review any [FAIL] or [WARN] messages above."
Write-Log "Machine-wide settings (USB, Password Policy, Updates) applied."
Write-Log "Password change forced for enabled non-admin users (if Get-LocalUser available)."
Write-Log "Screen saver settings applied to Default User Profile (for NEW users)."
Write-Log "Log file saved to: $LogFile"
Write-Log "======================================================================"
