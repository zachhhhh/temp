# --- Function to Check if User is Administrator ---
function Test-IsAdminMember {
    param([string]$UserName)
    
    try {
        $adminGroup = (Get-LocalGroup -SID "S-1-5-32-544").Name # Gets localized Administrators group name
        $members = Get-LocalGroupMember -Group $adminGroup -ErrorAction Stop
        return ($members | Where-Object { $_.Name -like "*\$UserName" -or $_.Name -eq $UserName }) -ne $null
    } catch {
        # Fallback method using net localgroup
        $adminMembers = net localgroup administrators | 
            Where-Object { $_ -and $_ -notmatch "command completed successfully" } |
            Select-Object -Skip 4 | Select-Object -SkipLast 2
        return $adminMembers -contains $UserName
    }
}

# --- Function to Set Screen Saver for a User Profile ---
function Set-UserProfileScreenSaver {
    param(
        [string]$UserProfilePath,
        [string]$Username,
        [int]$TimeoutSeconds,
        [string]$ScreenSaverPath
    )

    $ntUserDatPath = Join-Path $UserProfilePath "NTUSER.DAT"
    if (-not (Test-Path $ntUserDatPath)) {
        Write-Log "NTUSER.DAT not found for user $Username at $ntUserDatPath" "WARNING"
        return $false
    }

    $tempMountName = "TempHive_$($Username)_$(Get-Random)"
    try {
        # Load the hive
        $result = & reg load "HKU\$tempMountName" "$ntUserDatPath" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Failed to load hive for $Username: $result" "ERROR"
            return $false
        }

        # Set screen saver settings
        $userDesktopPath = "Registry::HKEY_USERS\$tempMountName\Control Panel\Desktop"
        
        if (-not (Test-Path $userDesktopPath)) {
            New-Item -Path $userDesktopPath -Force | Out-Null
        }

        Set-ItemProperty -Path $userDesktopPath -Name "ScreenSaveActive" -Value "1" -Type String -Force
        Set-ItemProperty -Path $userDesktopPath -Name "ScreenSaveTimeOut" -Value $TimeoutSeconds.ToString() -Type String -Force
        Set-ItemProperty -Path $userDesktopPath -Name "ScreenSaverIsSecure" -Value "1" -Type String -Force
        
        if (Test-Path $ScreenSaverPath) {
            Set-ItemProperty -Path $userDesktopPath -Name "SCRNSAVE.EXE" -Value $ScreenSaverPath -Type String -Force
        }

        Write-Log "Successfully configured screen saver for user $Username" "INFO"
        return $true
    }
    catch {
        Write-Log "Error configuring screen saver for $Username: $($_.Exception.Message)" "ERROR"
        return $false
    }
    finally {
        # Always attempt to unload the hive
        [gc]::Collect() # Force garbage collection
        Start-Sleep -Seconds 1 # Give system time to release handles
        $result = & reg unload "HKU\$tempMountName" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Warning: Failed to unload hive for $Username: $result" "WARNING"
        }
    }
}

# --- Configure Screen Saver for All Non-Admin Users ---
Write-Log "Configuring screen saver for non-administrator users..."

# Set screen saver path
$screenSaverPath = "$env:SystemRoot\system32\scrnsave.scr"
if (-not (Test-Path $screenSaverPath)) {
    Write-Log "Default screen saver not found at $screenSaverPath" "WARNING"
}

# Get all user profiles
$userProfiles = Get-CimInstance -ClassName Win32_UserProfile | 
    Where-Object { -not $_.Special -and $_.LocalPath -like "$env:SystemDrive\Users\*" }

foreach ($profile in $userProfiles) {
    $userName = ($profile.LocalPath -split '\\')[-1]
    
    # Skip if user is an administrator
    if (Test-IsAdminMember -UserName $userName) {
        Write-Log "Skipping administrator account: $userName" "INFO"
        continue
    }

    Write-Log "Configuring screen saver for user: $userName" "INFO"
    $success = Set-UserProfileScreenSaver -UserProfilePath $profile.LocalPath `
                                        -Username $userName `
                                        -TimeoutSeconds $ScreenSaverTimeout `
                                        -ScreenSaverPath $screenSaverPath

    if ($success) {
        Write-Log "Successfully configured screen saver for $userName" "INFO"
    } else {
        Write-Log "Failed to configure screen saver for $userName" "ERROR"
    }
}

# --- Configure Default User Profile for New Users ---
Write-Log "Configuring default user profile for new non-administrator users..."

$defaultUserProfile = "$env:SystemDrive\Users\Default"
$success = Set-UserProfileScreenSaver -UserProfilePath $defaultUserProfile `
                                    -Username "Default" `
                                    -TimeoutSeconds $ScreenSaverTimeout `
                                    -ScreenSaverPath $screenSaverPath

if ($success) {
    Write-Log "Successfully configured default user profile" "INFO"
} else {
    Write-Log "Failed to configure default user profile" "ERROR"
}

# Add verification section for user profiles
Write-Log "Verifying screen saver settings for non-administrator users..."

foreach ($profile in $userProfiles) {
    $userName = ($profile.LocalPath -split '\\')[-1]
    
    # Skip if user is an administrator
    if (Test-IsAdminMember -UserName $userName) {
        continue
    }

    $ntUserDatPath = Join-Path $profile.LocalPath "NTUSER.DAT"
    $tempMountName = "VerifyHive_$($userName)_$(Get-Random)"
    
    try {
        # Load the hive
        $result = & reg load "HKU\$tempMountName" "$ntUserDatPath" 2>&1
        if ($LASTEXITCODE -eq 0) {
            $userDesktopPath = "Registry::HKEY_USERS\$tempMountName\Control Panel\Desktop"
            
            if (Test-Path $userDesktopPath) {
                $settings = Get-ItemProperty -Path $userDesktopPath -ErrorAction Stop
                
                Write-Log "Verification for user $userName:" "INFO"
                Write-Log "  Screen Saver Active: $($settings.ScreenSaveActive -eq '1')" "INFO"
                Write-Log "  Screen Saver Timeout: $($settings.ScreenSaveTimeOut -eq $ScreenSaverTimeout)" "INFO"
                Write-Log "  Screen Saver Secure: $($settings.ScreenSaverIsSecure -eq '1')" "INFO"
                Write-Log "  Screen Saver Path: $($settings.'SCRNSAVE.EXE' -eq $screenSaverPath)" "INFO"
            }
        }
    }
    catch {
        Write-Log "Error verifying settings for $userName: $($_.Exception.Message)" "ERROR"
    }
    finally {
        # Unload the hive
        [gc]::Collect()
        Start-Sleep -Seconds 1
        & reg unload "HKU\$tempMountName" 2>&1 | Out-Null
    }
}
