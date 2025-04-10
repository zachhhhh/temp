# PowerShell script to verify security policies and settings.

# --- Function to Extract Secedit Values ---
function Get-SeceditValue {
    param(
        [string]$cfgPath,
        [string[]]$patterns
    )

    $results = @{}
    $content = Get-Content $cfgPath -ErrorAction SilentlyContinue
    if ($content) {
        foreach ($pattern in $patterns) {
            $line = $content | Select-String -Pattern $pattern
            if ($line) {
                $parts = $line -split "="
                if ($parts.Length -ge 2) {
                    $key = ($parts[0]).Trim()
                    $value = ($parts[1]).Trim()
                    $results[$key] = $value
                }
            }
        }
    }
    return $results
}

# --- Configuration Variables ---
$tempCfgPath = "$env:TEMP\temp.cfg"

# --- Password Policies (Using secedit) ---
Write-Host "Checking password policies..."

try {
    secedit /export /cfg "$tempCfgPath" -Quiet -Force  # Use -Quiet and -Force
    $passwordSettings = Get-SeceditValue -cfgPath "$tempCfgPath" -patterns @(
        "MinimumPasswordLength",
        "PasswordComplexity",
        "MaximumPasswordAge"
    )

    if ($passwordSettings["MinimumPasswordLength"]) {
        Write-Host "Minimum password length is set to: $($passwordSettings['MinimumPasswordLength'])"
    } else {
        Write-Host "Minimum password length not found. Possible keys:"
        $passwordSettings.Keys | ForEach-Object { Write-Host "- $_" }
        Write-Host "Check if the policy was applied or if the key name is different."
    }

    if ($passwordSettings["PasswordComplexity"]) {
        if ($passwordSettings["PasswordComplexity"].Trim() -eq "1") {
            Write-Host "Password complexity is enabled."
        } else {
            Write-Host "Password complexity is NOT enabled."
        }
    } else {
        Write-Host "Password complexity setting not found. Possible keys:"
        $passwordSettings.Keys | ForEach-Object { Write-Host "- $_" }
        Write-Host "Check if the policy was applied or if the key name is different."
    }

    if ($passwordSettings["MaximumPasswordAge"]) {
        Write-Host "Maximum password age is set to: $($passwordSettings['MaximumPasswordAge']) days"
    } else {
        Write-Host "Maximum password age setting not found. Possible keys:"
        $passwordSettings.Keys | ForEach-Object { Write-Host "- $_" }
        Write-Host "Check if the policy was applied or if the key name is different."
    }

} catch {
    Write-Warning "Failed to configure password policies: $($_.Exception.Message)"
} finally {
    if (Test-Path $tempCfgPath) { Remove-Item $tempCfgPath -Force }
}

# --- Rest of the script (USB, Updates, Screen Saver checks) remains the same ---
# ... (as the previous improved version)
