#Requires -RunAsAdministrator

<#
.SYNOPSIS
在 Windows 11 家用版上設定安全性和喜好設定，並可選擇強制變更密碼。
.DESCRIPTION
此腳本嘗試在 Windows 11 家用版上進行以下設定：
- 停用 USB 大量儲存裝置（系統範圍）。
- 使用 'net accounts' 設定基本密碼原則（系統範圍，家用版選項有限）。
- 可選擇性地標記所有標準本機使用者在下次登入時變更密碼。
- 為執行腳本的*目前使用者*設定螢幕保護裝置。
.NOTES
版本: 1.7
作者: Gemini AI (根據使用者輸入修改)
日期: 2025-04-10

重要提示: 如果要在註解或字串中使用非英文字元，建議將此腳本檔案儲存為 UTF-8 with BOM 編碼。

重要的 WINDOWS 家用版限制:
- 無法透過腳本在家用版上強制執行完整的密碼原則（例如複雜性）。
- 透過登錄檔設定群組原則機碼（例如自動更新的機碼）在家用版上不保證可靠。
- 套用至 HKCU 的設定（螢幕保護裝置）僅影響執行腳本的使用者。
- 強制變更密碼會標記所有非內建系統管理員的使用者，無論其目前密碼是否符合規定。
#>

# --- 設定變數 ---
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [bool]$DisableUsbStorage = $true,

    [Parameter(Mandatory=$false)]
    [int]$MinPasswordLength = 12,

    [Parameter(Mandatory=$false)]
    [int]$MaxPasswordAge = 90,

    [Parameter(Mandatory=$false)]
    [int]$ScreenSaverTimeoutSeconds = 600, # 10 分鐘

    [Parameter(Mandatory=$false)]
    [string]$ScreenSaverExecutable = "$($env:SystemRoot)\System32\scrnsave.scr",

    [Parameter(Mandatory=$false)]
    [bool]$EnforcePasswordChangeOnNonAdmins = $true # 設定為 $false 以停用強制變更
)

# =============================================
# --- 設定區段 ---
# =============================================
Write-Host "正在開始設定腳本..." -ForegroundColor Yellow
Write-Host "執行身分: $($env:USERNAME)" -ForegroundColor Gray
Write-Host "系統時間: $(Get-Date)" -ForegroundColor Gray
Write-Host "系統文化特性: $(Get-Culture).Name" -ForegroundColor Gray

# --- 停用 USB 儲存裝置 ---
Write-Host "`n正在設定 USB 儲存裝置..."
$usbStorPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor"
$expectedUsbStorStartValue = if ($DisableUsbStorage) { 4 } else { 3 } # 4 = 停用, 3 = 啟用 (手動啟動)

try {
    if (!(Test-Path $usbStorPath)) {
        Write-Warning "找不到 USB 儲存裝置登錄路徑: $usbStorPath。正在跳過設定。"
    } else {
        Set-ItemProperty -Path $usbStorPath -Name Start -Value $expectedUsbStorStartValue -ErrorAction Stop
        if ($DisableUsbStorage) {
            Write-Host "USB 儲存裝置驅動程式已停用 (系統範圍)。" -ForegroundColor Green
        } else {
            Write-Host "USB 儲存裝置驅動程式已設為啟用/手動啟動 (系統範圍)。" -ForegroundColor Green
        }
    }
} catch {
    Write-Error "設定 USB 儲存裝置失敗。錯誤: $($_.Exception.Message)"
}


# --- 密碼原則 (使用 net accounts - 家用版有限) ---
Write-Host "`n正在使用 'net accounts' 設定密碼原則..."
Write-Host "注意: 無法在家用版上透過 'net accounts' 強制執行密碼複雜性。" -ForegroundColor Yellow

# 最小密碼長度
try {
    Write-Verbose "正在設定最小密碼長度為 $MinPasswordLength"
    net accounts /minpwlen:$MinPasswordLength
    if ($lasterrorcode -ne 0) { # 檢查結束代碼
         Write-Warning "指令 'net accounts /minpwlen' 可能遇到問題 (結束代碼: $lasterrorcode)。"
    } else {
         Write-Host "已嘗試設定最小密碼長度為: $MinPasswordLength (系統範圍)。" -ForegroundColor Green
    }
} catch {
    Write-Error "執行 'net accounts' 設定最小密碼長度失敗。錯誤: $($_.Exception.Message)"
}

# 最長密碼有效期
try {
    Write-Verbose "正在設定最長密碼有效期為 $MaxPasswordAge 天"
    net accounts /maxpwage:$MaxPasswordAge
    if ($lasterrorcode -ne 0) { # 檢查結束代碼
        Write-Warning "指令 'net accounts /maxpwage' 可能遇到問題 (結束代碼: $lasterrorcode)。"
    } else {
        Write-Host "已嘗試設定最長密碼有效期為: $MaxPasswordAge 天 (系統範圍)。" -ForegroundColor Green
    }
} catch {
    Write-Error "執行 'net accounts' 設定最長密碼有效期失敗。錯誤: $($_.Exception.Message)"
}

# --- 強制非系統管理員變更密碼 (可選) ---
if ($EnforcePasswordChangeOnNonAdmins) {
    Write-Host "`n正在嘗試標記非系統管理員使用者於下次登入時變更密碼..." -ForegroundColor Yellow
    Write-Host "警告: 這將影響所有已啟用的本機使用者，除了內建的 Administrator (SID 結尾為 -500)。" -ForegroundColor Yellow

    try {
        # 使用 Get-CimInstance 取得已啟用且非內建 Administrator 的本機帳戶
        $usersToFlag = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" | Where-Object { $_.Disabled -eq $false -and $_.SID -notlike 'S-1-5-*-500' } -ErrorAction Stop

        if ($null -eq $usersToFlag -or $usersToFlag.Count -eq 0) {
             Write-Host "找不到適用的使用者帳戶來標記變更密碼。" -ForegroundColor Green
        } else {
            # 確保 $usersToFlag 是陣列，即使只找到一個使用者
            if ($usersToFlag -isnot [array]) { $usersToFlag = @($usersToFlag) }

            foreach ($user in $usersToFlag) {
                Write-Host "  正在嘗試標記使用者: $($user.Name)"
                try {
                    # 使用 net user 強制在下次登入時變更密碼
                    # 如果使用者名稱包含空格，則在名稱周圍加上引號
                    net user "$($user.Name)" /logonpasswordchg:yes
                    if ($lasterrorcode -eq 0) {
                        Write-Host "    [成功] 使用者 '$($user.Name)' 已被標記在下次登入時變更密碼。" -ForegroundColor Green
                    } else {
                         Write-Warning "    [警告] 指令 'net user ""$($user.Name)"" /logonpasswordchg:yes' 以結束代碼 $lasterrorcode 完成。可能未成功。"
                    }
                } catch {
                    Write-Error "    [失敗] 標記使用者 '$($user.Name)' 失敗。錯誤: $($_.Exception.Message)"
                }
            }
        }
    } catch {
        Write-Error "擷取本機使用者或執行 'net user' 指令失敗。錯誤: $($_.Exception.Message)"
        Write-Warning "由於錯誤，正在跳過強制變更密碼區段。"
    }
} else {
    Write-Host "`n依照要求，正在跳過強制非系統管理員變更密碼的步驟。" -ForegroundColor Cyan
}


# --- 自動更新 (僅供參考) ---
Write-Host "`n正在跳過自動更新的設定..."
Write-Host "注意: 在家用版上透過登錄檔強制執行特定的自動更新行為是不可靠的。" -ForegroundColor Yellow
Write-Host "建議透過 Windows 設定應用程式 (設定 > Windows Update) 管理更新設定。" -ForegroundColor Cyan


# --- 螢幕保護裝置 (僅限目前使用者) ---
Write-Host "`n正在為 *目前使用者* ($env:USERNAME) 設定螢幕保護裝置..."
$controlPanelDesktopPath = "HKCU:\Control Panel\Desktop"
$expectedScreenSaverActive = "1"
$expectedScreenSaverSecure = "1"
$expectedScreenSaverTimeoutString = $ScreenSaverTimeoutSeconds.ToString()
$expectedScreenSaverExe = $ScreenSaverExecutable

try {
    if (!(Test-Path $controlPanelDesktopPath)) {
        New-Item -Path $controlPanelDesktopPath -Force -ErrorAction Stop | Out-Null
    }
    Write-Verbose "正在設定螢幕保護裝置執行檔為 $expectedScreenSaverExe"
    Set-ItemProperty -Path $controlPanelDesktopPath -Name SCRNSAVE.EXE -Value $expectedScreenSaverExe -ErrorAction Stop
    Write-Verbose "正在啟用螢幕保護裝置使用中旗標"
    Set-ItemProperty -Path $controlPanelDesktopPath -Name ScreenSaveActive -Value $expectedScreenSaverActive -ErrorAction Stop
    Write-Verbose "正在設定螢幕保護裝置逾時為 $expectedScreenSaverTimeoutString 秒"
    Set-ItemProperty -Path $controlPanelDesktopPath -Name ScreenSaverTimeout -Value $expectedScreenSaverTimeoutString -ErrorAction Stop
    Write-Verbose "正在設定螢幕保護裝置安全旗標 (需要密碼)"
    Set-ItemProperty -Path $controlPanelDesktopPath -Name ScreenSaverIsSecure -Value $expectedScreenSaverSecure -ErrorAction Stop
    Write-Host "已為使用者 '$($env:USERNAME)' 設定螢幕保護裝置，逾時 $expectedScreenSaverTimeoutString 秒並要求密碼。" -ForegroundColor Green
} catch {
    Write-Error "為使用者 '$($env:USERNAME)' 設定螢幕保護裝置失敗。錯誤: $($_.Exception.Message)"
}


# =============================================
# --- 設定結束 ---
# =============================================

Write-Host "`n設定腳本已完成。" -ForegroundColor Yellow
# 腳本結束
