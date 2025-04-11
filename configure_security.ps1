# --- 密碼原則 (使用 net accounts - 家用版有限) ---
Write-Host "`n正在使用 'net accounts' 設定密碼原則..." -ForegroundColor Yellow
Write-Host "注意: 無法在家用版上透過 'net accounts' 強制執行密碼複雜性。" -ForegroundColor Yellow

# 最小密碼長度
try {
    $MinPasswordLength = [math]::Min($MinPasswordLength, 14) # 限制為 14，Windows Home 的最大值
    if ($MinPasswordLength -lt 0) { $MinPasswordLength = 0 } # 允許 0（無限制）
    Write-Verbose "正在設定最小密碼長度為 $MinPasswordLength"
    $process = Start-Process -FilePath "net.exe" -ArgumentList "accounts /minpwlen:$MinPasswordLength" -NoNewWindow -PassThru -Wait
    if ($process.ExitCode -ne 0) {
        Write-Warning "指令 'net accounts /minpwlen:$MinPasswordLength' 失敗，結束代碼: $($process.ExitCode)。請檢查值是否有效（0-14）。"
    } else {
        Write-Host "已設定最小密碼長度為: $MinPasswordLength (系統範圍)。" -ForegroundColor Green
    }
} catch {
    Write-Error "執行 'net accounts' 設定最小密碼長度失敗。錯誤: $($_.Exception.Message)"
}

# 最長密碼有效期
try {
    $MaxPasswordAge = [math]::Clamp($MaxPasswordAge, 1, 999) # 限制為 1-999 天
    Write-Verbose "正在設定最長密碼有效期為 $MaxPasswordAge 天"
    $process = Start-Process -FilePath "net.exe" -ArgumentList "accounts /maxpwage:$MaxPasswordAge" -NoNewWindow -PassThru -Wait
    if ($process.ExitCode -ne 0) {
        Write-Warning "指令 'net accounts /maxpwage:$MaxPasswordAge' 失敗，結束代碼: $($process.ExitCode)。請檢查值是否有效（1-999）。"
    } else {
        Write-Host "已設定最長密碼有效期為: $MaxPasswordAge 天 (系統範圍)。" -ForegroundColor Green
    }
} catch {
    Write-Error "執行 'net accounts' 設定最長密碼有效期失敗。錯誤: $($_.Exception.Message)"
}

# --- 強制非系統管理員變更密碼 (可選) ---
if ($EnforcePasswordChangeOnNonAdmins) {
    Write-Host "`n正在嘗試標記非系統管理員使用者於下次登入時變更密碼..." -ForegroundColor Yellow
    Write-Host "警告: 這將影響所有已啟用的本機使用者，除了內建的 Administrator (SID 結尾為 -500)。" -ForegroundColor Yellow

    try {
        # 使用 Get-LocalUser 取得已啟用且非內建 Administrator 的本機帳戶
        $usersToFlag = Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.SID -notlike '*-500' } -ErrorAction Stop

        if ($null -eq $usersToFlag -or $usersToFlag.Count -eq 0) {
            Write-Host "找不到適用的使用者帳戶來標記變更密碼。" -ForegroundColor Green
        } else {
            # 確保 $usersToFlag 是陣列
            if ($usersToFlag -isnot [array]) { $usersToFlag = @($usersToFlag) }

            foreach ($user in $usersToFlag) {
                Write-Host "  正在嘗試標記使用者: $($user.Name)"
                try {
                    $process = Start-Process -FilePath "net.exe" -ArgumentList "user `"$($user.Name)`" /logonpasswordchg:yes" -NoNewWindow -PassThru -Wait
                    if ($process.ExitCode -eq 0) {
                        Write-Host "    [成功] 使用者 '$($user.Name)' 已被標記在下次登入時變更密碼。" -ForegroundColor Green
                    } else {
                        Write-Warning "    [警告] 指令 'net user ""$($user.Name)"" /logonpasswordchg:yes' 以結束代碼 $($process.ExitCode) 完成。可能未成功。"
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
