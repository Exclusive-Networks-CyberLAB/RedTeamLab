<#
.SYNOPSIS
    ALPHV Scheduled Task Persistence - DETECTION TRIGGER
.DESCRIPTION
    Creates scheduled task for persistence.
    Will trigger EDR detection for T1053.005.
    TTP: T1053, T1053.005
#>
Write-Host "[*] Starting ALPHV Scheduled Task Persistence (T1053)" -ForegroundColor Cyan
Write-Host "[*] This will trigger EDR detection for scheduled task creation" -ForegroundColor Yellow

try {
    $taskName = "RTL_Test_SchTask"
    $taskAction = "cmd.exe"
    $taskArgs = "/c echo RTL_Test > $env:TEMP\schtask_test.txt"
    
    Write-Host "[*] Task Name: $taskName"
    Write-Host "[*] Action: $taskAction $taskArgs"
    
    # ACTUAL DETECTION TRIGGER - Create scheduled task
    Write-Host "[*] Executing: schtasks /create /tn '$taskName' /tr '$taskAction $taskArgs' /sc ONLOGON /ru SYSTEM"
    
    # Try with SYSTEM (requires admin)
    $result = schtasks /create /tn $taskName /tr "$taskAction $taskArgs" /sc ONLOGON /ru SYSTEM /f 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        # Fall back to current user
        Write-Host "[*] SYSTEM task failed, trying current user..."
        $result = schtasks /create /tn $taskName /tr "$taskAction $taskArgs" /sc ONLOGON /f 2>&1
    }
    
    Write-Host "[*] Result: $result"
    
    # Verify creation
    $verify = schtasks /query /tn $taskName 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] SUCCESS: Scheduled task created" -ForegroundColor Green
        Write-Host "[!] CrowdStrike should detect: 'ScheduledTaskCreated' or 'Persistence'" -ForegroundColor Magenta
    } else {
        Write-Host "[-] Task creation may have been blocked by EDR" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}

Write-Host "`n[*] Detection should appear in CrowdStrike within 1-2 minutes" -ForegroundColor Cyan
Write-Host "[!] IMPORTANT: Run the REVERT script to remove the scheduled task!" -ForegroundColor Red
