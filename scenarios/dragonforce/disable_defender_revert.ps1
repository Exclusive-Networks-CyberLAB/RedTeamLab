<#
.SYNOPSIS
    DragonForce Windows Defender Disable - REVERT
.DESCRIPTION
    Re-enables Windows Defender protections.
#>
Write-Host "[*] REVERTING: Re-enabling Windows Defender" -ForegroundColor Cyan

try {
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
    Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
    
    Write-Host "[+] SUCCESS: Windows Defender protections RE-ENABLED" -ForegroundColor Green
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}
