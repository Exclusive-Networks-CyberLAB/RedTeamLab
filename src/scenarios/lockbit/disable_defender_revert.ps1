<#
.SYNOPSIS
    LockBit Disable Windows Defender - REVERT
.DESCRIPTION
    Re-enables Windows Defender real-time monitoring.
    Use after testing to restore security posture.
#>
Write-Host "[*] REVERTING: Re-enabling Windows Defender" -ForegroundColor Cyan

try {
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
    Write-Host "[+] SUCCESS: Windows Defender Real-Time Monitoring RE-ENABLED" -ForegroundColor Green
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}
