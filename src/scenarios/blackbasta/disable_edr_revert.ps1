<#
.SYNOPSIS
    Black Basta EDR Disable - REVERT
.DESCRIPTION
    Removes registry keys that attempt to disable security tools.
#>
Write-Host "[*] REVERTING: Restoring EDR/Defender settings" -ForegroundColor Cyan

try {
    $defenderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    
    Remove-ItemProperty -Path $defenderPath -Name "DisableAntiSpyware" -Force -ErrorAction SilentlyContinue
    
    # Re-enable Defender if it was disabled
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    
    Write-Host "[+] SUCCESS: EDR disable registry keys removed" -ForegroundColor Green
} catch {
    Write-Host "[!] Error or key didn't exist: $_" -ForegroundColor Yellow
}
