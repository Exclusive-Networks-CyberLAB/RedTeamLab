<#
.SYNOPSIS
    SafePay UAC Bypass - REVERT
.DESCRIPTION
    Cleans up registry keys from UAC bypass attempts.
#>
Write-Host "[*] REVERTING: Cleaning up UAC bypass artifacts" -ForegroundColor Cyan

try {
    # Remove fodhelper bypass registry keys
    Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue
    
    # Remove any leftover test files
    Remove-Item "$env:TEMP\uac_bypass_test.txt" -Force -ErrorAction SilentlyContinue
    
    Write-Host "[+] SUCCESS: UAC bypass artifacts cleaned up" -ForegroundColor Green
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}
