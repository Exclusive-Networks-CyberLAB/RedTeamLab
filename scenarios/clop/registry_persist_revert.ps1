<#
.SYNOPSIS
    Cl0p Registry Persistence - REVERT
.DESCRIPTION
    Removes Run key persistence created by the test.
#>
Write-Host "[*] REVERTING: Removing Run key persistence" -ForegroundColor Cyan

try {
    $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $valueName = "RTL_Test_Persistence"
    
    Remove-ItemProperty -Path $runKey -Name $valueName -Force -ErrorAction Stop
    
    # Also clean up any test files
    Remove-Item "$env:TEMP\persist_test.txt" -Force -ErrorAction SilentlyContinue
    
    Write-Host "[+] SUCCESS: Run key persistence REMOVED" -ForegroundColor Green
} catch {
    Write-Host "[!] Error or key didn't exist: $_" -ForegroundColor Yellow
}
