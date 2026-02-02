<#
.SYNOPSIS
    ALPHV Scheduled Task - REVERT
.DESCRIPTION
    Removes scheduled task persistence created by the test.
#>
Write-Host "[*] REVERTING: Removing scheduled task" -ForegroundColor Cyan

try {
    $taskName = "RTL_Test_SchTask"
    
    schtasks /delete /tn $taskName /f 2>&1 | Out-Null
    
    # Clean up test files
    Remove-Item "$env:TEMP\schtask_test.txt" -Force -ErrorAction SilentlyContinue
    
    Write-Host "[+] SUCCESS: Scheduled task REMOVED" -ForegroundColor Green
} catch {
    Write-Host "[!] Error or task didn't exist: $_" -ForegroundColor Yellow
}
