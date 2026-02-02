<#
.SYNOPSIS
    Cl0p Registry Persistence - DETECTION TRIGGER
.DESCRIPTION
    Creates Run key for persistence.
    Will trigger EDR detection for T1547.001.
    TTP: T1547, T1547.001
#>
Write-Host "[*] Starting Cl0p Registry Persistence (T1547)" -ForegroundColor Cyan
Write-Host "[*] This will trigger EDR detection for persistence" -ForegroundColor Yellow

try {
    $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $valueName = "RTL_Test_Persistence"
    $payload = "cmd.exe /c echo RTL_Test > $env:TEMP\persist_test.txt"
    
    Write-Host "[*] Target: $runKey"
    Write-Host "[*] Value Name: $valueName"
    Write-Host "[*] Payload: $payload"
    
    # ACTUAL DETECTION TRIGGER - Create Run key persistence
    Write-Host "[*] Executing: Set-ItemProperty -Path '$runKey' -Name '$valueName' -Value '$payload'"
    
    Set-ItemProperty -Path $runKey -Name $valueName -Value $payload -ErrorAction Stop
    
    # Verify creation
    $created = Get-ItemProperty -Path $runKey -Name $valueName -ErrorAction SilentlyContinue
    
    if ($created) {
        Write-Host "[+] SUCCESS: Run key persistence created" -ForegroundColor Green
        Write-Host "[+] Value: $($created.$valueName)" -ForegroundColor Green
        Write-Host "[!] CrowdStrike should detect: 'PersistenceRunKey' or 'AutoStartRegistryModification'" -ForegroundColor Magenta
    }
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}

Write-Host "`n[*] Detection should appear in CrowdStrike within 1-2 minutes" -ForegroundColor Cyan
Write-Host "[!] IMPORTANT: Run the REVERT script to remove the persistence!" -ForegroundColor Red
