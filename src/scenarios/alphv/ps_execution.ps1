<#
.SYNOPSIS
    ALPHV PowerShell Execution - DETECTION TRIGGER
.DESCRIPTION
    Executes encoded PowerShell commands.
    Will trigger EDR detection for T1059.001.
    TTP: T1059.001
#>
Write-Host "[*] Starting ALPHV PowerShell Execution (T1059.001)" -ForegroundColor Cyan
Write-Host "[*] This will trigger EDR detection for encoded command execution" -ForegroundColor Yellow

try {
    # ACTUAL DETECTION TRIGGER - Encoded PowerShell execution
    
    # Create a benign but suspicious-looking encoded command
    $command = "Write-Host '[RTL Test] Encoded command executed successfully' -ForegroundColor Green; Get-Process | Select-Object -First 5"
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $encodedCommand = [Convert]::ToBase64String($bytes)
    
    Write-Host "[*] Encoded Command: $encodedCommand"
    Write-Host "[*] Executing: powershell -EncodedCommand ..."
    
    # Execute encoded command (this is the detection trigger)
    powershell -EncodedCommand $encodedCommand
    
    # Also try with bypass flags (additional detection trigger)
    Write-Host "`n[*] Executing with bypass flags..."
    $command2 = "Write-Host '[RTL Test] Bypass execution completed' -ForegroundColor Green"
    $bytes2 = [System.Text.Encoding]::Unicode.GetBytes($command2)
    $encodedCommand2 = [Convert]::ToBase64String($bytes2)
    
    powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand $encodedCommand2
    
    Write-Host "[+] SUCCESS: Encoded PowerShell execution completed" -ForegroundColor Green
    Write-Host "[!] CrowdStrike should detect: 'EncodedCommandExecution' or 'SuspiciousPowerShell'" -ForegroundColor Magenta
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}

Write-Host "`n[*] Detection should appear in CrowdStrike within 1-2 minutes" -ForegroundColor Cyan
