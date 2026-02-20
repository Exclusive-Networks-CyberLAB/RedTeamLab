<#
.SYNOPSIS
    DragonForce Self-Delete - DETECTION TRIGGER
.DESCRIPTION
    Demonstrates ransomware self-deletion after execution.
    TTP: T1070.004
#>
$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting DragonForce Self-Delete Simulation (T1070.004)" -ForegroundColor Cyan

# Step 1: Create a temporary payload to self-delete
$tempDir = "C:\temp\dragonforce_staging"
if (-not (Test-Path $tempDir)) { New-Item -Path $tempDir -ItemType Directory -Force | Out-Null }

$selfDeleteScript = @"
# RTL DragonForce Self-Delete Test
Write-Host "[*] Payload executing..."
Write-Host "[*] Collecting system info..."
whoami
hostname
Write-Host "[*] Self-deleting..."
Remove-Item -Path `$MyInvocation.MyCommand.Path -Force
Write-Host "[+] Self-delete executed"
"@

$payloadPath = "$tempDir\dragonforce_payload.ps1"
$selfDeleteScript | Out-File $payloadPath -Encoding UTF8
Write-Host "[+] Created self-deleting payload: $payloadPath" -ForegroundColor Green

# Step 2: Execute the self-deleting payload
Write-Host "`n[*] [T1070.004] Executing self-deleting payload..."
Write-Host "    CMD: powershell -NoProfile -File $payloadPath"
try {
    Start-Process powershell -ArgumentList "-NoProfile -File `"$payloadPath`"" -Wait -NoNewWindow
    
    if (-not (Test-Path $payloadPath)) {
        Write-Host "    [+] Payload self-deleted successfully" -ForegroundColor Green
    } else {
        Write-Host "    [-] Payload still exists (self-delete may have failed)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "    [-] Execution failed: $_" -ForegroundColor Red
}

# Step 3: cmd.exe delayed self-delete technique
Write-Host "`n[*] [T1070.004] Testing cmd delayed delete technique..."
$tempBat = "$tempDir\cleanup.bat"
@"
@echo off
ping 127.0.0.1 -n 2 > nul
del "%~f0"
"@ | Out-File $tempBat -Encoding ASCII
Start-Process "cmd.exe" -ArgumentList "/c `"$tempBat`"" -WindowStyle Hidden
Write-Host "    [+] Delayed self-delete batch executed" -ForegroundColor Green

Write-Host "`n[+] Self-Delete Simulation Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: File self-deletion, delayed delete via ping/del, PowerShell Remove-Item" -ForegroundColor Magenta
