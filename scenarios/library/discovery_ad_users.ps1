<#
.SYNOPSIS
    Generic Discovery - AD Users - DETECTION TRIGGER
.DESCRIPTION
    Enumerates Active Directory users.
    Will trigger EDR detection for T1087.002.
    TTP: T1087, T1087.002
#>
Write-Host "[*] Starting AD User Discovery (T1087.002)" -ForegroundColor Cyan
Write-Host "[*] This will trigger EDR detection for discovery" -ForegroundColor Yellow

# ACTUAL DETECTION TRIGGER - User enumeration commands
Write-Host "`n[*] Executing: net user /domain" -ForegroundColor Yellow
Write-Host "========================================"
net user /domain 2>&1

Write-Host "`n[*] Executing: LDAP query for users" -ForegroundColor Yellow
Write-Host "========================================"
try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    Write-Host "Domain: $($domain.Name)"
    
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($domain.Name)")
    $searcher.Filter = "(&(objectClass=user)(objectCategory=person))"
    $searcher.PageSize = 100
    $searcher.PropertiesToLoad.Add("samaccountname") | Out-Null
    $searcher.PropertiesToLoad.Add("displayname") | Out-Null
    
    $results = $searcher.FindAll()
    Write-Host "[*] Found $($results.Count) user accounts"
    
    $results | Select-Object -First 20 | ForEach-Object {
        $sam = $_.Properties["samaccountname"]
        $dn = $_.Properties["displayname"]
        Write-Host "  $sam - $dn"
    }
    
    if ($results.Count -gt 20) {
        Write-Host "  ... and $($results.Count - 20) more"
    }
    
} catch {
    Write-Host "[-] Not domain-joined or LDAP query failed: $_" -ForegroundColor Gray
}

Write-Host "`n[*] Executing: Get-ADUser (if available)" -ForegroundColor Yellow
Write-Host "========================================"
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Get-ADUser -Filter * -Properties DisplayName | Select-Object -First 20 | Format-Table SamAccountName, DisplayName
} catch {
    Write-Host "[-] ActiveDirectory module not available" -ForegroundColor Gray
}

Write-Host "`n[!] CrowdStrike may detect: 'DiscoveryActivity' or 'ADEnumeration'" -ForegroundColor Magenta
Write-Host "[*] Discovery commands completed" -ForegroundColor Cyan
