<#
.SYNOPSIS
    Generic Discovery - Domain Groups - DETECTION TRIGGER
.DESCRIPTION
    Enumerates domain groups and members.
    Will trigger EDR detection for T1069.
    TTP: T1069, T1069.002
#>
Write-Host "[*] Starting Domain Groups Discovery (T1069)" -ForegroundColor Cyan
Write-Host "[*] This will trigger EDR detection for discovery" -ForegroundColor Yellow

# ACTUAL DETECTION TRIGGER - Group enumeration commands
Write-Host "`n[*] Executing: net group /domain" -ForegroundColor Yellow
Write-Host "========================================"
net group /domain 2>&1

Write-Host "`n[*] Executing: net group 'Domain Admins' /domain" -ForegroundColor Yellow
Write-Host "========================================"
net group "Domain Admins" /domain 2>&1

Write-Host "`n[*] Executing: net group 'Enterprise Admins' /domain" -ForegroundColor Yellow
Write-Host "========================================"
net group "Enterprise Admins" /domain 2>&1

Write-Host "`n[*] Executing: net localgroup Administrators" -ForegroundColor Yellow
Write-Host "========================================"
net localgroup Administrators 2>&1

Write-Host "`n[*] Executing: Get-ADGroupMember (if available)" -ForegroundColor Yellow
Write-Host "========================================"
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Get-ADGroupMember -Identity "Domain Admins" | Format-Table Name, SamAccountName, ObjectClass
} catch {
    Write-Host "[-] ActiveDirectory module not available or not domain-joined" -ForegroundColor Gray
}

Write-Host "`n[!] CrowdStrike may detect: 'DiscoveryActivity' or 'DomainEnumeration'" -ForegroundColor Magenta
Write-Host "[*] Discovery commands completed" -ForegroundColor Cyan
