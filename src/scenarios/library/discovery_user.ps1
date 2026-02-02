<#
.SYNOPSIS
    Generic Discovery - User Context - DETECTION TRIGGER
.DESCRIPTION
    Discovers current user context and privileges.
    Will trigger EDR detection for T1033.
    TTP: T1033
#>
Write-Host "[*] Starting User Context Discovery (T1033)" -ForegroundColor Cyan
Write-Host "[*] This will trigger EDR detection for discovery" -ForegroundColor Yellow

# ACTUAL DETECTION TRIGGER - User enumeration commands
Write-Host "`n[*] Executing: whoami /all" -ForegroundColor Yellow
Write-Host "========================================"
whoami /all

Write-Host "`n[*] Executing: net user %username%" -ForegroundColor Yellow
Write-Host "========================================"
net user $env:USERNAME

Write-Host "`n[*] Executing: [System.Security.Principal.WindowsIdentity]::GetCurrent()" -ForegroundColor Yellow
Write-Host "========================================"
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
Write-Host "Name: $($identity.Name)"
Write-Host "AuthenticationType: $($identity.AuthenticationType)"
Write-Host "IsAuthenticated: $($identity.IsAuthenticated)"
Write-Host "IsSystem: $($identity.IsSystem)"

Write-Host "`n[*] Executing: Get-LocalGroupMember -Group Administrators" -ForegroundColor Yellow
Write-Host "========================================"
Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Format-Table

Write-Host "`n[!] CrowdStrike may detect: 'DiscoveryActivity' or 'UserEnumeration'" -ForegroundColor Magenta
Write-Host "[*] Discovery commands completed" -ForegroundColor Cyan
