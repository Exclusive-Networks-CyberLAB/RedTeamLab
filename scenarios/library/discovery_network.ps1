<#
.SYNOPSIS
    Generic Discovery - Network Configuration - DETECTION TRIGGER
.DESCRIPTION
    Enumerates network configuration.
    Will trigger EDR detection for T1016.
    TTP: T1016
#>
Write-Host "[*] Starting Network Configuration Discovery (T1016)" -ForegroundColor Cyan
Write-Host "[*] This will trigger EDR detection for discovery" -ForegroundColor Yellow

# ACTUAL DETECTION TRIGGER - Network enumeration commands
Write-Host "`n[*] Executing: ipconfig /all" -ForegroundColor Yellow
Write-Host "========================================"
ipconfig /all

Write-Host "`n[*] Executing: Get-NetIPConfiguration" -ForegroundColor Yellow
Write-Host "========================================"
Get-NetIPConfiguration | Format-List

Write-Host "`n[*] Executing: Get-NetAdapter" -ForegroundColor Yellow
Write-Host "========================================"
Get-NetAdapter | Format-Table Name, InterfaceDescription, Status, MacAddress -AutoSize

Write-Host "`n[*] Executing: Get-DnsClientServerAddress" -ForegroundColor Yellow
Write-Host "========================================"
Get-DnsClientServerAddress | Format-Table InterfaceAlias, ServerAddresses -AutoSize

Write-Host "`n[*] Executing: route print" -ForegroundColor Yellow
Write-Host "========================================"
route print

Write-Host "`n[!] CrowdStrike may detect: 'DiscoveryActivity' or 'NetworkEnumeration'" -ForegroundColor Magenta
Write-Host "[*] Discovery commands completed" -ForegroundColor Cyan
