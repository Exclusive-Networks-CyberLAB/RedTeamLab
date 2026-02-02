<#
.SYNOPSIS
    BianLian USB Spread Simulation
.DESCRIPTION
    Detects removable drives for potential spread.
    TTP: T1091
#>
Write-Host "[*] Starting BianLian USB Spread Simulation (T1091)" -ForegroundColor Cyan
Write-Host "[*] Command: Get-WmiObject Win32_LogicalDisk -Filter 'DriveType=2'"
$removable = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=2"
if ($removable) {
    foreach ($drive in $removable) {
        Write-Host "[!] Removable drive found: $($drive.DeviceID)" -ForegroundColor Yellow
    }
    Write-Host "[!] Ransomware would copy itself to these drives." -ForegroundColor Yellow
} else {
    Write-Host "[-] No removable drives detected." -ForegroundColor Gray
}
