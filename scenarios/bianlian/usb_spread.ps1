<#
.SYNOPSIS
    BianLian USB Spread Simulation - DETECTION TRIGGER
.DESCRIPTION
    Enumerates removable drives and creates autorun artifacts.
    TTP: T1091
#>
$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting BianLian USB Spread Simulation (T1091)" -ForegroundColor Cyan

# Step 1: Enumerate removable drives
Write-Host "`n[*] [T1091] Enumerating removable media..."
Write-Host "    CMD: Get-WmiObject Win32_LogicalDisk -Filter DriveType=2"
$removable = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=2"
if ($removable) {
    foreach ($drive in $removable) {
        Write-Host "    [!] Removable drive found: $($drive.DeviceID) ($($drive.VolumeName))" -ForegroundColor Yellow
        Write-Host "        Size: $([math]::Round($drive.Size/1GB, 2)) GB"
        Write-Host "        Free: $([math]::Round($drive.FreeSpace/1GB, 2)) GB"
    }
} else {
    Write-Host "    [-] No removable drives found" -ForegroundColor Gray
}

# Step 2: Enumerate ALL drives for lateral spread enumeration
Write-Host "`n[*] [T1083] Enumerating all logical drives..."
$allDrives = Get-WmiObject Win32_LogicalDisk
foreach ($drive in $allDrives) {
    $driveType = switch ($drive.DriveType) {
        0 { "Unknown" }; 1 { "No Root" }; 2 { "Removable" }
        3 { "Local" }; 4 { "Network" }; 5 { "CD-ROM" }; 6 { "RAM" }
    }
    Write-Host "    [*] $($drive.DeviceID) -> $driveType ($($drive.VolumeName))"
}

# Step 3: Create autorun artifact in staging (simulated USB payload)
Write-Host "`n[*] [T1091] Creating autorun payload artifacts..."
$stagingDir = "C:\temp\usb_staging"
if (-not (Test-Path $stagingDir)) { New-Item -Path $stagingDir -ItemType Directory -Force | Out-Null }

$autorunContent = @"
[AutoRun]
; RTL Detection Test - Simulated USB Worm Autorun
Open=payload.exe
Action=Open folder to view files
Icon=shell32.dll,4
Label=Documents
Shell\Open\Command=payload.exe
"@
$autorunContent | Out-File "$stagingDir\autorun.inf" -Encoding ASCII
Write-Host "    [+] Created: $stagingDir\autorun.inf" -ForegroundColor Green

# Create fake payload
"RTL USB Spread Test Payload" | Out-File "$stagingDir\payload.exe" -Encoding ASCII
Write-Host "    [+] Created: $stagingDir\payload.exe" -ForegroundColor Green

# Step 4: Enumerate USB device history from registry
Write-Host "`n[*] [T1120] Enumerating USB device history..."
Write-Host "    CMD: Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*"
try {
    $usbDevices = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" -ErrorAction SilentlyContinue
    foreach ($device in $usbDevices) {
        Write-Host "    [*] USB History: $($device.PSChildName)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "    [-] Cannot access USB history" -ForegroundColor Gray
}

Write-Host "`n[+] USB Spread Simulation Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: Removable media enumeration, autorun.inf creation, USB device history access" -ForegroundColor Magenta
