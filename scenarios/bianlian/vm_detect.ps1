<#
.SYNOPSIS
    BianLian VM Detection - DETECTION TRIGGER
.DESCRIPTION
    Detects virtualization/sandbox environments using WMI queries.
    TTP: T1497
#>
$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting BianLian VM/Sandbox Detection (T1497)" -ForegroundColor Cyan

# Step 1: WMI Computer System query
Write-Host "`n[*] [T1497] Querying system manufacturer..."
Write-Host "    CMD: Get-WmiObject Win32_ComputerSystem"
$cs = Get-WmiObject Win32_ComputerSystem
Write-Host "    [*] Manufacturer: $($cs.Manufacturer)" -ForegroundColor Yellow
Write-Host "    [*] Model: $($cs.Model)" -ForegroundColor Yellow
Write-Host "    [*] Total Memory: $([math]::Round($cs.TotalPhysicalMemory/1GB, 2)) GB"

$vmIndicators = @("VMware", "VirtualBox", "Hyper-V", "QEMU", "Xen", "KVM", "Virtual")
$isVM = $false
foreach ($indicator in $vmIndicators) {
    if ($cs.Manufacturer -match $indicator -or $cs.Model -match $indicator) {
        Write-Host "    [!] VM DETECTED: $indicator" -ForegroundColor Red
        $isVM = $true
    }
}

# Step 2: Check BIOS for VM signatures
Write-Host "`n[*] [T1497] Checking BIOS information..."
Write-Host "    CMD: Get-WmiObject Win32_BIOS"
$bios = Get-WmiObject Win32_BIOS
Write-Host "    [*] BIOS Manufacturer: $($bios.Manufacturer)"
Write-Host "    [*] BIOS Version: $($bios.SMBIOSBIOSVersion)"
Write-Host "    [*] Serial: $($bios.SerialNumber)"

# Step 3: Check for VM tools processes
Write-Host "`n[*] [T1497] Checking for VM tools processes..."
$vmProcesses = @("vmtoolsd", "vmwaretray", "VBoxService", "VBoxTray", "xenservice")
foreach ($proc in $vmProcesses) {
    $found = Get-Process -Name $proc -ErrorAction SilentlyContinue
    if ($found) {
        Write-Host "    [!] VM Process found: $proc (PID: $($found.Id))" -ForegroundColor Red
    }
}

# Step 4: Check disk size (VMs often have small disks)
Write-Host "`n[*] [T1497] Checking disk size..."
$disk = Get-WmiObject Win32_DiskDrive | Select-Object -First 1
$diskSizeGB = [math]::Round($disk.Size / 1GB, 2)
Write-Host "    [*] Primary disk: $diskSizeGB GB"
if ($diskSizeGB -lt 60) {
    Write-Host "    [!] Small disk detected - possible VM" -ForegroundColor Yellow
}

# Step 5: Check MAC address for VM vendor prefixes
Write-Host "`n[*] [T1497] Checking network adapter MAC addresses..."
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.MACAddress }
$vmMACs = @("00:0C:29", "00:50:56", "08:00:27", "00:1C:14", "00:15:5D")
foreach ($adapter in $adapters) {
    $mac = $adapter.MACAddress
    Write-Host "    [*] MAC: $mac ($($adapter.Description))"
    foreach ($vmMAC in $vmMACs) {
        if ($mac -like "$vmMAC*") {
            Write-Host "    [!] VM MAC prefix detected: $vmMAC" -ForegroundColor Red
        }
    }
}

Write-Host "`n[+] VM/Sandbox Detection Complete." -ForegroundColor Green
if ($isVM) {
    Write-Host "[!] RESULT: Running in a VIRTUAL environment" -ForegroundColor Red
} else {
    Write-Host "[+] RESULT: Appears to be physical hardware" -ForegroundColor Green
}
Write-Host "[!] Check EDR for: WMI enumeration queries, VM detection behavior" -ForegroundColor Magenta
