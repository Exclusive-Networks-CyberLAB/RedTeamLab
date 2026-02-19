<#
.SYNOPSIS
    BianLian VM Detection - DETECTION TRIGGER
.DESCRIPTION
    Checks for virtualization indicators (sandbox evasion).
    Will trigger EDR detection for T1497.
    TTP: T1497
#>
Write-Host "[*] Starting BianLian VM Detection (T1497)" -ForegroundColor Cyan
Write-Host "[*] This will trigger EDR detection for evasion behavior" -ForegroundColor Yellow

# ACTUAL DETECTION TRIGGER - VM/Sandbox detection queries
$vmIndicators = @()

Write-Host "`n[*] Checking WMI for virtualization..." -ForegroundColor Yellow

# Check BIOS
try {
    $bios = Get-WmiObject Win32_BIOS
    Write-Host "[*] BIOS: $($bios.Manufacturer) - $($bios.SMBIOSBIOSVersion)"
    if ($bios.Manufacturer -match "VMware|VirtualBox|Xen|QEMU|Hyper-V") {
        $vmIndicators += "BIOS indicates VM"
    }
} catch {
    Write-Host "[-] Could not query BIOS" -ForegroundColor Gray
}

# Check Computer System
try {
    $cs = Get-WmiObject Win32_ComputerSystem
    Write-Host "[*] Manufacturer: $($cs.Manufacturer)"
    Write-Host "[*] Model: $($cs.Model)"
    if ($cs.Model -match "VMware|VirtualBox|Virtual Machine|HVM") {
        $vmIndicators += "Computer model indicates VM"
    }
} catch {
    Write-Host "[-] Could not query ComputerSystem" -ForegroundColor Gray
}

# Check for VM-specific processes
$vmProcesses = @("vmtoolsd", "vmwaretray", "VBoxService", "VBoxTray", "xenservice")
$runningVMProcs = Get-Process | Where-Object { $_.Name -in $vmProcesses }
if ($runningVMProcs) {
    $vmIndicators += "VM tools processes running"
    Write-Host "[*] VM Processes found: $($runningVMProcs.Name -join ', ')"
}

# Check MAC address prefixes
$macPrefixes = @("00:0C:29", "00:50:56", "00:1C:42", "08:00:27", "00:15:5D")
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
foreach ($adapter in $adapters) {
    $mac = $adapter.MacAddress -replace '-', ':'
    foreach ($prefix in $macPrefixes) {
        if ($mac.StartsWith($prefix)) {
            $vmIndicators += "VM MAC prefix detected: $mac"
        }
    }
}

# Check registry for VM artifacts
$vmRegKeys = @(
    "HKLM:\SOFTWARE\VMware, Inc.\VMware Tools",
    "HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions"
)
foreach ($key in $vmRegKeys) {
    if (Test-Path $key) {
        $vmIndicators += "VM registry key found: $key"
    }
}

Write-Host "`n[*] VM Detection Summary:" -ForegroundColor Cyan
if ($vmIndicators.Count -gt 0) {
    Write-Host "[!] VIRTUAL MACHINE DETECTED" -ForegroundColor Red
    foreach ($indicator in $vmIndicators) {
        Write-Host "    - $indicator" -ForegroundColor Yellow
    }
} else {
    Write-Host "[+] No obvious VM indicators found (could be physical or well-hidden VM)" -ForegroundColor Green
}

Write-Host "`n[!] CrowdStrike may detect: 'SandboxEvasion' or 'VMDetection'" -ForegroundColor Magenta
Write-Host "[*] VM detection completed" -ForegroundColor Cyan
