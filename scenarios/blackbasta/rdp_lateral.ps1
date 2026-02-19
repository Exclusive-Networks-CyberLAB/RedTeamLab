<#
.SYNOPSIS
    Black Basta RDP Lateral Movement - DETECTION TRIGGER
.DESCRIPTION
    Performs RDP connection attempt to target.
    Will trigger EDR detection for T1021.001.
    TTP: T1021.001
.PARAMETER TargetIP
    Target IP address for RDP connection
#>
param(
    [Parameter(Mandatory=$false)]
    [string]$TargetIP = "10.0.0.1"
)

Write-Host "[*] Starting Black Basta RDP Lateral Movement (T1021.001)" -ForegroundColor Cyan
Write-Host "[*] Target: $TargetIP" -ForegroundColor Yellow
Write-Host "[*] This will trigger EDR detection for lateral movement" -ForegroundColor Yellow

try {
    # First check if port is open
    Write-Host "[*] Testing RDP port 3389 on $TargetIP..."
    $tcpTest = Test-NetConnection -ComputerName $TargetIP -Port 3389 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    
    if ($tcpTest.TcpTestSucceeded) {
        Write-Host "[+] RDP port 3389 is OPEN on $TargetIP" -ForegroundColor Green
        
        # ACTUAL DETECTION TRIGGER - Launch mstsc
        Write-Host "[*] Executing: mstsc /v:$TargetIP"
        
        # Start RDP client (this triggers the lateral movement detection)
        Start-Process "mstsc.exe" -ArgumentList "/v:$TargetIP" -ErrorAction SilentlyContinue
        
        Write-Host "[+] RDP client launched to $TargetIP" -ForegroundColor Green
        Write-Host "[!] CrowdStrike should detect: 'LateralMovementRDP' or 'RemoteDesktopConnection'" -ForegroundColor Magenta
        
    } else {
        Write-Host "[-] RDP port 3389 is CLOSED or unreachable on $TargetIP" -ForegroundColor Red
        Write-Host "[*] Attempting connection anyway to generate detection..."
        
        # Still attempt to trigger detection even if port is closed
        Start-Process "mstsc.exe" -ArgumentList "/v:$TargetIP" -ErrorAction SilentlyContinue
    }
    
    # Also try cmdkey for credential caching (another lateral movement indicator)
    Write-Host "[*] Also testing cmdkey credential caching..."
    $cmdkeyResult = cmdkey /add:$TargetIP /user:TestUser /pass:TestPass123 2>&1
    Write-Host "[*] Cmdkey result: $cmdkeyResult"
    
    # Cleanup
    cmdkey /delete:$TargetIP 2>&1 | Out-Null
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}

Write-Host "`n[*] Detection should appear in CrowdStrike within 1-2 minutes" -ForegroundColor Cyan
