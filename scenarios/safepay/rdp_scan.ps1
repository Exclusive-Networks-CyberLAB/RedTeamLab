<#
.SYNOPSIS
    SafePay RDP Scan - DETECTION TRIGGER
.DESCRIPTION
    Scans for RDP on target IP/subnet.
    Will trigger EDR detection for T1133.
    TTP: T1133
.PARAMETER TargetIP
    Target IP or subnet to scan (e.g., 10.0.0.1 or 10.0.0.0/24)
#>
param(
    [Parameter(Mandatory=$false)]
    [string]$TargetIP = "10.0.0.1"
)

Write-Host "[*] Starting SafePay RDP Scan (T1133)" -ForegroundColor Cyan
Write-Host "[*] Target: $TargetIP" -ForegroundColor Yellow
Write-Host "[*] This will trigger EDR detection for network scanning" -ForegroundColor Yellow

try {
    # Parse if it's a CIDR range or single IP
    if ($TargetIP -match '/') {
        # CIDR notation - scan range
        $parts = $TargetIP -split '/'
        $baseIP = $parts[0]
        $cidr = [int]$parts[1]
        
        # Simple /24 scanning for demo
        $ipParts = $baseIP -split '\.'
        $targets = 1..10 | ForEach-Object { "$($ipParts[0]).$($ipParts[1]).$($ipParts[2]).$_" }
        
        Write-Host "[*] Scanning first 10 IPs of subnet..."
    } else {
        $targets = @($TargetIP)
    }
    
    $openHosts = @()
    
    foreach ($target in $targets) {
        Write-Host "[*] Scanning $target`:3389..."
        
        # ACTUAL DETECTION TRIGGER - Port scan
        $result = Test-NetConnection -ComputerName $target -Port 3389 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        
        if ($result.TcpTestSucceeded) {
            Write-Host "[+] OPEN: $target`:3389" -ForegroundColor Green
            $openHosts += $target
        } else {
            Write-Host "[-] Closed: $target`:3389" -ForegroundColor Gray
        }
    }
    
    Write-Host "`n[*] Scan Summary:" -ForegroundColor Cyan
    Write-Host "[*] Targets scanned: $($targets.Count)"
    Write-Host "[*] Open RDP ports: $($openHosts.Count)"
    
    if ($openHosts.Count -gt 0) {
        Write-Host "[+] Open hosts: $($openHosts -join ', ')" -ForegroundColor Green
    }
    
    Write-Host "[!] CrowdStrike should detect: 'NetworkScanning' or 'PortScan'" -ForegroundColor Magenta
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}

Write-Host "`n[*] Detection should appear in CrowdStrike within 1-2 minutes" -ForegroundColor Cyan
