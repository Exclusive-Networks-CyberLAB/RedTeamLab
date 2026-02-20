<#
.SYNOPSIS
    Black Basta RDP Lateral Movement - DETECTION TRIGGER
.DESCRIPTION
    Attempts RDP lateral movement using cmdkey credential caching and mstsc.
    TTP: T1021.001
#>
$ErrorActionPreference = "SilentlyContinue"
$TargetIP = if ($env:TARGET_IP) { $env:TARGET_IP } else { "192.168.1.10" }

Write-Host "[*] Starting Black Basta RDP Lateral Movement (T1021.001)" -ForegroundColor Cyan
Write-Host "[!] Target: $TargetIP" -ForegroundColor Yellow

# Step 1: Test RDP port connectivity
Write-Host "`n[*] Testing RDP connectivity (port 3389)..."
Write-Host "    CMD: Test-NetConnection -ComputerName $TargetIP -Port 3389"
$rdpTest = Test-NetConnection -ComputerName $TargetIP -Port 3389 -WarningAction SilentlyContinue
if ($rdpTest.TcpTestSucceeded) {
    Write-Host "    [+] RDP port 3389 is OPEN" -ForegroundColor Green
} else {
    Write-Host "    [-] RDP port 3389 not reachable" -ForegroundColor Red
}

# Step 2: Cache credentials with cmdkey (T1078)
Write-Host "`n[*] [T1078] Caching RDP credentials via cmdkey..."
Write-Host "    CMD: cmdkey /add:$TargetIP /user:administrator /pass:P@ssw0rd123"
cmdkey /add:$TargetIP /user:administrator /pass:"P@ssw0rd123" 2>&1

# Step 3: Enumerate existing cached credentials
Write-Host "`n[*] Listing cached credentials..."
Write-Host "    CMD: cmdkey /list"
cmdkey /list 2>&1 | ForEach-Object { Write-Host "    $_" }

# Step 4: Attempt RDP connection (will launch mstsc briefly)
Write-Host "`n[*] [T1021.001] Launching RDP connection attempt..."
Write-Host "    CMD: mstsc /v:$TargetIP"
try {
    $proc = Start-Process -FilePath "mstsc" -ArgumentList "/v:$TargetIP" -PassThru -ErrorAction Stop
    Start-Sleep -Seconds 3
    if (!$proc.HasExited) {
        $proc.Kill()
        Write-Host "    [+] RDP client launched and terminated (detection triggered)" -ForegroundColor Green
    }
} catch {
    Write-Host "    [-] mstsc launch failed: $_" -ForegroundColor Red
}

# Step 5: Cleanup cached credentials
Write-Host "`n[*] Cleaning up cached credentials..."
Write-Host "    CMD: cmdkey /delete:$TargetIP"
cmdkey /delete:$TargetIP 2>&1

Write-Host "`n[+] RDP Lateral Movement Simulation Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: cmdkey credential caching, mstsc.exe launch, RDP connection attempt" -ForegroundColor Magenta
