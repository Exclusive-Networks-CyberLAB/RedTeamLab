<#
.SYNOPSIS
    SafePay RDP Scan - DETECTION TRIGGER
.DESCRIPTION
    Scans for exposed RDP services on target network.
    TTP: T1133, T1046
#>
$ErrorActionPreference = "SilentlyContinue"
$TargetIP = if ($env:TARGET_IP) { $env:TARGET_IP } else { "192.168.1.0" }

Write-Host "[*] Starting SafePay RDP Scan (T1133)" -ForegroundColor Cyan
Write-Host "[!] Target: $TargetIP" -ForegroundColor Yellow

# Step 1: Single host RDP check
Write-Host "`n[*] [T1133] Testing RDP on $TargetIP..."
Write-Host "    CMD: Test-NetConnection -ComputerName $TargetIP -Port 3389"
$result = Test-NetConnection -ComputerName $TargetIP -Port 3389 -WarningAction SilentlyContinue
if ($result.TcpTestSucceeded) {
    Write-Host "    [!] RDP is OPEN on $TargetIP" -ForegroundColor Red
} else {
    Write-Host "    [-] RDP closed on $TargetIP" -ForegroundColor Gray
}

# Step 2: Scan common ports for other remote services
Write-Host "`n[*] [T1046] Scanning remote access ports on $TargetIP..."
$ports = @(
    @{Port=22; Name="SSH"},
    @{Port=3389; Name="RDP"},
    @{Port=5900; Name="VNC"},
    @{Port=5985; Name="WinRM"},
    @{Port=5986; Name="WinRM-SSL"},
    @{Port=445; Name="SMB"},
    @{Port=135; Name="RPC"}
)
foreach ($p in $ports) {
    $test = Test-NetConnection -ComputerName $TargetIP -Port $p.Port -WarningAction SilentlyContinue
    if ($test.TcpTestSucceeded) {
        Write-Host "    [+] $($p.Name) ($($p.Port)): OPEN" -ForegroundColor Green
    } else {
        Write-Host "    [-] $($p.Name) ($($p.Port)): Closed" -ForegroundColor Gray
    }
}

# Step 3: Check local RDP configuration
Write-Host "`n[*] [T1133] Checking local RDP configuration..."
Write-Host "    CMD: Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
try {
    $rdpConfig = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -ErrorAction Stop
    $rdpEnabled = if ($rdpConfig.fDenyTSConnections -eq 0) { "ENABLED" } else { "DISABLED" }
    Write-Host "    [*] Local RDP: $rdpEnabled" -ForegroundColor Yellow
} catch {
    Write-Host "    [-] Cannot read RDP registry" -ForegroundColor Gray
}

# Step 4: Enumerate active RDP sessions
Write-Host "`n[*] Enumerating RDP sessions..."
Write-Host "    CMD: qwinsta"
qwinsta 2>&1 | ForEach-Object { Write-Host "    $_" }

Write-Host "`n[+] RDP Scan Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: Port scanning, RDP enumeration, registry access" -ForegroundColor Magenta
