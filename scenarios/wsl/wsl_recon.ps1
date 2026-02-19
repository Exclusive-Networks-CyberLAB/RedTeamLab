$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting WSL Reconnaissance & Enumeration..." -ForegroundColor Cyan

# Check if WSL is available
Write-Host "[*] Checking WSL availability..."
$wslCheck = wsl.exe --list --quiet 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] WSL is not installed or not configured properly." -ForegroundColor Red
    exit 1
}
Write-Host "[+] WSL is available. Installed distributions:" -ForegroundColor Green
wsl.exe --list --verbose

# T1202 - Indirect Command Execution via WSL
Write-Host "`n[*] [T1202] Executing Linux reconnaissance via WSL..."

Write-Host "`n[*] Gathering system information via uname..."
wsl.exe uname -a

Write-Host "`n[*] Enumerating network interfaces via ip addr..."
wsl.exe ip addr 2>/dev/null

Write-Host "`n[*] Checking mounted Windows drives..."
wsl.exe ls -la /mnt/

Write-Host "`n[*] [T1083] Listing Windows Users directory from WSL..."
wsl.exe ls -la /mnt/c/Users/

Write-Host "`n[*] Checking current user context in WSL..."
wsl.exe whoami

Write-Host "`n[*] Enumerating running Linux processes..."
wsl.exe ps aux 2>/dev/null

Write-Host "`n[+] WSL Reconnaissance Complete." -ForegroundColor Green
