$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting WSL Defense Evasion - Indirect Command Execution..." -ForegroundColor Cyan

# T1202 - Indirect Command Execution
# Adversaries may use wsl.exe to execute commands, bypassing Windows command-line logging
# and security controls that focus on PowerShell/cmd.exe

Write-Host "[*] [T1202] Demonstrating command execution bypass via WSL..."
Write-Host "[!] This technique bypasses Windows command-line monitoring by using wsl.exe" -ForegroundColor Yellow

# Execute whoami via WSL - bypasses Windows command logging
Write-Host "`n[*] Executing 'whoami' via wsl.exe (bypasses Windows cmd logging)..."
$result = wsl.exe whoami
Write-Host "[+] Result: $result" -ForegroundColor Green

# Execute network commands via bash - harder to detect
Write-Host "`n[*] Executing network enumeration via bash..."
wsl.exe bash -c "cat /etc/resolv.conf | grep nameserver"

# Execute encoded command (additional obfuscation)
Write-Host "`n[*] [T1027] Executing base64 encoded command via WSL..."
$encodedCmd = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("echo 'Defense Evasion Test Successful'"))
wsl.exe bash -c "echo $encodedCmd | base64 -d | bash"

# Access Windows file system stealthily
Write-Host "`n[*] Accessing Windows temp directory via WSL mount..."
wsl.exe bash -c "ls -la /mnt/c/Windows/Temp/ | head -10"

# Demonstrate process execution that may evade EDR
Write-Host "`n[*] Spawning process via WSL that appears as wsl.exe to Windows..."
wsl.exe bash -c "sleep 1 && echo '[+] Process completed inside WSL subsystem'"

Write-Host "`n[+] Defense Evasion Demonstration Complete." -ForegroundColor Green
Write-Host "[!] Note: All commands executed via WSL may evade standard Windows logging" -ForegroundColor Yellow
