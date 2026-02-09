$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting WSL File Access & Staging..." -ForegroundColor Cyan

# T1005 - Data from Local System
# T1074 - Data Staged
# Adversaries can access Windows files via WSL's /mnt/ mount points

Write-Host "[*] [T1005] Accessing Windows filesystem via WSL mount points..."

# Show available Windows drives
Write-Host "`n[*] Enumerating mounted Windows drives..."
wsl.exe bash -c "df -h | grep /mnt/"

# Access sensitive Windows locations
Write-Host "`n[*] Checking access to Windows user profiles..."
wsl.exe bash -c "ls -la /mnt/c/Users/ 2>/dev/null"

# Look for interesting files
Write-Host "`n[*] Searching for potentially sensitive files..."
Write-Host "[*] Looking for configuration files..."
wsl.exe bash -c "find /mnt/c/Users -maxdepth 3 -name '*.config' -o -name '*.xml' 2>/dev/null | head -10"

Write-Host "`n[*] Looking for database files..."
wsl.exe bash -c "find /mnt/c/Users -maxdepth 4 -name '*.db' -o -name '*.sqlite' 2>/dev/null | head -5"

# T1074.001 - Local Data Staging
Write-Host "`n[*] [T1074.001] Creating staging directory in WSL..."
wsl.exe bash -c "mkdir -p /tmp/staged_data && echo '[+] Staging directory created: /tmp/staged_data'"

# Simulate copying files to staging
Write-Host "`n[*] Simulating file staging operation..."
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
wsl.exe bash -c "echo 'Staged data manifest - $timestamp' > /tmp/staged_data/manifest.txt"
wsl.exe bash -c "echo 'File1: /mnt/c/Users/*/Documents/*.docx' >> /tmp/staged_data/manifest.txt"
wsl.exe bash -c "echo 'File2: /mnt/c/Users/*/Desktop/*.xlsx' >> /tmp/staged_data/manifest.txt"

Write-Host "`n[*] Staging manifest contents:"
wsl.exe cat /tmp/staged_data/manifest.txt

# Show that Linux tools can read Windows files
Write-Host "`n[*] Demonstrating cross-platform file access..."
wsl.exe bash -c "cat /mnt/c/Windows/System32/drivers/etc/hosts | head -5"

Write-Host "`n[+] WSL File Access & Staging Complete." -ForegroundColor Green
