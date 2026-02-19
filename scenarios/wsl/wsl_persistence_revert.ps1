$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Reverting WSL Cron Persistence..." -ForegroundColor Cyan

# Remove cron job
Write-Host "[*] Removing cron persistence entry..."
wsl.exe bash -c "crontab -l 2>/dev/null | grep -v '.wsl_persist' | crontab -"
Write-Host "[+] Cron entry removed" -ForegroundColor Green

# Remove persistence script
Write-Host "[*] Removing persistence payload..."
wsl.exe rm -f /tmp/.wsl_persist.sh
Write-Host "[+] Payload removed" -ForegroundColor Green

# Remove log file
Write-Host "[*] Removing log files..."
wsl.exe rm -f /tmp/.wsl_persist.log
Write-Host "[+] Logs removed" -ForegroundColor Green

# Verify cleanup
Write-Host "`n[*] Verifying cleanup..."
Write-Host "[*] Current crontab:"
wsl.exe crontab -l 2>&1

Write-Host "`n[+] WSL Persistence Reverted Successfully." -ForegroundColor Green
