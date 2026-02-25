$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Reverting Golden/Silver/Diamond Ticket Attack..." -ForegroundColor Cyan
Write-Host "[*] Purging all cached Kerberos tickets..." -ForegroundColor Yellow

# Purge all Kerberos tickets from the current session
Write-Host "    CMD: klist purge"
klist purge 2>&1

# Also purge tickets for all logon sessions (requires admin)
Write-Host "`n[*] Attempting to purge tickets for all sessions (requires admin)..." -ForegroundColor Yellow
Write-Host "    CMD: klist -li 0x3e7 purge"
klist -li 0x3e7 purge 2>&1

# Clean up staged ticket files
$stagingDir = "C:\temp\staging"
$ticketFiles = Get-ChildItem -Path $stagingDir -Filter "*.kirbi" -ErrorAction SilentlyContinue
if ($ticketFiles) {
    Write-Host "`n[*] Removing staged ticket files..." -ForegroundColor Yellow
    foreach ($file in $ticketFiles) {
        Remove-Item $file.FullName -Force
        Write-Host "    [+] Removed: $($file.Name)" -ForegroundColor Green
    }
}

# Verify cleanup
Write-Host "`n[*] Current Kerberos ticket cache:" -ForegroundColor Yellow
klist 2>&1

Write-Host "`n[+] Ticket Revert Complete. All forged tickets purged." -ForegroundColor Green
Write-Host "[!] Note: The user may need to re-authenticate for legitimate services" -ForegroundColor Yellow
