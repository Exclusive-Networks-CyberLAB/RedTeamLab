$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting Host Reconnaissance (PowerShell)..."

Write-Host "[*] [T1049] Enumerating Active TCP Connections..."
$conns = Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'}
foreach ($c in $conns) {
    Write-Host "    [+] Connected: $($c.LocalAddress):$($c.LocalPort) -> $($c.RemoteAddress):$($c.RemotePort)"
}

Write-Host "`n[*] [T1057] Identifying Interesting Processes..."
$procs = Get-Process | Where-Object {$_.ProcessName -match "lsass|winlogon|chrome|firefox"}
foreach ($p in $procs) {
    Write-Host "    [!] High Value Target Found: $($p.ProcessName) (PID: $($p.Id))"
}

Write-Host "`n[+] Reconnaissance Complete."
