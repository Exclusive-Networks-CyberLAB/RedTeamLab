$ErrorActionPreference = "SilentlyContinue"
$c2 = $env:C2_HOST

if ([string]::IsNullOrEmpty($c2)) {
    Write-Host "[!] Error: No C2 Host provided."
    exit 1
}

Write-Host "[*] Checking Connectivity to C2 Infrastructure: $c2"

# DNS Check
Write-Host "[*] Resolving DNS..."
try {
    $dns = Resolve-DnsName -Name $c2 -ErrorAction Stop
    Write-Host "    [+] DNS Resolution Successful: $($dns.IPAddress)"
} catch {
    Write-Host "    [-] DNS Resolution Failed."
}

# TCP Connect
Write-Host "`n[*] Testing TCP Connection (Port 443)..."
$tcp = Test-NetConnection -ComputerName $c2 -Port 443 -InformationLevel Quiet
if ($tcp) {
    Write-Host "    [+] Connection Established (HTTPS)."
} else {
    Write-Host "    [-] Connection Refused/Timeout."
}

Write-Host "`n[+] Communication Check Complete."
