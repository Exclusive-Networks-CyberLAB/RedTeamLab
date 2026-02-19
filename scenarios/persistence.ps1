$ErrorActionPreference = "Stop"
Write-Host "[*] Establishing Persistence (Registry Run Key)..."

$keyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$name = "Updater"
$value = "C:\Windows\System32\calc.exe"

Write-Host "[*] Target Key: $keyPath"
Write-Host "[*] Value Name: $name"

try {
    # REAL EXECUTION: Writing to Registry
    if (Test-Path $keyPath) {
        New-ItemProperty -Path $keyPath -Name $name -Value $value -PropertyType String -Force | Out-Null
        Write-Host "    [+] Registry Key Created Successfully."
        Write-Host "    [!] ALERT: Artifact created at $keyPath\$name"
    } else {
        Write-Host "    [-] Target registry path not found."
    }
} catch {
    Write-Host "    [-] Failed to create registry key. Error: $_"
    Write-Host "    [!] Note: Ensure you are running this app as Administrator if targeting HKLM."
}

Write-Host "[*] Verifying Persistence..."
try {
    $item = Get-ItemProperty -Path $keyPath -Name $name -ErrorAction SilentlyContinue
    if ($item) {
        Write-Host "    [+] Verified: $($item.$name)"
    } else {
         Write-Host "    [-] Verification Failed."
    }
} catch {}

Write-Host "`n[+] Persistence Configuration Complete."
