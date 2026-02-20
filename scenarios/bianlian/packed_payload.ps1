<#
.SYNOPSIS
    BianLian Packed Payload Simulation - DETECTION TRIGGER
.DESCRIPTION
    Creates a base64-encoded payload and decodes it to disk.
    TTP: T1027.002, T1140
#>
$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting BianLian Packed Payload Simulation (T1027.002)" -ForegroundColor Cyan

# Step 1: Create staging directory
$stagingDir = "C:\temp\bianlian_staging"
if (-not (Test-Path $stagingDir)) { New-Item -Path $stagingDir -ItemType Directory -Force | Out-Null }

# Step 2: Create a payload and encode it (T1027)
Write-Host "`n[*] [T1027] Creating obfuscated payload..."
$payloadScript = @"
# RTL Detection Test - Simulated BianLian Payload
Write-Host "[RTL] Packed payload executed successfully"
Get-Process | Select-Object -First 5 Name, Id, CPU
whoami /all
ipconfig /all
"@

# Base64 encode
$bytes = [System.Text.Encoding]::Unicode.GetBytes($payloadScript)
$encoded = [Convert]::ToBase64String($bytes)
Write-Host "    [+] Payload encoded (length: $($encoded.Length) chars)" -ForegroundColor Green

# Write encoded payload to disk
$encodedPath = "$stagingDir\payload.b64"
$encoded | Out-File $encodedPath -Encoding ASCII
Write-Host "    [+] Encoded payload written: $encodedPath" -ForegroundColor Green

# Step 3: Decode and execute (T1140)
Write-Host "`n[*] [T1140] Decoding and executing payload..."
Write-Host "    CMD: powershell -EncodedCommand <base64>"
try {
    $decodedBytes = [Convert]::FromBase64String($encoded)
    $decodedScript = [System.Text.Encoding]::Unicode.GetString($decodedBytes)
    
    # Write decoded to disk
    $decodedPath = "$stagingDir\payload_decoded.ps1"
    $decodedScript | Out-File $decodedPath -Encoding UTF8
    Write-Host "    [+] Decoded payload written: $decodedPath" -ForegroundColor Green
    
    # Execute via encoded command (triggers EDR)
    Start-Process powershell -ArgumentList "-NoProfile -EncodedCommand $encoded" -Wait -NoNewWindow
    Write-Host "    [+] Encoded command execution complete" -ForegroundColor Green
} catch {
    Write-Host "    [-] Decode/execute failed: $_" -ForegroundColor Red
}

# Step 4: XOR obfuscation simulation
Write-Host "`n[*] [T1027] XOR obfuscation demonstration..."
$xorKey = 0x42
$plaintext = "RTL_BianLian_Payload_Marker"
$xorBytes = [System.Text.Encoding]::ASCII.GetBytes($plaintext) | ForEach-Object { $_ -bxor $xorKey }
$xorHex = ($xorBytes | ForEach-Object { $_.ToString("X2") }) -join ""
Write-Host "    [+] XOR encrypted (key=0x42): $xorHex" -ForegroundColor Green

# Decrypt
$decrypted = ($xorBytes | ForEach-Object { $_ -bxor $xorKey })
$decryptedText = [System.Text.Encoding]::ASCII.GetString($decrypted)
Write-Host "    [+] Decrypted: $decryptedText" -ForegroundColor Green

Write-Host "`n[+] Packed Payload Simulation Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: Base64 encoded command, suspicious file writes, obfuscated execution" -ForegroundColor Magenta
