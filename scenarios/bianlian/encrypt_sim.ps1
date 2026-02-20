<#
.SYNOPSIS
    BianLian Encryption Simulation - DETECTION TRIGGER
.DESCRIPTION
    Creates test files and encrypts them using AES.
    TTP: T1486
#>
$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting BianLian Encryption Simulation (T1486)" -ForegroundColor Cyan
Write-Host "[!] This creates and encrypts TEST files only - NO real user data affected" -ForegroundColor Yellow

# Step 1: Create test directory
$testDir = "C:\temp\bianlian_encrypt_test"
if (-not (Test-Path $testDir)) { New-Item -Path $testDir -ItemType Directory -Force | Out-Null }

# Step 2: Create test files
Write-Host "`n[*] Creating test files..."
$fileTypes = @(
    @{Name="report.docx"; Content="RTL Test - Simulated Word document content"},
    @{Name="financials.xlsx"; Content="RTL Test - Simulated Excel spreadsheet data"},
    @{Name="passwords.txt"; Content="RTL Test - Simulated password file"},
    @{Name="database_backup.sql"; Content="RTL Test - Simulated database dump"},
    @{Name="presentation.pptx"; Content="RTL Test - Simulated presentation"}
)
foreach ($file in $fileTypes) {
    $file.Content | Out-File "$testDir\$($file.Name)" -Encoding UTF8
    Write-Host "    [+] Created: $($file.Name)" -ForegroundColor Green
}

# Step 3: Generate AES key (like real ransomware)
Write-Host "`n[*] [T1486] Generating AES-256 encryption key..."
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.KeySize = 256
$aes.GenerateKey()
$aes.GenerateIV()
$keyHex = ($aes.Key | ForEach-Object { $_.ToString("X2") }) -join ""
Write-Host "    [+] AES-256 Key: $($keyHex.Substring(0, 16))..." -ForegroundColor Green

# Step 4: Encrypt each file
Write-Host "`n[*] [T1486] Encrypting test files..."
$files = Get-ChildItem $testDir -File | Where-Object { $_.Name -notmatch "\.bianlian$" }
foreach ($file in $files) {
    try {
        $plainBytes = [System.IO.File]::ReadAllBytes($file.FullName)
        $encryptor = $aes.CreateEncryptor()
        $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
        
        $encPath = $file.FullName + ".bianlian"
        [System.IO.File]::WriteAllBytes($encPath, $encryptedBytes)
        Remove-Item $file.FullName -Force
        Write-Host "    [!] Encrypted: $($file.Name) -> $($file.Name).bianlian" -ForegroundColor Red
    } catch {
        Write-Host "    [-] Failed to encrypt $($file.Name): $_" -ForegroundColor Red
    }
}

# Step 5: Drop ransom note
$ransomNote = @"
Your network has been compromised by BianLian group.

[RTL TEST - This is a Red Team Lab simulation]

All files encrypted with AES-256.
Contact: bianlian-rtl-test@redteam.lab

DO NOT attempt recovery. Your backups are deleted.
(This is a DETECTION TEST only)
"@
$ransomNote | Out-File "$testDir\Look at this instruction.txt" -Encoding ASCII
Write-Host "    [+] Ransom note dropped" -ForegroundColor Green

$aes.Dispose()

Write-Host "`n[+] Encryption Simulation Complete." -ForegroundColor Green
Write-Host "[!] Files at: $testDir" -ForegroundColor Yellow
Write-Host "[!] Check EDR for: AES encryption, mass file modification, ransom note" -ForegroundColor Magenta
