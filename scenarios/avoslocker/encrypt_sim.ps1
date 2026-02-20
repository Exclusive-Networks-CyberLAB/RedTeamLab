<#
.SYNOPSIS
    AvosLocker Encryption Simulation - DETECTION TRIGGER
.DESCRIPTION
    Creates test files and renames them with ransom extension.
    TTP: T1486
#>
$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting AvosLocker Encryption Simulation (T1486)" -ForegroundColor Cyan
Write-Host "[!] This creates test files and renames them - NO real encryption of user data" -ForegroundColor Yellow

# Step 1: Create test directory with sample files
$testDir = "C:\temp\avos_encrypt_test"
if (-not (Test-Path $testDir)) { New-Item -Path $testDir -ItemType Directory -Force | Out-Null }

Write-Host "`n[*] Creating test files for encryption simulation..."
$extensions = @(".docx", ".xlsx", ".pdf", ".txt", ".pptx")
foreach ($ext in $extensions) {
    $filename = "test_document$ext"
    $filepath = "$testDir\$filename"
    "RTL Test Data - This is a test file for ransomware simulation" | Out-File $filepath -Encoding ASCII
    Write-Host "    [+] Created: $filepath" -ForegroundColor Green
}

# Step 2: Simulate encryption by renaming files
Write-Host "`n[*] [T1486] Simulating file encryption (rename to .avos2 extension)..."
$files = Get-ChildItem $testDir -File
foreach ($file in $files) {
    $newName = $file.FullName + ".avos2"
    Rename-Item -Path $file.FullName -NewName $newName -Force
    Write-Host "    [!] Encrypted: $($file.Name) -> $($file.Name).avos2" -ForegroundColor Red
}

# Step 3: Drop ransom note
Write-Host "`n[*] Creating ransom note..."
$ransomNote = @"
=== YOUR FILES HAVE BEEN ENCRYPTED ===

[RTL TEST - This is a Red Team Lab simulation]

All your files have been encrypted with AES-256.
To decrypt, contact: rtl-test@redteam.lab

This is a DETECTION TEST. No real encryption occurred.
"@
$ransomNote | Out-File "$testDir\GET_YOUR_FILES_BACK.txt" -Encoding ASCII
Write-Host "    [+] Ransom note dropped: $testDir\GET_YOUR_FILES_BACK.txt" -ForegroundColor Green

# Step 4: Notify user of detection expectation
Write-Host "`n[+] Encryption Simulation Complete." -ForegroundColor Green
Write-Host "[!] Files at: $testDir (can be safely deleted)" -ForegroundColor Yellow
Write-Host "[!] Check EDR for: Mass file rename, ransom note creation, suspicious file extension changes" -ForegroundColor Magenta
