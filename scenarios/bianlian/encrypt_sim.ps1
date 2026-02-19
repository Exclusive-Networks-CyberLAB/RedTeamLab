<#
.SYNOPSIS
    BianLian File Encryption Simulation - DETECTION TRIGGER
.DESCRIPTION
    Creates and encrypts test files to trigger ransomware detection.
    Uses safe test directory - no real files affected.
    TTP: T1486
#>
Write-Host "[*] Starting BianLian Encryption Simulation (T1486)" -ForegroundColor Cyan
Write-Host "[*] This will trigger EDR detection for ransomware behavior" -ForegroundColor Yellow

try {
    # Create test directory
    $testDir = "$env:TEMP\RTL_Encrypt_Test"
    New-Item -Path $testDir -ItemType Directory -Force | Out-Null
    
    Write-Host "[*] Created test directory: $testDir"
    
    # Create test files
    1..10 | ForEach-Object {
        $content = "RTL Test File $_. This is test data for ransomware detection validation."
        $filePath = "$testDir\testfile$_.txt"
        $content | Out-File $filePath -Force
    }
    
    Write-Host "[*] Created 10 test files"
    
    # ACTUAL DETECTION TRIGGER - Rapid file modification pattern
    Write-Host "[*] Simulating encryption behavior..."
    
    Get-ChildItem $testDir -Filter "*.txt" | ForEach-Object {
        $originalPath = $_.FullName
        $encryptedPath = "$originalPath.bianlian_encrypted"
        
        # Read, modify (simulate encryption), and write with new extension
        $content = Get-Content $originalPath -Raw
        
        # XOR-like "encryption" (actually reversible, just for detection trigger)
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
        $encrypted = $bytes | ForEach-Object { $_ -bxor 0x42 }
        
        # Write encrypted content with ransomware extension
        [System.IO.File]::WriteAllBytes($encryptedPath, $encrypted)
        
        # Delete original
        Remove-Item $originalPath -Force
        
        Write-Host "[+] Encrypted: $($_.Name) -> $($_.Name).bianlian_encrypted" -ForegroundColor Green
    }
    
    # Create ransom note
    $ransomNote = @"
==================================================
BIANLIAN RANSOMWARE - RED TEAM LAB TEST
==================================================
This is a SIMULATED ransom note for EDR detection testing.
Your test files have been encrypted.

Run the REVERT script to restore files.

This is NOT real ransomware.
==================================================
"@
    
    $ransomNote | Out-File "$testDir\README_DECRYPT.txt" -Force
    Write-Host "[+] Created ransom note" -ForegroundColor Green
    
    Write-Host "[+] SUCCESS: Encryption simulation completed" -ForegroundColor Green
    Write-Host "[!] CrowdStrike should detect: 'RansomwareBehavior' or 'MassFileEncryption'" -ForegroundColor Magenta
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}

Write-Host "`n[*] Detection should appear in CrowdStrike within 1-2 minutes" -ForegroundColor Cyan
Write-Host "[!] Test files are in: $testDir - run REVERT to clean up" -ForegroundColor Yellow
