<#
.SYNOPSIS
    BianLian File Encryption - REVERT
.DESCRIPTION
    Decrypts test files and cleans up encryption simulation.
#>
Write-Host "[*] REVERTING: Cleaning up encryption simulation" -ForegroundColor Cyan

try {
    $testDir = "$env:TEMP\RTL_Encrypt_Test"
    
    if (Test-Path $testDir) {
        # Decrypt files
        Get-ChildItem $testDir -Filter "*.bianlian_encrypted" | ForEach-Object {
            $encryptedPath = $_.FullName
            $originalPath = $encryptedPath -replace '\.bianlian_encrypted$', ''
            
            $encrypted = [System.IO.File]::ReadAllBytes($encryptedPath)
            $decrypted = $encrypted | ForEach-Object { $_ -bxor 0x42 }
            
            [System.IO.File]::WriteAllBytes($originalPath, $decrypted)
            Remove-Item $encryptedPath -Force
            
            Write-Host "[+] Decrypted: $($_.Name)" -ForegroundColor Green
        }
        
        # Remove ransom note
        Remove-Item "$testDir\README_DECRYPT.txt" -Force -ErrorAction SilentlyContinue
        
        # Remove test directory
        Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue
        
        Write-Host "[+] SUCCESS: Encryption simulation cleaned up" -ForegroundColor Green
    } else {
        Write-Host "[*] Test directory not found - already cleaned" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}
