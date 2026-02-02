<#
.SYNOPSIS
    LockBit BCDEdit Recovery - REVERT
.DESCRIPTION
    Re-enables Windows boot recovery options.
    Use after testing to restore recovery functionality.
#>
Write-Host "[*] REVERTING: Re-enabling Windows Recovery" -ForegroundColor Cyan

try {
    bcdedit /set "{default}" recoveryenabled Yes
    bcdedit /set "{default}" bootstatuspolicy displayallfailures
    
    Write-Host "[+] SUCCESS: Boot recovery options RE-ENABLED" -ForegroundColor Green
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}
