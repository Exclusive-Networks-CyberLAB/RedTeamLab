<#
.SYNOPSIS
    ALPHV/BlackCat Scheduled Task Creation - DETECTION TRIGGER
.DESCRIPTION
    Creates a scheduled task for persistence/payload deployment.
    TTP: T1053.005
#>
$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting ALPHV Scheduled Task Creation (T1053)" -ForegroundColor Cyan

# Step 1: Create scheduled task
$taskName = "RTL_ALPHV_Update"
$taskAction = "C:\Windows\System32\calc.exe"

Write-Host "`n[*] [T1053.005] Creating scheduled task for persistence..."
Write-Host "    CMD: schtasks /create /sc once /tn `"$taskName`" /tr `"$taskAction`" /st 00:00 /ru SYSTEM /f"
schtasks /create /sc once /tn $taskName /tr $taskAction /st 00:00 /ru SYSTEM /f 2>&1

# Step 2: Verify task was created
Write-Host "`n[*] Verifying scheduled task..."
Write-Host "    CMD: schtasks /query /tn $taskName"
schtasks /query /tn $taskName /fo LIST 2>&1 | ForEach-Object { Write-Host "    $_" }

# Step 3: Run the task
Write-Host "`n[*] Executing scheduled task..."
Write-Host "    CMD: schtasks /run /tn $taskName"
schtasks /run /tn $taskName 2>&1

Start-Sleep -Seconds 2

# Step 4: Create a second task mimicking GPO deployment
$taskName2 = "RTL_ALPHV_GPO_Deploy"
Write-Host "`n[*] [T1053.005] Creating GPO-style deployment task..."
Write-Host "    CMD: schtasks /create /sc onlogon /tn `"$taskName2`" /tr `"cmd /c echo compromised`" /ru SYSTEM /f"
schtasks /create /sc onlogon /tn $taskName2 /tr "cmd /c echo RTL_ALPHV_compromised > C:\temp\alphv_marker.txt" /ru SYSTEM /f 2>&1

Write-Host "`n[+] Scheduled Task Creation Complete." -ForegroundColor Green
Write-Host "[!] Tasks created: $taskName, $taskName2" -ForegroundColor Yellow
Write-Host "[!] Check EDR for: schtasks.exe execution, SYSTEM-level task creation" -ForegroundColor Magenta
Write-Host "[!] Run the REVERT script to clean up tasks" -ForegroundColor Yellow
