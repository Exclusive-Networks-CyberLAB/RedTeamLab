<#
.SYNOPSIS
    Black Basta Phishing Simulation - DETECTION TRIGGER
.DESCRIPTION
    Simulates phishing delivery by creating malicious artifacts on disk.
    Creates HTA file and invokes mshta.exe for detection.
    TTP: T1566
#>
$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting Black Basta Phishing Simulation (T1566)" -ForegroundColor Cyan
Write-Host "[*] Simulating spearphishing with malicious attachment delivery" -ForegroundColor Yellow

# Create staging directory
$stagingDir = "C:\temp\phishing_staging"
if (-not (Test-Path $stagingDir)) { New-Item -Path $stagingDir -ItemType Directory -Force | Out-Null }

# Step 1: Create a malicious ZIP-like artifact (simulated Qakbot loader)
Write-Host "`n[*] [T1566.001] Creating malicious attachment artifact..."
$fakePayload = @"
' Simulated Qakbot VBScript Loader
' This file is harmless - detection trigger only
Set objShell = CreateObject("WScript.Shell")
objShell.Run "cmd /c whoami > %TEMP%\qbot_output.txt", 0, True
"@
$vbsPath = "$stagingDir\invoice_2024.vbs"
$fakePayload | Out-File $vbsPath -Encoding ASCII
Write-Host "[+] Created: $vbsPath" -ForegroundColor Green

# Step 2: Create an HTA file (T1218.005 - mshta proxy execution)
Write-Host "`n[*] [T1218.005] Creating HTA payload for mshta execution..."
$htaContent = @"
<html>
<head>
<script language="VBScript">
Sub Window_OnLoad
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run "cmd /c echo RTL_PhishingTest > %TEMP%\phish_marker.txt", 0, True
    window.close
End Sub
</script>
</head>
<body>
</body>
</html>
"@
$htaPath = "$stagingDir\update_notice.hta"
$htaContent | Out-File $htaPath -Encoding ASCII
Write-Host "[+] Created: $htaPath" -ForegroundColor Green

# Step 3: Execute HTA via mshta.exe (will trigger EDR)
Write-Host "`n[*] Executing HTA via mshta.exe..."
Write-Host "    CMD: mshta.exe $htaPath"
try {
    Start-Process -FilePath "mshta.exe" -ArgumentList $htaPath -Wait -ErrorAction Stop
    Write-Host "[+] mshta.exe execution completed" -ForegroundColor Green
} catch {
    Write-Host "[-] mshta execution failed: $_" -ForegroundColor Red
}

# Step 4: Attempt macro-like behavior via WScript
Write-Host "`n[*] [T1059.005] Attempting VBScript execution..."
Write-Host "    CMD: cscript //nologo $vbsPath"
try {
    Start-Process -FilePath "cscript" -ArgumentList "//nologo `"$vbsPath`"" -Wait -ErrorAction Stop
    Write-Host "[+] VBScript execution completed" -ForegroundColor Green
} catch {
    Write-Host "[-] VBScript execution failed: $_" -ForegroundColor Red
}

Write-Host "`n[+] Phishing simulation complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: mshta.exe execution, VBScript execution, suspicious file creation" -ForegroundColor Magenta
