<#
.SYNOPSIS
    Simulates Initial Access by staging a payload.
.DESCRIPTION
    Creates a dummy payload file at C:\temp\output.wav to be used for exfiltration.
    In a real scenario, this might be a dropped implant or collected audio recording.
#>

$ErrorActionPreference = "Stop"
$StagingDir = "C:\temp"
$StagingFile = "$StagingDir\output.wav"

Write-Host "[*] Starting Initial Access Simulation..." -ForegroundColor Green

# 1. Create Staging Directory
if (-not (Test-Path -Path $StagingDir)) {
    Write-Host "[+] Creating staging directory: $StagingDir"
    New-Item -ItemType Directory -Force -Path $StagingDir | Out-Null
} else {
    Write-Host "[*] Staging directory exists: $StagingDir"
}

# 2. Simulate Downloading/Dropping a Payload
# We'll create a binary file with some random data to simulate a .wav recording or payload
Write-Host "[*] Staging payload to: $StagingFile"
try {
    $bytes = New-Object Byte[] 10240 # 10KB dummy file
    (new-object Random).NextBytes($bytes)
    [System.IO.File]::WriteAllBytes($StagingFile, $bytes)
    
    Write-Host "[+] Payload staged successfully." -ForegroundColor Green
    Write-Host "[+] File Size: $((Get-Item $StagingFile).Length) bytes"
} catch {
    Write-Host "[!] Failed to stage payload: $_" -ForegroundColor Red
    exit 1
}

Write-Host "[+] Initial Access Phase Complete." -ForegroundColor Green
