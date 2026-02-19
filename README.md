# 🔴 Red Team Lab

A **Python/Flask** red team simulation platform for executing adversary attack emulations against Windows endpoints. Execute real-world TTPs from known threat actors to validate EDR detections and test your security controls.

---

## 📋 Table of Contents

- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Running the Application](#-running-the-application)
- [Test Scenarios](#-test-scenarios)
  - [Atomic Scenarios](#atomic-scenarios)
  - [Adversary Campaigns](#adversary-campaigns)
  - [Threat Actor Library](#threat-actor-library)
- [Usage Guide](#-usage-guide)
- [Project Structure](#-project-structure)
- [Troubleshooting](#-troubleshooting)

---

## ✨ Features

- **Atomic TTP Execution**: Run individual MITRE ATT&CK techniques with detailed output
- **Adversary Campaigns**: Multi-stage attack chains emulating real-world threat actors (APT28, APT1, Scattered Spider, etc.)
- **Threat Actor Library**: 10+ ransomware/APT groups with 45+ detection-triggering scripts
- **MITRE ATT&CK Mapping**: Every technique linked to official MITRE documentation
- **Revert Capabilities**: Undo system modifications with one-click revert scripts
- **Parameter Inputs**: Dynamic input fields for tester-specified targets (IPs, hostnames, URLs)

---

## 📦 Prerequisites

Before installing, ensure you have the following software installed on your system:

### Python

- **Required Version**: Python 3.9 or later
- **Download**: [https://www.python.org/downloads/](https://www.python.org/downloads/)

**Verify Installation:**
```bash
python3 --version
# Expected output: Python 3.9.x or higher

pip3 --version
# Expected output: pip 21.x or higher
```

### Target Environment

- **Operating System**: Windows 10/11 or Windows Server 2016+
- **PowerShell**: Version 5.1 or later (included with Windows)
- **Permissions**: Administrator privileges required for most TTPs
- **Network**: Connectivity to target hosts for lateral movement scenarios

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Exclusive-Networks-CyberLAB/RedTeamLab.git
cd RedTeamLab
```

### 2. Create a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate    # macOS/Linux
# venv\Scripts\activate     # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

This will install:
- **Flask 3.x** — Web framework for the application

---

## ▶️ Running the Application

### Start the Server

```bash
source venv/bin/activate    # Activate venv if not already active
python app.py
```

**Output:**
```
 * Serving Flask app 'app'
 * Debug mode: on
 * Running on http://127.0.0.1:5001
```

Open your browser and navigate to **[http://localhost:5001](http://localhost:5001)**

---

## 🧪 Test Scenarios

### Atomic Scenarios

Individual TTPs that can be executed independently. Access via the **Scenarios** tab in the sidebar.

| Scenario | Adversary | MITRE ID | Difficulty |
|----------|-----------|----------|------------|
| Host Reconnaissance (PowerShell) | Red Team Ops | T1049, T1057 | Easy |
| Privilege Escalation Check | APT28 | T1134 | Medium |
| Lateral Movement to Domain Controller | APT28 | T1021.002 | Hard |
| C2 Connectivity Check | Scattered Spider | T1071 | Easy |
| Persistence (Registry) | APT1 | T1547.001 | Medium |
| Defense Evasion (Clear Logs) | Red Team Ops | T1070.001 | Medium |
| Credential Dumping (Active) | APT1 | T1003.001 | Hard |
| Initial Access (Payload Staging) | APT45 | T1105 | Easy |
| Exfiltration via DNS | APT45 | T1048.003 | Hard |

### Adversary Campaigns

Multi-stage attack chains accessible via the **Campaigns** tab in the sidebar.

| Campaign | Adversary | Steps | Description |
|----------|-----------|-------|-------------|
| Full Killchain Emulation | Red Team Ops | 7 | Complete end-to-end simulation |
| Operation XAgent | APT28 | 4 | Recon → Priv Esc → Lateral → Cred Dump |
| Operation Comment Crew | APT1 | 3 | Persistence and credential harvesting |
| Cloud & Identity Siege | Scattered Spider | 4 | C2, evasion, and persistence |
| North Korean Info Stealer | APT45 | 3 | Rapid collection and credential theft |
| PlugX Propagation | Mustang Panda | 3 | Lateral movement and C2 beaconing |
| Conti/Ryuk Precursor | Wizard Spider | 4 | Ransomware attack prelude |
| WSL Subsystem Exploitation | Scattered Spider | 5 | Linux-based bypass via WSL |
| Ransomware Precursor Chain | Wizard Spider | 4 | LOLBin staging → Mimikatz → PsExec → BYOVD |
| APT Full Intrusion Chain | APT28 | 5 | BITS download → Procdump → WMI → PtH → BYOVD |

### Threat Actor Library

Detailed TTP libraries for 10+ threat actors, accessible via the **Adversaries** tab in the sidebar:

| Threat Actor | Aliases | Notable TTPs |
|--------------|---------|--------------|
| **LockBit 3.0** | LockBit Black | WMI Shadow Copy Delete, Registry Mod, Inhibit Recovery |
| **Black Basta** | - | Phishing, EDR Disable, Priv Esc Exploits, RDP Lateral |
| **ALPHV/BlackCat** | Noberus | ProxyShell, PowerShell Execution, Scheduled Tasks |
| **AvosLocker** | - | Web Exploits, Shadow Delete, RAT Install, Encryption |
| **BianLian** | - | VM Detection, Packing, USB Spread, Encryption |
| **Cl0p** | TA505, FIN11 | MOVEit Exploit, Registry Persistence, Log Clear |
| **Conti** | Wizard Spider | Fast Encryption, Web Exfiltration |
| **DragonForce** | DragonForce Malaysia | Defender Disable, Self-Delete, Encryption |
| **SafePay** | - | RDP Scan, UAC Bypass, Credential Dump, FTP Exfil |
| **Generic Discovery** | Red Team Ops | Network Config, Groups, User, AD Enumeration |

---

## 📖 Usage Guide

### Configuring Target & C2

1. In the **sidebar**, enter your **Target IP** and **C2 Host**
2. These values persist across page navigation via local storage
3. The C2 status indicator (dot) shows green when configured

### Executing an Atomic Scenario

1. Click **SCENARIOS** in the sidebar
2. Select a scenario card (e.g., "Host Reconnaissance")
3. Review the MITRE technique details and estimated duration
4. Click **INITIALIZE** to open the execution page
5. Click **EXECUTE SCENARIO**
6. Monitor the terminal output for results

### Running an Adversary Campaign

1. Click **CAMPAIGNS** in the sidebar
2. Select a campaign (e.g., "Operation XAgent")
3. Review the attack chain steps
4. Click **INITIATE CAMPAIGN** to open the execution page
5. Click **EXECUTE CAMPAIGN**
6. The campaign will execute each step sequentially with progress indicators
7. Monitor output and observe EDR alerts

### Using the Threat Library

1. Click **ADVERSARIES** in the sidebar (default view)
2. Select a threat actor card (e.g., "LockBit 3.0")
3. Browse available TTPs organized by MITRE tactic
4. Fill in any required input parameters (IP, URL, etc.)
5. Click **EXECUTE** on any TTP to run it
6. For TTPs with system modifications, use **REVERT** to undo changes

---

## 📁 Project Structure

```
RTL/
├── app.py                      # Flask application (routes & API)
├── data.py                     # Scenarios, campaigns, threat actor data
├── requirements.txt            # Python dependencies (flask)
├── templates/                  # Jinja2 HTML templates
│   ├── base.html              # Base layout with sidebar
│   ├── index.html             # Unified Threat Library dashboard
│   ├── scenario.html          # Scenario execution page
│   └── campaign.html          # Campaign execution page
├── static/                     # Static assets
│   ├── css/
│   │   └── style.css          # Application styles
│   └── js/
│       └── app.js             # Client-side JavaScript
└── scenarios/                  # PowerShell execution scripts
    ├── *.ps1                  # Root-level atomic scripts
    ├── lockbit/               # LockBit threat actor scripts
    ├── blackbasta/            # Black Basta scripts
    ├── alphv/                 # ALPHV/BlackCat scripts
    ├── clop/                  # Cl0p scripts
    ├── dragonforce/           # DragonForce scripts
    ├── safepay/               # SafePay scripts
    ├── bianlian/              # BianLian scripts
    ├── avoslocker/            # AvosLocker scripts
    ├── conti/                 # Conti scripts
    ├── credential_access/     # Credential dumping scripts
    ├── lateral_movement/      # Lateral movement scripts
    ├── lolbin/                # LOLBin download scripts
    ├── byovd/                 # BYOVD EDR bypass scripts
    ├── wsl/                   # WSL-based attack scripts
    └── library/               # Generic discovery modules
```

---

## 🔧 Troubleshooting

### Common Issues

#### Port 5001 Already in Use

```bash
# Find the process using port 5001
lsof -i :5001

# Or change the port in app.py (last line)
app.run(debug=True, host="0.0.0.0", port=5002)
```

#### Virtual Environment Issues

```bash
# Recreate the virtual environment
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### PowerShell Scripts Not Executing

1. Ensure you're running on a **Windows** target machine
2. Verify **PowerShell ExecutionPolicy** allows script execution:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
   ```
3. Run PowerShell as **Administrator** for privilege-required TTPs

#### Script Execution Errors

- **Access Denied**: Ensure Administrator privileges
- **Network Errors**: Verify target IP/hostname is reachable
- **LSASS Dump Fails**: Requires elevated privileges and may be blocked by EDR
- **Timeout**: Scripts have a 120-second timeout — adjust in `app.py` if needed

---

## ⚠️ Disclaimer

This tool is designed for **authorized security testing only**. Ensure you have explicit written permission before executing any scenarios against systems you do not own. Misuse of this tool may violate computer fraud and abuse laws.

---

## 📝 License

[MIT License](LICENSE) - See LICENSE file for details.
