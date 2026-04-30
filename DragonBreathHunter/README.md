# 🐉 DragonBreath Hunter

## 🔍 Overview

A PowerShell threat-hunting script that scans for indicators of compromise (IOCs) associated with the **DragonBreath APT campaign**, including **RONINGLOADER** and **Gh0st RAT** variants. It performs a multi-layered sweep of the local system and applies automated mitigations.

### Scan phases

| Step | What it does |
|------|-------------|
| **1. NSIS Installer Detection** | Scans `%TEMP%`, `%APPDATA%`, `ProgramData`, and `Downloads` for large, recently-modified executables that mimic legitimate software names (chrome, teams, vpn) in suspicious paths. Quarantines matches to `%TEMP%\Quarantine\`. |
| **2. Malicious Process Scan** | Checks running processes against known IOC names (`Snieoatwtregoable.exe`, `taskload.exe`, `letsvpnlatest.exe`, `ollama.sys`) and heuristic patterns (e.g., `tp.png` shellcode). Terminates suspicious processes (excluding `svchost`). |
| **3. Suspicious Module Analysis** | Inspects DLLs loaded by `svchost`, `regsvr32`, and `rundll32` for non-system modules that may indicate Gh0st RAT injection. |
| **4. Registry Persistence Scan** | Examines `HKLM` and `HKCU` Run keys for entries referencing known IOC patterns (`gh0st`, `roning`, `tp.png`, `snieo`) or `%TEMP%` paths. |
| **5. Network C2 Detection** | Scans established TCP connections for traffic on common Gh0st RAT ports (4444, 1337) and flags connections to known C2 patterns. Kills owning processes. |
| **6. Scheduled Task Audit** | Identifies suspicious scheduled tasks with names matching common loader patterns (`update`, `vpn`, `chrome`) that execute PowerShell or `rundll32`. |
| **7. Mitigations** | Enables ASR rules for Office macro blocking, initiates a Windows Defender Quick Scan, and clears temporary files. |
| **8. Event Log Analysis** | Reviews Security event log (Event ID 4688 — process creation) from the last 24 hours for references to NSIS, PowerShell, or Gh0st-related strings. |

All findings are logged to `C:\DragonBreathScan_Log.txt` with timestamps.

## 🚀 Usage

Run as **Administrator** in PowerShell:

```powershell
.\DragonBreathHunter.ps1
```

Example output:

```
2025-11-17 12:00:00 - === Starting Dragon Breath Campaign Scan ===
2025-11-17 12:00:00 - Scanning for suspicious NSIS installers in common drop locations...
2025-11-17 12:00:01 - No suspicious NSIS installers detected.
2025-11-17 12:00:01 - Scanning processes for RONINGLOADER/Gh0st indicators...
...
2025-11-17 12:00:15 - === Scan Complete. Review C:\DragonBreathScan_Log.txt for details. Reboot recommended. ===
```

### Customization

- Update the `$MaliciousProcesses` array with fresh IOC process names
- Replace `known_c2_ip_pattern` in Step 5 with real C2 IP addresses from threat intelligence feeds (e.g., ThreatFox)
- Add additional Gh0st RAT ports to the `$_.RemotePort -in @(4444, 1337)` filter

## 📋 Requirements

- Windows 10/11
- PowerShell 5.1+
- Administrator privileges
- Microsoft Defender Antivirus (for Quick Scan and ASR mitigations)

---

## 📜 License & Disclaimer

This project is intended for authorized defensive, administrative, research, or educational use only.

- Use only on systems, networks, and environments where you have explicit permission.
- Misuse may violate law, contracts, policy, or acceptable-use terms.
- Running security, hardening, monitoring, or response tooling can impact stability and may disrupt legitimate software.
- Validate all changes in a test environment before production use.
- This project is provided "AS IS", without warranties of any kind, including merchantability, fitness for a particular purpose, and non-infringement.
- Authors and contributors are not liable for direct or indirect damages, data loss, downtime, business interruption, legal exposure, or compliance impact.
- You are solely responsible for lawful operation, configuration choices, and compliance obligations in your jurisdiction.

---

<p align="center">
  <sub>Built with care by <strong>Gorstak</strong></sub>
</p>
