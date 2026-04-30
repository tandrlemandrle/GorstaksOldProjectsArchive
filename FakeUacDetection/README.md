# 🛡️ FakeUacDetection — Fake UAC/System Dialog Detector

> **Window-Title Heuristic Scanner** — Detects processes displaying fake UAC prompts or system dialogs that may indicate social engineering attacks.

---

## 🔍 Overview

FakeUacDetection.ps1 is a real-time monitoring script that scans running processes for window titles resembling fake UAC (User Account Control) or Windows security dialogs. Attackers often create convincing fake prompts to trick users into entering credentials or granting elevated permissions. This script catches those attempts using pattern-matching heuristics.

### ✨ Key Features

- 🔎 **Heuristic Detection** — Scans window titles for suspicious patterns like "user account control", "windows security", "microsoft defender", "critical update", etc.
- ✅ **Trusted Process Whitelist** — Skips legitimate system processes (`consent`, `explorer`, `dwm`, `securityhealthservice`, `msmpeng`, etc.)
- 🔄 **Continuous Monitoring** — Runs in a loop every 10 seconds
- 📋 **Threat Logging** — Logs detections with PID and window title to `C:\ProgramData\Antivirus\Logs\user_protection.log`
- 💾 **Install/Uninstall Persistence** — Copies itself to `C:\ProgramData\Antivirus` and registers a scheduled task at logon
- 🔧 **Module-Compatible** — Can be dot-sourced into larger security frameworks via `$ModuleConfig`

---

## 📁 Files

| File | Description |
|------|-------------|
| `FakeUacDetection.ps1` | Main script — detection engine, persistence installer, and monitoring loop |

---

## 🚀 Usage

```powershell
# Run directly (continuous monitoring)
powershell -ExecutionPolicy Bypass -File FakeUacDetection.ps1

# Install as persistent scheduled task (runs at logon, hidden window)
powershell -ExecutionPolicy Bypass -File FakeUacDetection.ps1 -Install

# Uninstall — removes scheduled task and installed script
powershell -ExecutionPolicy Bypass -File FakeUacDetection.ps1 -Uninstall
```

### Detection Patterns

The script flags any non-trusted process whose window title contains:

| Pattern | Typical Attack |
|---------|---------------|
| `user account control` | Fake UAC elevation prompt |
| `do you want to allow` | Fake permission dialog |
| `windows security` | Credential phishing |
| `microsoft defender` | Fake antivirus alert |
| `critical update` | Fake update prompt |
| `windows update` | Fake update dialog |

### Checking Logs

```powershell
# View detection log
Get-Content "C:\ProgramData\Antivirus\Logs\user_protection.log" -Tail 20
```

---

## ⚠️ Notes

- **High false-positive rate** is expected — this is heuristic-based detection. Legitimate applications with matching window titles may trigger alerts.
- Requires Administrator privileges for installation and scheduled task management.

---

## ⚙️ Requirements

- **OS:** Windows 10/11
- **Privileges:** Administrator
- **PowerShell:** 5.1+

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
