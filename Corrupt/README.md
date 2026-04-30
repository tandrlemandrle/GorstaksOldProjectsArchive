# 🗑️ Corrupt — Telemetry File Overwriter

## 🔍 Overview

A PowerShell script that continuously overwrites telemetry and analytics files from Windows, browsers, GPU drivers, gaming platforms, and other software with random junk data on an **hourly loop**. It installs itself as a scheduled task that runs at logon under the SYSTEM account.

### Targeted telemetry sources

| Category | Examples |
|----------|----------|
| **Windows** | Diagtrack ETL logs, event transcripts, shutdown logger, telemetry EVTX |
| **Browsers** | Chrome Web Data, Chrome local storage logs, Edge preferences, Firefox telemetry SQLite |
| **GPU Drivers** | NVIDIA NvTelemetry, Intel GFX telemetry, AMD diagnostics |
| **Gaming** | Steam perf logs & cookies, Epic Games analytics, Discord analytics & local storage |
| **Productivity** | Adobe ARM telemetry, Autodesk analytics, Slack/Dropbox/Zoom logs |
| **Peripherals** | Logitech LogiOptions, Razer Synapse, Corsair iCUE telemetry |
| **Security Software** | Kaspersky, McAfee, Norton, Bitdefender telemetry logs |

### How it works

1. **Self-installs** — Copies itself to `C:\Windows\Setup\Scripts\Bin\` and registers a scheduled task (`RunCorruptAtLogon`) that runs at user logon under SYSTEM with highest privileges
2. **Overwrites files** — For each target file that exists, reads its size, generates random bytes of the same length, and writes them back over the original content
3. **Loops hourly** — After processing all files, sleeps until the next hour and repeats
4. **Duplicate protection** — Checks for an already-running instance and exits if one is found

## 🚀 Usage

Run as **Administrator** in PowerShell:

```powershell
.\Corrupt.ps1
```

The script will:
- Install the scheduled task for persistence
- Start a background job that overwrites telemetry files every hour

To remove the scheduled task:

```powershell
Unregister-ScheduledTask -TaskName "RunCorruptAtLogon" -Confirm:$false
```

## 📋 Requirements

- Windows 10/11
- PowerShell 5.1+
- Administrator privileges

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
