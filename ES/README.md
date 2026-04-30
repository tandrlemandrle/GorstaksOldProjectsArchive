# 🔒 ES — Remote Session Terminator

> **Automated RDP/Remote Session Killer** — Continuously monitors and terminates non-console sessions to prevent unauthorized remote access.

---

## 🛡️ Overview

ES.ps1 is a defensive PowerShell script that protects your system by automatically detecting and terminating any non-console (RDP, remote desktop, or network) sessions. It runs as a background job, polling every 5 seconds, and installs itself as a scheduled task so it persists across reboots.

### ✨ Key Features

- 🔍 **Session Monitoring** — Uses `qwinsta` to enumerate all active Windows sessions every 5 seconds
- ⚡ **Auto-Termination** — Kills any session that isn't the local console via `rwinsta`
- 📋 **Logging** — Writes timestamped logs to `%TEMP%\SessionTerminator.log`
- 🔄 **Persistence** — Registers a scheduled task (`RunESAtLogon`) that runs at logon under SYSTEM
- 🛡️ **Self-Installing** — Copies itself to `C:\Windows\Setup\Scripts\Bin` for reliable execution

---

## 📁 Files

| File | Description |
|------|-------------|
| `ES.ps1` | Main script — session monitor, terminator, and scheduled task installer |

---

## 🚀 Usage

```powershell
# Run directly (requires Administrator)
# This will install the scheduled task AND start the background monitoring job
powershell -ExecutionPolicy Bypass -File ES.ps1
```

### What Happens on Execution

1. The script copies itself to `C:\Windows\Setup\Scripts\Bin\ES.ps1`
2. Creates a scheduled task `RunESAtLogon` that triggers at user logon (runs as SYSTEM)
3. Starts a background job that loops every 5 seconds:
   - Lists all sessions via `qwinsta`
   - Parses session names and IDs
   - Terminates any session that is **not** the console session
   - Logs all actions to `%TEMP%\SessionTerminator.log`

### Checking Logs

```powershell
# View the session terminator log
Get-Content "$env:TEMP\SessionTerminator.log" -Tail 20
```

### Removing the Scheduled Task

```powershell
Unregister-ScheduledTask -TaskName "RunESAtLogon" -Confirm:$false
```

---

## ⚙️ Requirements

- **OS:** Windows 10/11 or Windows Server
- **Privileges:** Administrator (required for `qwinsta`, `rwinsta`, and scheduled task creation)
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
