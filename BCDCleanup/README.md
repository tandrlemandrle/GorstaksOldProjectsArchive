# 🧹 BCDCleanup — Boot Configuration Data Scanner & Cleaner

> **Automated BCD Threat Detection** — Scans the Windows Boot Configuration Data store for suspicious entries, backs up the BCD, and automatically removes non-Windows boot entries that may indicate bootkits or unauthorized OS installations.

---

## 🔍 Overview

BCDCleanup.ps1 is a fully automated script that enumerates all BCD (Boot Configuration Data) entries, identifies suspicious ones using heuristic analysis, creates a backup, and removes threats — all without user interaction. It's designed to be run from batch files or automated pipelines.

### ✨ Key Features

- 🔎 **Heuristic Analysis** — Flags entries with:
  - Non-Windows descriptions (missing "Windows" in the description)
  - VHD-based boot devices (`vhd=` in device path)
  - Non-standard boot paths (anything other than `winload.exe`)
- 💾 **Automatic BCD Backup** — Creates a timestamped backup (`C:\BCD_Backup_YYYYMMDD_HHmmss.bcd`) before any changes
- 🗑️ **Auto-Removal** — Deletes flagged entries using `bcdedit /delete /f`
- 🛡️ **Critical Entry Protection** — Never touches `{bootmgr}`, `{current}`, or `{default}`
- 📋 **Detailed Logging** — Writes all actions to `C:\BCD_Cleanup_Log_YYYYMMDD_HHmmss.txt`
- ✅ **Post-Cleanup Verification** — Re-enumerates BCD after cleanup to confirm changes
- 🔢 **Exit Codes** — Returns 0 on success, 1 on error (batch-friendly)

---

## 📁 Files

| File | Description |
|------|-------------|
| `BCDCleanup.ps1` | Main script — BCD scanner, backup creator, threat remover, and verifier |

---

## 🚀 Usage

```powershell
# Run directly (requires Administrator)
powershell -ExecutionPolicy Bypass -File BCDCleanup.ps1
```

### What Happens on Execution

1. **Backup** — Exports current BCD to `C:\BCD_Backup_*.bcd`
2. **Enumerate** — Lists all BCD entries via `bcdedit /enum all`
3. **Analyze** — Checks each entry against suspicious patterns
4. **Remove** — Deletes flagged entries (skipping critical identifiers)
5. **Verify** — Re-enumerates BCD and logs final state

### Restoring from Backup

If something goes wrong, restore the BCD from the backup:

```cmd
bcdedit /import "C:\BCD_Backup_YYYYMMDD_HHmmss.bcd"
```

### Detection Criteria

| Check | Suspicious When |
|-------|----------------|
| Description | Does not contain "Windows" |
| Device | Contains `vhd=` (VHD boot) |
| Path | Does not contain `winload.exe` |

---

## ⚙️ Requirements

- **OS:** Windows 10/11 or Windows Server
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
