# 🖱️ Cursor Takeover Detection

## 🔍 Overview

A PowerShell script that samples cursor movement at regular intervals and uses **velocity variance analysis** to detect automated or remote cursor manipulation — a common indicator of RAT (Remote Access Trojan) activity or unauthorized remote control sessions.

### How it works

1. **Samples cursor position** every 3 seconds using the Win32 `GetCursorPos` API
2. **Maintains a rolling window** of the last 20 cursor samples
3. **Calculates velocity deltas** between consecutive samples (distance / time)
4. **Computes variance** of the velocity distribution
5. **Flags suspicious movement** when variance is very low (`< 0.005`) but the cursor is actively moving (`mean > 0.01`) — this pattern indicates unnaturally smooth, machine-driven movement rather than natural human jitter

Alerts are written to `C:\ProgramData\Antivirus\Logs\user_protection.log`.

### Persistence

The script supports `-Install` and `-Uninstall` switches for persistence via a scheduled task:

- Copies itself to `C:\ProgramData\Antivirus\CursorTakeoverDetection.ps1`
- Registers a scheduled task (`CursorTakeoverDetection`) that runs at logon with highest privileges
- Configured to restart up to 3 times on failure

## 🚀 Usage

### Run directly

```powershell
.\CursorTakeoverDetection.ps1
```

Runs in a continuous loop, sampling every 3 seconds.

### Install persistence

```powershell
.\CursorTakeoverDetection.ps1 -Install
```

Copies the script to `C:\ProgramData\Antivirus\` and creates a logon-triggered scheduled task.

### Uninstall

```powershell
.\CursorTakeoverDetection.ps1 -Uninstall
```

Removes the scheduled task and deletes the installed script.

### Dot-source for integration

```powershell
. .\CursorTakeoverDetection.ps1
Invoke-CursorTakeoverDetection
```

When dot-sourced, the script exposes `Invoke-CursorTakeoverDetection` without entering the main loop.

## 📋 Requirements

- Windows 10/11
- PowerShell 5.1+
- Administrator privileges (required for install/uninstall)

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
