# 🍪 CookieMonitor

## 🔍 Overview

A PowerShell script that monitors the Chrome cookie database for unauthorized changes and responds by **rotating the local user password** and **restoring cookies from a known-good backup**. It installs multiple scheduled tasks for continuous protection.

### How it works

1. **Monitors** the Chrome `Cookies` file by computing its SHA-256 hash every 5 minutes
2. **Detects changes** by comparing the current hash against the last known hash
3. **Responds** to unauthorized cookie modifications by:
   - Generating a new random 16-character password and applying it to the local user account
   - Restoring the cookie file from the last known-good backup
4. **Backs up** cookies at system startup (after killing Chrome)
5. **Resets** the local password to blank on shutdown (Event ID 1074) so the user can log back in

### Installed scheduled tasks

| Task Name | Trigger | Purpose |
|-----------|---------|---------|
| `MonitorCookiesLogon` | At logon (SYSTEM) | Runs the full install flow |
| `BackupCookiesOnStartup` | At startup (SYSTEM) | Backs up Chrome cookies |
| `MonitorCookies` | Every 5 minutes | Checks cookie hash, triggers countermeasures |
| `ResetPasswordOnShutdown` | System Event ID 1074 | Resets password to blank before shutdown |

### File locations

- Script install path: `C:\Windows\Setup\Scripts\Bin\CookieMonitor.ps1`
- Cookie backup: `%ProgramData%\CookieBackup\Cookies.bak`
- Hash file: `%ProgramData%\CookieBackup\CookieHash.txt`
- Password log: `%ProgramData%\CookieBackup\NewPassword.log`
- Logs: `%ProgramData%\CookieBackup\CookieMonitor.log` and `ScriptErrors.log`

## 🚀 Usage

### Install (creates all scheduled tasks)

Run as **Administrator** in PowerShell:

```powershell
.\CookieMonitor.ps1
```

### Manual operations

```powershell
# Monitor cookies (check hash and respond)
.\CookieMonitor.ps1 -Monitor

# Backup cookies
.\CookieMonitor.ps1 -Backup

# Reset password to blank
.\CookieMonitor.ps1 -ResetPassword
```

### Uninstall

```powershell
$tasks = @("MonitorCookiesLogon", "BackupCookiesOnStartup", "MonitorCookies", "ResetPasswordOnShutdown")
foreach ($task in $tasks) {
    Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
}
```

## 📋 Requirements

- Windows 10/11
- PowerShell 5.1+
- Administrator privileges
- Google Chrome installed (default profile path)

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
