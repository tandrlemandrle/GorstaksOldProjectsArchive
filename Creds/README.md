# 🔑 Credential Protection

## 🔍 Overview

A PowerShell script that hardens local credential storage and access on Windows. It applies four defensive measures to protect against credential theft and unauthorized access:

### Actions performed

1. **Enable LSASS PPL** — Configures the Local Security Authority Subsystem Service (LSASS) to run as a Protected Process Light by setting `RunAsPPL = 1` under `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`. This prevents unauthorized processes from reading LSASS memory (a common technique used by tools like Mimikatz).

2. **Clear cached credentials** — Uses `cmdkey.exe` to enumerate and delete all stored credentials from Windows Credential Manager.

3. **Disable credential caching** — Sets `CachedLogonsCount` to `0` under `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, preventing Windows from caching domain logon credentials locally.

4. **Enable credential auditing** — Configures the `Credential Validation` audit subcategory to log both success and failure events via `auditpol`, providing visibility into credential access attempts in the Security event log.

## 🚀 Usage

Run as **Administrator** in PowerShell:

```powershell
.\Creds.ps1
```

Example output:

```
Starting credential protection script...
LSASS configured to run as Protected Process Light (PPL). Reboot required.
Cleared cached credentials from Credential Manager using cmdkey.
Disabled cached logon credentials. Set CachedLogonsCount to 0.
Enabled auditing for credential validation events.
Script completed. Reboot the system to apply LSASS PPL changes.
```

A **reboot is required** for the LSASS PPL change to take effect.

## 📋 Requirements

- Windows 10/11
- PowerShell 5.1+
- Administrator privileges
- Reboot after running (for LSASS PPL)

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
