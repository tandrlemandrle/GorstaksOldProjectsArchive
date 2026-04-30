# 🛡️ GEDR ASR Rules

## 🔍 Overview

A PowerShell script that applies **Windows Defender Attack Surface Reduction (ASR)** rules to harden your system against common attack vectors. ASR rules are a feature of Microsoft Defender Exploit Guard that reduce the exploitable surface area of your applications and operating system.

The script enables the following ASR rules:

| Rule | Description |
|------|-------------|
| `56a863a9-...` | Block Office child process creation |
| `5beb7efe-...` | Block script execution in Office apps |
| `e6db77e5-...` | Block executable email attachments |
| `d4f940ab-...` | Block Office macros from the Internet |
| `b2b3f03d-...` | Block USB execution |

Each rule is applied via `Add-MpPreference` and the script provides color-coded output indicating success or failure for every rule.

## 🚀 Usage

Run as **Administrator** in PowerShell:

```powershell
.\GEDR_ASR_Rules.ps1
```

The script iterates through each rule GUID, enables it in Windows Defender, and reports the result:

```
Applying GEDR ASR Rules...
Applied: Block Office child process creation (56a863a9-875e-4185-98a7-b882c64b5ce5)
Applied: Block script execution in Office apps (5beb7efe-fd9a-4556-801d-275e5ffc04cc)
...
ASR Rules application complete.
```

## 📋 Requirements

- Windows 10/11 with Microsoft Defender enabled
- PowerShell 5.1+
- Administrator privileges
- Microsoft Defender Antivirus must be the active AV provider

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
