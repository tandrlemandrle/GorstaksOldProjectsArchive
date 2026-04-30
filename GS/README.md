# 🛡️ GS (GSecurity Core)

> **Lightweight Security Policy Installer** - Minimal security baseline deployment tool.

---

## 📋 Overview

GS provides a minimal installation path for core GSecurity components. It deploys essential security policies and LGPO configuration for rapid system hardening.

---

## 🎯 What It Does

- 📜 **Policy Installation** - Deploys GSecurity.inf security template
- 🔧 **LGPO Integration** - Uses Microsoft LGPO for policy application
- ⚡ **Lightweight** - Minimal footprint deployment
- 🚀 **Quick Setup** - One-click installation

---

## 📁 Project Structure

| File | Description |
|------|-------------|
| `GSecurity.inf` | Security template (15.4 KB) |
| `LGPO.exe` | Microsoft Local Group Policy Object utility |
| `Setup.bat` | Installation batch script |

---

## 🚀 Installation

```cmd
:: Run as Administrator
Setup.bat
```

---

## 📋 Security Template Contents

- Security policy settings
- Registry hardening entries
- Service configuration
- Audit policy settings

---

## 📝 Requirements

- Windows 10/11 Pro/Enterprise
- Administrator privileges

---

## 📜 License & Disclaimer
---

## Comprehensive legal disclaimer

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