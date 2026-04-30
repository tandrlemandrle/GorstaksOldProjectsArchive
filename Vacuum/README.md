# 🧹 Vacuum

> **Advanced Windows Memory Cleaner** - Continuous RAM optimization with scheduled task integration.

---

## 📋 Overview

Vacuum is a system memory optimization tool similar to RamCleaner, designed to continuously free up RAM and improve system responsiveness. It provides automated memory management through Windows Task Scheduler integration.

---

## 🎯 What It Does

- 🧠 **Memory Optimization** - Clears working sets and standby lists
- 🔄 **Automated Operation** - Runs continuously via scheduled task
- ⏰ **Scheduled Integration** - Uses Windows Task Scheduler
- ⚡ **Lightweight** - Minimal system impact
- 🛡️ **System Safe** - Uses Windows-approved memory APIs

---

## 📁 Project Structure

| File | Description |
|------|-------------|
| `Setup.cmd` | Installation and task scheduler setup |
| `Bin/` | Executable components |

---

## 🚀 Installation

```cmd
:: Run as Administrator
Setup.cmd
```

Creates a scheduled task for automatic startup.

---

## ⚙️ Technical Details

### Memory Management
- Targets working sets of inactive processes
- Clears standby file cache
- Optimizes available memory for active applications

### Scheduled Task
- Runs at user logon
- Executes with highest privileges
- Continues running in background

---

## 📝 Requirements

- Windows 10/11
- Administrator privileges for installation
- 4+ GB RAM recommended

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