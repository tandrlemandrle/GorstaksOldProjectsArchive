# 🧹 RamCleaner

> **Windows Memory Optimization Tool** - Automated RAM cleanup using EmptyStandbyList for improved system performance.

---

## 📋 Overview

RamCleaner is a lightweight Windows utility that continuously frees up RAM by clearing working sets and standby lists. It uses Microsoft's Sysinternals EmptyStandbyList tool to optimize memory usage without affecting system stability.

---

## 🎯 What It Does

- 🧠 **Clears Working Sets** - Frees RAM used by inactive processes
- 💾 **Clears Standby List** - Releases cached data back to available memory
- 🔄 **Continuous Operation** - Runs in a loop every 10 seconds
- ⚡ **Lightweight** - Minimal CPU and memory overhead
- 🛡️ **Safe** - Uses Microsoft-approved memory management techniques

---

## 📁 Project Structure

| File | Description |
|------|-------------|
| `Setup.cmd` | Installation script |
| `Bin/` | Executable components |
| `Bin\EmptyStandbyList.exe` | Microsoft Sysinternals memory cleanup tool |
| `Bin\RamCleaner.bat` | Continuous cleanup loop script |
| `Bin\RamCleaner.cmd` | Alternative launcher |
| `Bin\RamCleaner.xml` | Task Scheduler XML definition |

---

## 🚀 Installation

```cmd
:: Run as Administrator
Setup.cmd
```

This installs RamCleaner as a scheduled task that runs automatically at system startup.

---

## ⚙️ How It Works

### Memory Cleanup Process
```batch
:Cleaner
emptystandbylist.exe workingsets    :: Clear process working sets
emptystandbylist.exe standbylist     :: Clear file system cache
timeout /t 10 /nobreak >nul          :: Wait 10 seconds
goto:Cleaner                         :: Repeat forever
```

### What Gets Cleared
- **Working Sets**: Physical RAM assigned to processes (non-active pages freed)
- **Standby List**: Cached file data not currently in use

### What Is Preserved
- Active application memory
- Critical system processes
- Modified pages not yet written to disk

---

## 📊 Memory Management Details

| List Type | Description | Impact |
|-----------|-------------|--------|
| **Working Sets** | Active process memory pages | Minor performance impact for inactive apps |
| **Standby List** | Cached file data from disk | May increase disk reads for recently used files |

---

## 🎮 Use Cases

### Gaming
- Free up RAM before launching demanding games
- Reduce stuttering caused by memory pressure
- Keep system responsive during gameplay

### Development
- Clear memory after intensive build processes
- Reset environment between testing cycles
- Manage memory leaks in development tools

### General Use
- Improve responsiveness on systems with limited RAM
- Manage browsers that consume excessive memory
- Maintain performance during long uptime periods

---

## ⚠️ Important Notes

### ⚠️ Performance Impact
- **Disk Activity**: Clearing standby list may increase disk reads
- **CPU Usage**: Minimal - EmptyStandbyList is efficient
- **Application Restart**: Some applications may take longer to resume if their memory was cleared

### ⚠️ When NOT to Use
- Systems with 32 GB+ RAM (minimal benefit)
- During disk-intensive operations
- On systems with slow HDD (increased disk thrashing)

### ✅ Best Practices
- Use on systems with 8-16 GB RAM
- Ideal for gaming PCs
- Good for systems with SSD (faster cache rebuild)

---

## 🔧 Manual Usage

```cmd
:: Single cleanup
EmptyStandbyList.exe workingsets
EmptyStandbyList.exe standbylist

:: Available options
EmptyStandbyList.exe workingsets    :: Process working sets
EmptyStandbyList.exe standbylist     :: Standby cache
EmptyStandbyList.exe modifiedpagelist :: Modified pages
EmptyStandbyList.exe priority0standbylist :: Priority 0 standby
```

---

## 📝 Requirements

- Windows 10/11 or Windows Server 2016+
- Administrator privileges
- 4+ GB RAM (benefits decrease with more RAM)

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