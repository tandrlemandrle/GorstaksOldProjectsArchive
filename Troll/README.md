# 🎭 Troll

> **Network Bridge Prevention Utility** - Automated network bridge detection and removal tool.

---

## 📋 Overview

Troll is a network security utility that continuously monitors for and removes unauthorized network bridges. It prevents network bridging attacks by automatically detecting and dismantling bridge configurations.

---

## 🎯 What It Does

- 🔍 **Bridge Detection** - Monitors for network bridge configurations
- 🚫 **Auto-Removal** - Automatically removes detected bridges
- 🔄 **Continuous Monitoring** - Runs persistently in background
- ⚡ **Lightweight** - Minimal system resource usage
- 🛡️ **Prevention** - Blocks bridge-based attack vectors

---

## 📁 Project Structure

| File | Description |
|------|-------------|
| `Troll.ps1` | PowerShell monitoring and removal script |

---

## 🚀 Usage

### Automatic Installation
```powershell
# Run as Administrator
.\Troll.ps1
```

The script will:
1. Copy itself to `C:\Windows\Setup\Scripts\Bin\`
2. Create a scheduled task to run at logon
3. Start continuous monitoring

### Manual Execution
```powershell
# Check and remove bridges once
# (Script functions can be called manually)
```

---

## ⚙️ How It Works

### Detection Process
```powershell
netsh bridge show adapter
# Parses output for "IsBridged: Yes"
```

### Removal Process
```powershell
netsh bridge uninstall
# Removes entire bridge configuration
```

### Persistence
- Scheduled task runs under SYSTEM account
- Executes at every user logon
- Runs in continuous loop (5-second intervals)

---

## 🛡️ Security Use Cases

### Bridge-Based Attacks Prevention
- **Network Sniffing** - Prevents bridged adapter packet capture
- **MITM Attacks** - Stops bridge-based man-in-the-middle
- **Unauthorized Access** - Blocks network extension attempts
- **Traffic Redirection** - Prevents traffic interception

---

## ⚠️ Important Notes

### ⚠️ Legitimate Use
- Some virtualization software uses bridging
- Corporate networks may require bridges
- VPN software may create temporary bridges

### ✅ Whitelist Approach
Edit script to exclude specific adapters if needed:
```powershell
# Add adapter name check before removal
if ($adapter -notmatch "Virtual|VPN|ValidBridge") {
    # Remove bridge
}
```

---

## 📝 Requirements

- Windows 10/11
- Administrator privileges
- PowerShell 5.1+

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