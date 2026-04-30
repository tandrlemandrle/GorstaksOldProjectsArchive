# 🚀 GPrep

> **Gorstak Windows System Preparation Tool** - Complete post-installation system optimizer and software installer.

---

## 📋 Overview

GPrep (Gorstak Preparation) is a comprehensive PowerShell-based system preparation and optimization tool designed for fresh Windows installations. It automates software installation via package managers, applies system tweaks, and optimizes Windows settings for performance and security.

The tool includes both a command-line script and a Control Panel applet (CPL) for easy access.

---

## 🎯 What It Does

- 📦 **Bulk Software Installation** - Installs 50+ applications via Winget
- 🔧 **System Optimization** - Applies BCD, NTFS, and RAM tweaks
- ⚙️ **Service Management** - Configures Windows services for optimal performance
- 🌐 **Network Hardening** - Sets Cloudflare DNS (1.1.1.1)
- 💾 **Memory Optimization** - Disables memory compression, applies RAM tweaks
- 🖱️ **Input Optimization** - DPI scaling and mouse curve adjustments
- 🔌 **USB Power Management** - Disables USB selective suspend
- 📂 **Context Menu** - Adds "Restart to BIOS" desktop right-click option
- 🛡️ **System Restore** - Creates restore point before modifications

---

## 📁 Project Structure

| File | Description |
|------|-------------|
| `GPrep.ps1` | Main PowerShell preparation script |
| `GPrep.cpl` | Control Panel applet executable |
| `GPrepHelper.ps1` | Helper functions for CPL |
| `GPrepUI.hta` | HTML Application UI for CPL |
| `install-cpl.reg` | Registry file to install CPL |
| `manifest.json` | Package manifest |
| `CPL/` | CPL source files (5 items) |

---

## 🚀 Installation

### Control Panel Applet

```cmd
# Install the CPL (requires Administrator)
regedit install-cpl.reg
```

After installation, GPrep appears in Windows Control Panel.

### Direct Script Usage

```powershell
# Run as Administrator
.\GPrep.ps1
```

The script auto-elevates if not run as admin.

---

## 📦 Installed Software (Winget)

| Category | Applications |
|----------|-------------|
| **Browsers** | Arc, Brave, Chrome, Firefox, Opera GX, Vivaldi |
| **Gaming** | Steam, Epic Games, GOG Galaxy, EA Desktop, Playnite, Prism Launcher, BlueStacks, Minecraft |
| **Development** | Git, Visual Studio 2022, VS Code |
| **Media** | Audacity, K-Lite Codec Pack, GIMP, Krita, VLC |
| **System** | Afterburner, HWMonitor, BleachBit, PowerToys, Everything, Bulk Crap Uninstaller |
| **Communication** | Discord |
| **Utilities** | ShareX, WinMerge, Rainmeter, Windhawk, UniGetUI |
| **Hardware** | Logitech G HUB, SteelSeries GG, Razer Synapse, GoXLR |

**Plus**: Additional packages via Chocolatey (AutoLogon, Start11)

---

## 🔧 System Modifications

### Network Configuration
```powershell
# Cloudflare DNS (IPv4 & IPv6)
IPv4: 1.1.1.1, 1.0.0.1
IPv6: 2606:4700:4700::1111, 2606:4700::1001
```

### BCD (Boot Configuration) Tweaks
| Setting | Value | Purpose |
|---------|-------|---------|
| tscsyncpolicy | Enhanced | Better CPU timing sync |
| timeout | 0 | No boot menu delay |
| bootux | disabled | No boot UI |
| quietboot | yes | Silent boot |
| x2apicpolicy | Enable | Modern APIC mode |

### NTFS Optimizations
```powershell
fsutil behavior set memoryusage 2      # Aggressive caching
fsutil behavior set mftzone 4          # Larger MFT zone
fsutil behavior set disablelastaccess 1 # Disable last access time
```

### RAM Management (Dynamic by System RAM)
| RAM Size | IoPageLockLimit | CacheUnmap | ModifiedWrite |
|----------|-----------------|------------|---------------|
| 4 GB | Calculated | 0x100 | 0x20 |
| 8 GB | Calculated | 0x200 | 0x40 |
| 16 GB | Calculated | 0x400 | 0x80 |
| 32 GB | Calculated | 0x800 | 0x160 |
| 64 GB+ | Calculated | 0x1600+ | 0x320+ |

### Services Set to Manual
- Diagnostic and tracking services (DiagTrack, dmwappushservice)
- Unused features (Fax, WMPNetworkSvc)
- Xbox services (XblAuthManager, XboxNetApiSvc)
- Printer services (if not needed)
- Update services (edgeupdate, gupdate)

---

## 🎨 UI Interface (HTA)

The CPL includes an HTML Application interface:

- **Modern Design** - Clean Windows-style interface
- **Progress Tracking** - Real-time installation progress
- **Category Selection** - Choose software categories to install
- **Status Updates** - Live feedback on current operations

---

## ⚙️ Usage Flow

1. **Elevation Check** - Auto-elevates to Administrator
2. **Winget Install** - Bulk application installation
3. **DNS Configuration** - Sets Cloudflare DNS
4. **Memory Optimization** - Disables compression, applies tweaks
5. **Restore Point** - Creates "GPrep" system restore point
6. **Device Cleanup** - Removes error-state phantom devices
7. **USB Power** - Disables selective suspend
8. **BCD Tweaks** - Boot configuration optimizations
9. **NTFS Tweaks** - File system optimizations
10. **RAM Tweaks** - Dynamic memory management settings
11. **Service Configuration** - Sets recommended services to manual
12. **DPI Scaling** - Mouse curve optimization
13. **SSD Optimization** - TRIM and latency settings
14. **Context Menu** - Adds Restart to BIOS option
15. **Additional Software** - PowerToys, FxSound, Chocolatey packages

---

## 📝 Requirements

- Windows 10/11 (64-bit)
- PowerShell 5.1+
- Administrator privileges
- Internet connection (for software downloads)
- Winget (Windows Package Manager) - included in Win10 20H2+/Win11

---

## ⚠️ Important Notes

### ⚠️ System Changes
- 🔄 **Reboot Required** - Some changes require restart to take effect
- 💾 **Disk Space** - Downloads require ~5-10 GB free space
- ⏱️ **Time** - Full installation takes 30-60 minutes depending on connection
- 🛡️ **Restore Point** - Creates restore point before making changes

### ⚠️ Service Disabling
- Some disabled services may be needed for specific hardware
- Review service list if you encounter issues after running

### ⚠️ Software Selection
- Modify the `$apps` array in `GPrep.ps1` to customize installations
- Some packages may require additional configuration post-install

---

## 🔧 Customization

### Modify Software List
```powershell
# Edit GPrep.ps1 - Add or remove from $apps array
$apps = @(
    "Your.App.Here",
    # ... existing apps
)
```

### Skip Categories
Comment out sections you don't want:
```powershell
# Remove or comment sections in GPrep.ps1
# Chocolatey installation
# BCD tweaks
# etc.
```

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