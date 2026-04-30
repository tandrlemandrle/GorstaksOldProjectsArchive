# 🔐 Hardening

> **Windows & Active Directory Security Hardening Suite** - Comprehensive system and domain security configuration scripts.

---

## 📋 Overview

Hardening is a comprehensive security hardening toolkit for Windows systems and Active Directory environments. It provides automated scripts to configure password policies, credential protection, privileged access management, and system-wide security settings.

---

## 🎯 What It Does

- 🔐 **Password Policies** - Enforce strong domain password requirements
- 🛡️ **Credential Protection** - LSASS protection and credential clearing
- 👤 **Service Account Security** - Secure service account configurations
- 🚫 **Privilege Management** - Restrict and monitor privileged access
- 🔒 **Local Security** - System-level hardening configurations
- 🎮 **Gaming Optimizations** - Security hardening without breaking games

---

## 📁 Project Structure

| File | Description |
|------|-------------|
| `Hardening.ps1` | Main comprehensive hardening script (20.2 KB) |
| `Harden_AD.ps1` | Active Directory specific hardening (10.2 KB) |
| `Hardening.cmd` | Batch wrapper for easy execution (4.4 KB) |
| `Games.reg` | Gaming-friendly security registry settings (23 KB) |
| `windows-security-hardening.ps1` | Additional security hardening (69.3 KB) |

---

## 🚀 Usage

### Full System Hardening
```powershell
# Run as Administrator
.\Hardening.ps1
```

### Active Directory Hardening
```powershell
# On Domain Controller as Domain Admin
.\Harden_AD.ps1
```

### Gaming-Friendly Hardening
```cmd
# Apply gaming-optimized settings
reg import Games.reg
```

---

## 📋 Hardening Areas

### Password Policies
| Setting | Value |
|---------|-------|
| Minimum Length | 14 characters |
| Complexity | Required |
| Maximum Age | 90 days |
| History | 24 passwords |
| Lockout Threshold | 5 attempts |
| Lockout Duration | 15 minutes |

### Credential Protection
- ✅ LSASS Protected Process Light (PPL) enabled
- ✅ Cached logons disabled
- ✅ Credential Manager cleared
- ✅ Credential Guard (if supported)

### Service Accounts
- ✅ Password expiration enforced
- ✅ Non-expiring passwords removed
- ✅ Regular audit and rotation

### Privileged Access
- ✅ Guest account disabled
- ✅ Built-in Administrator disabled
- ✅ Privileged use audited
- ✅ SeDebugPrivilege restricted

### Local Security
- ✅ Audit policy comprehensive
- ✅ Security options hardened
- ✅ User rights assignments
- ✅ Registry security

---

## ⚙️ Script Features

### Hardening.ps1
- Combines all hardening modules
- Comprehensive logging
- Error handling
- Progress indicators

### Harden_AD.ps1
- Domain-specific configurations
- GPO management
- Service account hardening
- Domain-wide policies

### Games.reg
- Gaming-optimized settings
- Reduced security impact for games
- Maintains protection while allowing gameplay

---

## 📝 Requirements

- Windows 10/11 Pro/Enterprise or Windows Server 2016+
- Administrator privileges
- Active Directory module (for AD hardening)
- PowerShell 5.1+

---

## ⚠️ Important Notes

### ⚠️ System Impact
- Changes may affect user experience
- Some legacy applications may require adjustment
- Test in non-production before deployment

### ⚠️ AD Considerations
- Domain-wide impact
- Coordinate with domain administrators
- Backup AD before major changes

### ✅ Recommendations
- Create system restore point before running
- Test with pilot group first
- Document any customizations

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