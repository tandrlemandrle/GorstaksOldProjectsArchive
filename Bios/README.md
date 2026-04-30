# ⚙️ BIOS / BCD Boot Tweaks

## 🔍 Overview

A batch script that applies a comprehensive set of **BCD (Boot Configuration Data)** tweaks via `bcdedit.exe` to optimize boot behavior and reduce overhead from security and virtualization features.

### Settings applied

| Setting | Value | Effect |
|---------|-------|--------|
| `nx` | AlwaysOff | **Disables DEP** (Data Execution Prevention) |
| `ems` / `bootems` | No | Disables Emergency Management Services |
| `integrityservices` | disable | Disables code integrity services |
| `tpmbootentropy` | ForceDisable | Disables TPM boot entropy |
| `bootmenupolicy` | Legacy | Uses legacy boot menu |
| `debug` | No | Disables kernel debugging |
| `disableelamdrivers` | Yes | Disables Early Launch Anti-Malware drivers |
| `isolatedcontext` | No | Disables isolated context |
| `vm` | No | Disables virtual machine mode |
| `vsmlaunchtype` | Off | Disables Virtual Secure Mode |
| `pae` | ForceDisable | Disables Physical Address Extension |
| `tscsyncpolicy` | legacy | Uses legacy TSC sync |
| `hypervisorlaunchtype` | off | Disables the hypervisor |
| `useplatformclock` / `useplatformtick` | false / no | Disables platform clock/tick |
| `disabledynamictick` | yes | Disables dynamic tick |
| `x2apicpolicy` | disable | Disables x2APIC |
| `uselegacyapicmode` | yes | Forces legacy APIC mode |

## ⚠️ WARNING — DEP is Disabled

> **This script sets `nx AlwaysOff`, which completely disables Data Execution Prevention (DEP).**
>
> DEP is a critical security feature that prevents code execution from non-executable memory regions. Disabling it makes your system significantly more vulnerable to buffer overflow attacks and memory-based exploits.
>
> **Only disable DEP if you have a specific compatibility reason and fully understand the security implications.** Re-enable with `bcdedit /set nx OptIn` or `AlwaysOn` when no longer needed.

## 🚀 Usage

Run as **Administrator** from a Command Prompt:

```cmd
Bios.cmd
```

A reboot is required for changes to take effect.

### Reverting

To restore DEP and other defaults:

```cmd
bcdedit /set nx OptIn
bcdedit /set hypervisorlaunchtype auto
bcdedit /set disabledynamictick no
```

## 📋 Requirements

- Windows 10/11
- Administrator privileges
- Reboot after running

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
