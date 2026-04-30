# 🔊 Audio Enhancement

## 🔍 Overview

A PowerShell script that enables **Acoustic Echo Cancellation (AEC)** and **Noise Suppression** on all audio render devices by modifying the Windows registry. The script takes ownership of the relevant registry keys, grants Administrators full control, and then sets the appropriate `FxProperties` values for every audio device found under the system's `MMDevices\Audio\Render` tree.

### What it does

1. Enumerates all audio render devices in `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render`
2. Creates the `FxProperties` subkey if it doesn't exist
3. Takes ownership and grants `FullControl` to the Administrators group
4. Sets the **AEC** property (`{1c7b1faf-caa2-451b-b0a4-87b19a93556a},6`) to enabled
5. Sets the **Noise Suppression** property (`{e0f158e1-cb04-43d5-b6cc-3eb27e4db2a1},3`) to enabled

## 🚀 Usage

Run as **Administrator** in PowerShell:

```powershell
.\Audio.ps1
```

Example output:

```
Ownership and Full Control granted for SOFTWARE\Microsoft\...
Acoustic Echo Cancellation set to enabled for device: {device-guid}
Noise Suppression set to enabled for device: {device-guid}
```

## 📋 Requirements

- Windows 10/11
- PowerShell 5.1+
- Administrator privileges

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
