# 🔐 Consent (UAC Prompt Configuration)

## 🔍 Overview

A batch script that takes ownership of `consent.exe` (the Windows UAC consent dialog binary) and configures UAC prompt behavior through the registry.

### What it does

1. **Takes ownership** of `%windir%\system32\consent.exe` using `takeown` and assigns it to the Administrators group
2. **Resets and restricts ACLs** on `consent.exe` — removes inherited permissions and grants Read & Execute only to `Console Logon` users
3. **Configures UAC behavior** via registry:
   - `ConsentPromptBehaviorAdmin` = `5` — Prompts admin users for consent on the secure desktop (default Windows behavior)
   - `ConsentPromptBehaviorUser` = `1` — Prompts standard users for credentials on the secure desktop

By restricting who can execute `consent.exe` and enforcing secure desktop prompts, this script hardens the UAC consent flow against tampering and bypass attempts.

## 🚀 Usage

Run as **Administrator** from a Command Prompt:

```cmd
Consent.cmd
```

Example output:

```
SUCCESS: The file (or folder): "C:\Windows\system32\consent.exe" now owned by the administrators group.
processed file: C:\Windows\system32\consent.exe
```

## 📋 Requirements

- Windows 10/11
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
