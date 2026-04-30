# 🌐 DNS over HTTPS & DNS over TLS Configurator

## 🔍 Overview

A PowerShell script that configures **DNS over HTTPS (DoH)** and **DNS over TLS (DoT)** on your active network adapter with **Cloudflare as primary** and **Google as secondary** DNS providers. All DNS traffic is encrypted — UDP fallback is explicitly disabled.

### DNS configuration applied

| Role | Provider | IPv4 | IPv6 |
|------|----------|------|------|
| **Primary** | Cloudflare | `1.1.1.1` / `1.0.0.1` | `2606:4700:4700::1111` / `2606:4700:4700::1001` |
| **Secondary** | Google | `8.8.8.8` / `8.8.4.4` | `2001:4860:4860::8888` / `2001:4860:4860::8844` |

### What it does

1. **Registers DoH server templates** for all 8 DNS addresses (Cloudflare + Google, IPv4 + IPv6) with `AllowFallbackToUdp = $false` and `AutoUpgrade = $true`
2. **Detects the active network adapter** (excludes virtual, loopback, and Bluetooth interfaces)
3. **Sets DNS servers** via `netsh` for both IPv4 and IPv6
4. **Configures per-interface DoH** via registry (`DohFlags = 0x11` for automatic mode) under `Dnscache\InterfaceSpecificParameters`
5. **Configures per-interface DoT** via registry (`DotFlags = 0x11`) with proper hostname validation (`cloudflare-dns.com`, `dns.google`)
6. **Flushes DNS cache** and restarts the DNS Client service to apply changes immediately

## 🚀 Usage

Run as **Administrator** in PowerShell:

```powershell
.\configure-dns-doh-dot.ps1
```

Example output:

```
Registering DoH server templates...
  Added: 1.1.1.1
  Added: 8.8.8.8
  ...
Configuring adapter: Ethernet [{ guid }]
Setting IPv4 DNS servers...
Setting IPv6 DNS servers...
Enabling DoH for each DNS server...
Enabling DoT for each DNS server...
Applying changes...

========================================
Configuration Complete!
========================================
Primary:   Cloudflare 1.1.1.1 / 2606:4700:4700::1111
Secondary: Google     8.8.8.8 / 2001:4860:4860::8888
DoH: Enabled (Automatic) | DoT: Enabled
```

Verify in **Settings → Network → DNS** — dropdowns should show "On (automatic)".

## 📋 Requirements

- Windows 11 (DoH/DoT registry support)
- PowerShell 5.1+
- Administrator privileges
- Active non-virtual network adapter

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
