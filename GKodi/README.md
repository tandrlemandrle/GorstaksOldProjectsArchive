# 📺 GKodi — Automated Kodi Installer & Configurator

> **Silent Kodi Setup with Addon Repositories** — Downloads, installs, and configures Kodi with web server access and popular streaming addon sources.

---

## 🎬 Overview

GKodi.ps1 automates the full setup of Kodi media center on Windows. It silently installs Kodi 20.2 (Nexus), enables the built-in web server for remote control, and pre-configures addon repository sources for The Crew, Venom, and Seren — then launches Kodi ready to use.

### ✨ Key Features

- 📥 **Silent Download & Install** — Downloads Kodi 20.2 Nexus (x64) and installs with `/S` flag
- 🌐 **Web Server Configuration** — Enables Kodi's JSON-RPC web server on port 8080 via `advancedsettings.xml`
- 📦 **Addon Repository Sources** — Pre-configures `sources.xml` with:
  - **The Crew** (`https://team-crew.github.io`)
  - **Venom** (`https://venom-mod.github.io`)
  - **Seren** (`https://nixgates.github.io/packages`)
- 🔌 **Addon Installation** — Attempts to install addons via Kodi's JSON-RPC API
- 🚀 **Auto-Launch** — Starts Kodi after setup completes

---

## 📁 Files

| File | Description |
|------|-------------|
| `GKodi.ps1` | Main script — Kodi downloader, installer, web server configurator, and addon manager |

---

## 🚀 Usage

```powershell
# Run the full setup
powershell -ExecutionPolicy Bypass -File GKodi.ps1
```

### What Happens on Execution

1. Downloads `kodi-20.2-Nexus-x64.exe` to `%TEMP%`
2. Installs Kodi silently to `C:\Program Files\Kodi`
3. Waits 10 seconds for initialization
4. Creates `%APPDATA%\Kodi\userdata\advancedsettings.xml` with web server config:
   - Port: `8080`
   - Username: `kodi`
   - Password: `changeme`
5. Creates `%APPDATA%\Kodi\userdata\sources.xml` with addon repository URLs
6. Attempts to install The Crew, Venom, and Seren via JSON-RPC
7. Launches Kodi

> ⚠️ **Change the default web server password** (`changeme`) in `advancedsettings.xml` before exposing Kodi to a network.

### Accessing Kodi Web Interface

After setup, access the Kodi web interface at:
```
http://localhost:8080
Username: kodi
Password: changeme
```

---

## ⚙️ Requirements

- **OS:** Windows 10/11 (x64)
- **Internet:** Required for download and addon installation
- **PowerShell:** 5.1+

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
