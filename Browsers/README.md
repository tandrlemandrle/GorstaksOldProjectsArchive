# 🌐 Browsers — WebRTC & Remote Desktop Hardening

> **Browser Privacy & Security Script** — Disables WebRTC leak vectors across all major browsers, blocks Chrome Remote Desktop, and disables browser plugins to reduce attack surface.

---

## 🔒 Overview

Browsers.ps1 is a comprehensive browser hardening script that targets WebRTC IP leaks, remote desktop features, and unnecessary plugins across Chrome, Edge, Brave, Vivaldi, Opera, Opera GX, and Firefox. It also fully disables Chrome Remote Desktop by stopping its service, blocking its process via firewall, and terminating related browser processes.

### ✨ Key Features

- 🛡️ **WebRTC Disabling** — Prevents real IP address leaks through WebRTC in all Chromium-based browsers and Firefox
- 🚫 **Remote Desktop Blocking** — Disables remote desktop support in browser preferences
- 🔌 **Plugin Disabling** — Disables all browser plugins found in preferences
- 🦊 **Firefox Support** — Modifies `prefs.js` to set `media.peerconnection.enabled` to `false` and clears `pluginreg.dat`
- 💾 **Backup Creation** — Backs up Firefox `prefs.js` and `pluginreg.dat` before modification
- 🔥 **Chrome Remote Desktop Killer:**
  - Stops and disables the `chrome-remote-desktop-host` service
  - Terminates all Chrome-based browser processes
  - Creates firewall rules to block `remoting_host.exe` (inbound + outbound)

---

## 📁 Files

| File | Description |
|------|-------------|
| `Browsers.ps1` | Main script — WebRTC disabler, plugin remover, and Chrome Remote Desktop blocker |

---

## 🚀 Usage

```powershell
# Run the script (Administrator recommended for firewall rules)
powershell -ExecutionPolicy Bypass -File Browsers.ps1
```

### Supported Browsers

| Browser | WebRTC | Remote Desktop | Plugins | Method |
|---------|--------|---------------|---------|--------|
| Chrome | ✅ | ✅ | ✅ | Preferences JSON |
| Edge | ✅ | ✅ | ✅ | Preferences JSON |
| Brave | ✅ | ✅ | ✅ | Preferences JSON |
| Vivaldi | ✅ | ✅ | ✅ | Preferences JSON |
| Opera | ✅ | ✅ | ✅ | Preferences JSON |
| Opera GX | ✅ | ✅ | ✅ | Preferences JSON |
| Firefox | ✅ | — | ✅ | prefs.js + pluginreg.dat |

### What Gets Modified

**Chromium-based browsers** (`Default\Preferences`):
```json
{
  "profile": {
    "default_content_setting_values": {
      "media_stream": 2,
      "webrtc": 2
    }
  },
  "remote": {
    "enabled": false,
    "support": false
  }
}
```

**Firefox** (`prefs.js`):
```javascript
user_pref("media.peerconnection.enabled", false);
```

### Chrome Remote Desktop Blocking

The script creates Windows Firewall rules named `Block CRD Service` that block `remoting_host.exe` in both inbound and outbound directions.

```powershell
# Verify firewall rules
Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*CRD*" }
```

---

## ⚠️ Notes

- Close all browsers before running for best results — the script modifies preference files on disk.
- The script will terminate running Chrome-based browser processes as part of CRD blocking.
- Firefox profiles are auto-detected from `%APPDATA%\Mozilla\Firefox\Profiles`.

---

## ⚙️ Requirements

- **OS:** Windows 10/11
- **Privileges:** Administrator (for firewall rules and service management)
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
