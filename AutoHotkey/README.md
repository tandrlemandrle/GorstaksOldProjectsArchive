# 🔇 MuteDiscord

> **AutoHotkey script that automatically mutes Discord when its window becomes active.**

---

## 📋 Overview

MuteDiscord is a lightweight AutoHotkey script that monitors the active window title every second. When it detects a Discord window in the foreground, it sends `Ctrl+Shift+M` (Discord's toggle-mute shortcut) to mute your microphone. It only fires once per activation — switching away and back will mute again.

Useful if you want Discord muted by default whenever you tab into it.

---

## 🎯 How It Works

1. 🔁 **Polling Loop** — Checks the active window title every 1 second
2. 🔍 **Title Match** — Uses partial matching (`SetTitleMatchMode, 2`) to detect any window containing "Discord"
3. 🔇 **Send Mute** — Sends `Ctrl+Shift+M` once when Discord becomes the foreground window
4. 🚫 **One-Shot Flag** — A `Muted` flag prevents repeated mute toggles while Discord stays focused

---

## 🚀 Usage

1. Install [AutoHotkey v1.x](https://www.autohotkey.com/)
2. Double-click `MuteDiscord.ahk` to run it
3. Switch to Discord — your mic will be muted automatically

To stop the script, right-click the AutoHotkey tray icon and select **Exit**.

---

## 📦 Requirements

- **Windows**
- **AutoHotkey v1.x** (uses legacy syntax: `SetTitleMatchMode, 2`, `Send ^+m`)

---

## ⚠️ Notes

- The script sends `Ctrl+Shift+M` which is Discord's default mute keybind. If you've remapped it, the script won't work as expected.
- The mute flag resets when you switch away from Discord, so returning to Discord will mute again.

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
