# 🎮 GamingScripts — Gaming Optimization Toolkit

> **Network Latency Reduction, Savegame Management & Game Configuration** — A collection of scripts to optimize your gaming experience on Windows.

---

## 🚀 Overview

GamingScripts is a toolkit containing three utilities: an aggressive bufferbloat/latency reduction script for competitive gaming, a savegame backup and restore tool, and a game AI configuration file for Infinity Engine games.

---

## 📁 Files

| File | Description |
|------|-------------|
| `Bufferbloat.ps1` | Aggressive network latency reduction via registry tweaks, netsh commands, and adapter configuration |
| `RestoreOrBackupSavegames.py` | Interactive Python tool to backup and restore game save files |
| `Infinity.BS` | AI behavior script for Infinity Engine games (Baldur's Gate series) |

---

## ⚡ Bufferbloat.ps1

A comprehensive network optimization script targeting low-latency gaming, specifically tuned for MediaTek WiFi 6E adapters (but applicable to any adapter).

### What It Does

The script applies optimizations in three phases:

**Phase 1 — Registry Optimizations:**
- Disables TCP window scaling and auto-tuning to prevent large buffers
- Sets immediate ACK (no delayed acknowledgments)
- Limits TCP/Winsock socket buffer sizes (`DefaultReceiveWindow`, `DefaultSendWindow` → 32 KB)
- Disables TCP offloading, checksum offload, and Large Send Offload (LSO)
- Configures QoS packet scheduler for zero bandwidth reservation
- Removes network throttling (`NetworkThrottlingIndex = 0xFFFFFFFF`)
- Sets `SystemResponsiveness` to 0 (prioritize foreground tasks)
- Configures Multimedia Class Scheduler for high-priority gaming
- Disables Windows Update Delivery Optimization P2P
- Optimizes DNS cache TTL settings

**Phase 2 — Netsh Commands:**
- Disables TCP auto-tuning level
- Sets congestion provider to CTCP (Compound TCP)
- Disables ECN, TCP timestamps, and TCP heuristics
- Enables RSS (Receive Side Scaling)

**Phase 3 — Adapter Configuration:**
- Disables Large Send Offload V2 (IPv4/IPv6) on all active adapters
- Disables Interrupt Moderation
- Sets Receive/Transmit Buffers to minimum (64)
- Disables adapter power management

```powershell
# Run as Administrator
powershell -ExecutionPolicy Bypass -File Bufferbloat.ps1
```

> ⚠️ **This prioritizes LOW LATENCY over maximum throughput.** Download speeds may decrease. A reboot is recommended after applying.

---

## 💾 RestoreOrBackupSavegames.py

An interactive Python script that backs up and restores game save files from common Windows save locations.

### Scanned Directories

| Location | Typical Games |
|----------|---------------|
| `Documents\My Games` | Skyrim, Fallout, Civilization |
| `Saved Games` | Various Windows games |
| `AppData\Local` | Indie games, Unity titles |
| `AppData\Roaming` | Minecraft, various launchers |

```bash
# Run interactively
python RestoreOrBackupSavegames.py

# Choose:
# 1. Backup savegames  → copies all save locations to a destination folder
# 2. Restore savegames → restores from a backup folder to original locations
```

---

## 🗡️ Infinity.BS

A `.BS` (BioWare Script) AI configuration file for Infinity Engine games (Baldur's Gate, Icewind Dale). Contains AI behavior scripts for party members including:

- Enemy detection logic for up to 6 players
- Archer behavior with weapon/spell slot management
- Party protector role assignment with strong protector counting
- Melee range detection and combat engagement timers
- Summoning item usage (Efreeti Bottle, Spider Figurine, Moon Dog Figurine, Golden Lion Figurine, Horn of Valhalla, Golem Manual, Vhailor's Helm)
- Harp usage (Harp of Discord, Harp of Pandemonium, Azlaer's Harp, Methild's Harp)
- Movement and positioning control

---

## ⚙️ Requirements

| Script | Requirements |
|--------|-------------|
| `Bufferbloat.ps1` | Windows 10/11, Administrator, PowerShell 5.1+ |
| `RestoreOrBackupSavegames.py` | Python 3.x |
| `Infinity.BS` | Infinity Engine game (BG1/BG2/IWD) with script support |

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
