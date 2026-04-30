# 🎮 GameCache — Multi-Tier Game File Caching System

> **RAM + SSD Caching for HDD Game Libraries** — Automatically accelerates game load times by caching frequently accessed files from HDD to faster storage tiers using symlinks and LRU eviction.

---

## ⚡ Overview

GameCache.ps1 is a multi-tier caching system designed for gamers who store their game libraries on HDDs but want SSD-like load times. It automatically detects your drive configuration, identifies cacheable game files (`.exe`, `.dll`, `.pak`, `.bin`, `.dat`, `.cache`), and transparently moves them to faster storage using symbolic links.

### ✨ Key Features

- 🧠 **RAM Cache (Tier 1)** — 2 GB RAM cache for small, frequently accessed files (<50 MB)
- 💾 **SSD Cache (Tier 2)** — 20 GB SSD cache for larger game files (<100 MB)
- 🔗 **Transparent Symlinks** — Original file paths remain unchanged; games don't know the difference
- 📊 **LRU Eviction** — Least Recently Used algorithm automatically evicts cold files when cache fills up
- 🔍 **Auto Drive Detection** — Identifies SSDs vs HDDs via WMI (interface type, model name, fallback heuristics)
- 📂 **Game Path Scanning** — Scans Steam, Epic Games, and local program directories
- 🔄 **Continuous Monitoring** — Rescans and re-caches every 60 seconds
- 💾 **Auto-Install** — Registers as a scheduled task at startup (runs as SYSTEM)
- 📋 **JSON Metadata** — Tracks cache state and access patterns in `%ProgramData%\GameCache\`

---

## 📁 Files

| File | Description |
|------|-------------|
| `GameCache.ps1` | Main script — caching engine, drive detection, LRU eviction, symlink management, and service installer |

---

## 🚀 Usage

```powershell
# First run — auto-installs as scheduled task and starts caching
powershell -ExecutionPolicy Bypass -File GameCache.ps1

# Explicitly uninstall — removes task, cache directories, and symlinks
powershell -ExecutionPolicy Bypass -File GameCache.ps1 -Uninstall
```

### How It Works

1. **Drive Detection** — Identifies SSDs and HDDs on your system
2. **Game Scanning** — Finds cacheable files in:
   - `C:\Program Files\Steam\steamapps\common`
   - `C:\Program Files (x86)\Steam\steamapps\common`
   - `C:\Program Files\Epic Games`
   - `%LOCALAPPDATA%\Programs`
3. **Tiered Caching:**
   - Files <50 MB → RAM cache (`%TEMP%\GameCache_RAM`)
   - Files 50–100 MB → SSD cache (`X:\GameCache_SSD`)
4. **Symlink Replacement** — Original file is copied to cache, replaced with a symlink
5. **LRU Eviction** — When cache hits 90% capacity, least recently used files are evicted

### Cache Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `RAMCacheSizeMB` | 2048 | RAM cache size in MB |
| `SSDCacheSizeGB` | 20 | SSD cache size in GB |
| `MonitorIntervalSeconds` | 60 | Scan interval |
| `MaxLRUEntries` | 10000 | Max tracked files for LRU |

### Checking Status

```powershell
# View cache log
Get-Content "$env:ProgramData\GameCache\cache.log" -Tail 30
```

---

## ⚙️ Requirements

- **OS:** Windows 10/11
- **Privileges:** Administrator (required for symlink creation)
- **PowerShell:** 5.1+
- **Storage:** At least one SSD + one HDD for optimal benefit

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
