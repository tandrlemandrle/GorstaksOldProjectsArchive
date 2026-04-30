# 🛡️ PiHole for Windows

> **System-wide ad, tracker, and malware blocking for Windows using permanent routes — IPv4 and IPv6.**

---

## 📋 Overview

PiHole for Windows is a lightweight PowerShell-based network blocker that operates at the routing level. It downloads community-maintained ad filter lists and threat intelligence feeds, resolves ad/tracker domains to their IP addresses (both IPv4 and IPv6), and blocks them using Windows persistent routes — no browser extensions, no DNS servers, no proxy software, no third-party dependencies.

Traffic to blocked IPs is routed to a black hole (`0.0.0.0` for IPv4, `::` for IPv6), preventing **any application** on the system from reaching ad servers, analytics trackers, and known malware infrastructure — browsers, desktop apps, games, background services, everything.

---

## ✨ Features

### 🚫 Ad & Tracker Blocking
- Downloads **EasyList**, **EasyPrivacy**, and **AdGuard Base** filter lists (~100K+ domains)
- Resolves domains to both **IPv4** (A records) and **IPv6** (AAAA records) via DNS
- Blocks Google Ads, Facebook Pixel, analytics trackers, Taboola, Outbrain, and thousands more
- No IPv6 bypass — both address families are blocked

### 🦠 Malware & Botnet Blocking
- Downloads threat intelligence feeds from **Spamhaus DROP**, **Emerging Threats**, **Feodo Tracker**, **CINS Army**, **Talos Intelligence**, and **FireHOL**
- Blocks known malware command & control servers, botnets, and malicious IPs
- No DNS resolution needed — IPs are blocked directly

### ⚙️ How It Works
- IPv4: `route add <ip> MASK 255.255.255.255 0.0.0.0 -p` (persistent route to black hole)
- IPv6: `netsh interface ipv6 add route <ip>/128 interface=1` (persistent route to loopback)
- Routes survive reboots — no background service needed
- Works independently of DNS settings, DoH, VPNs, and browser configuration

### ⚡ Smart Caching
- **DNS cache** — saves domain-to-IP mappings in `dns-cache.txt`, skips already-resolved domains on subsequent runs
- **Route detection** — checks existing persistent routes before adding, only adds new IPs
- **First run**: ~2 hours (full DNS resolution of 100K+ domains)
- **Subsequent runs**: seconds to minutes (only resolves new domains)

### 🔄 Auto-Updating
- Registers a daily scheduled task (3 AM) to refresh routes with latest lists
- Old routes are cleaned up before new ones are added on fresh installs

### 🧹 Clean Removal
- Single command removes all blocked routes (IPv4 + IPv6) instantly
- Cached IP list ensures complete cleanup

---

## 🚀 Usage

> ⚠️ **Must run as Administrator** — adding persistent routes requires elevated privileges.

### 📦 Full Install

Downloads lists, resolves IPs, adds routes, and registers daily update task:

```powershell
powershell -ExecutionPolicy Bypass -File Pihole.ps1
```

### 🔄 Update Only

Adds new routes without removing existing ones or re-registering the scheduled task:

```powershell
powershell -ExecutionPolicy Bypass -File Pihole.ps1 -UpdateOnly
```

### 🗑️ Remove All Routes

Cleanly removes all PiHole routes (IPv4 + IPv6) from the system:

```powershell
powershell -ExecutionPolicy Bypass -File Pihole.ps1 -Remove
```

### ⚡ Quick Test

Limit to first 5,000 domains for a fast test run (~2 minutes):

```powershell
powershell -ExecutionPolicy Bypass -File Pihole.ps1 -MaxDomains 5000
```

---

## 📊 Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-UpdateOnly` | Switch | `$false` | Add new routes only, skip removal and task registration |
| `-Remove` | Switch | `$false` | Remove all PiHole routes and caches |
| `-MaxDomains` | Int | `0` (all) | Limit number of ad domains to resolve (0 = unlimited) |

---

## 🌐 Filter & Threat Sources

### 📋 Ad & Tracker Lists

| List | Source | Content |
|---|---|---|
| EasyList | `easylist.to` | Primary ad blocking rules |
| EasyPrivacy | `easylist.to` | Tracker and analytics blocking |
| AdGuard Base | `adtidy.org` | Additional ad/tracker rules |

### 🦠 Threat Intelligence Feeds

| Feed | Source | Content |
|---|---|---|
| Spamhaus DROP | `spamhaus.org` | Known malware and botnet IPs |
| Emerging Threats | `emergingthreats.net` | Active threat IPs |
| Feodo Tracker | `abuse.ch` | Banking trojan C&C servers |
| CINS Army | `cinsscore.com` | Malicious IPs from threat scoring |
| Talos Intelligence | `talosintelligence.com` | Cisco threat intelligence blacklist |
| FireHOL Level 3 | `firehol.org` | Aggregated malware and botnet IPs |

---

## 🏗️ Project Structure

| File | Description |
|---|---|
| `Pihole.ps1` | Main script — downloads lists, resolves domains, adds routes |
| `Pihole.reg` | Pre-built registry file (legacy DNS policy approach) |
| `PiholeLite.reg` | Lightweight registry variant |
| `dns-cache.txt` | Generated — cached domain-to-IP mappings for fast subsequent runs |
| `route-cache.txt` | Generated — cached blocked IPs for clean removal |

---

## ⏱️ Performance Notes

| Scenario | Time |
|---|---|
| 🐢 First run (~100K domains) | 1–2 hours |
| ⚡ Subsequent runs (cached) | Seconds to minutes |
| 🧪 Quick test (`-MaxDomains 5000`) | ~2 minutes |
| 🦠 Threat IP lists only | Under 30 seconds |

- DNS cache (`dns-cache.txt`) persists between runs — already-resolved domains are skipped
- Existing persistent routes are detected — already-blocked IPs are not re-added
- The scheduled task runs at 3 AM to avoid impacting daytime usage

---

## 🔧 Troubleshooting

| Issue | Solution |
|---|---|
| Script fails with access denied | Run PowerShell as Administrator |
| Some websites break after install | Run with `-Remove` to undo, then re-run with `-MaxDomains 5000` for a lighter block |
| Routes not persisting after reboot | Ensure script ran as Administrator (routes require elevation) |
| Want to check active IPv4 routes | Run `route print` in an elevated command prompt |
| Want to check active IPv6 routes | Run `netsh interface ipv6 show route` |
| DNS resolution is slow | Use `-MaxDomains` to limit scope, or ensure your DNS server is responsive |
| Want to force full re-resolve | Delete `dns-cache.txt` and run again |

---

## 📜 License & Disclaimer

This project is intended for authorized defensive, administrative, research, or educational use only.

- Use only on systems, networks, and environments where you have explicit permission.
- Blocking IPs via persistent routes may affect legitimate services that share infrastructure with ad networks or flagged IP ranges.
- IPv6 route blocking uses the loopback interface — ensure this doesn't conflict with other IPv6 configurations.
- Threat intelligence feeds may contain false positives that block legitimate services.
- Misuse may violate law, contracts, policy, or acceptable-use terms.
- Validate all changes in a test environment before production use.
- This project is provided **"AS IS"**, without warranties of any kind, including merchantability, fitness for a particular purpose, and non-infringement.
- Authors and contributors are **not liable** for direct or indirect damages, data loss, downtime, business interruption, legal exposure, or compliance impact.
- You are solely responsible for lawful operation, configuration choices, and compliance obligations in your jurisdiction.
- Use `-Remove` to cleanly undo all changes if any issues arise.
- This software is not affiliated with or endorsed by Pi-hole®, Spamhaus, Cisco Talos, abuse.ch, or any other third party.

---

<p align="center">
  <sub>Built with care by <strong>Gorstak</strong></sub>
</p>
