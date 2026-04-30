# GorstaksEDR v2.0

> A single-file PowerShell EDR focused on detection and alerting. Monitor-only by default. No dependencies. PS 5.1 compatible.

## What changed from v1

- **One script** instead of two overlapping ones
- **Monitor-only by default** — auto-response requires explicit `-AutoRespond` flag
- **No dangerous modules** — removed Retaliate (network flooding), Password Rotator, Key Scrambler, VPN Gate
- **Auto-response requires High confidence** — won't kill/quarantine on weak signals
- **Conservative file monitoring** — watches user-writable paths, not entire drives
- **Defender exclusion scoped to Quarantine folder only** — not the whole install directory
- **Uninstall preserves data** — doesn't silently delete logs and quarantined files
- **Clean error handling** — no swallowed exceptions, proper `Set-StrictMode`

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   EVENT SOURCES                         │
│  WMI Process Trace (or polling fallback)                │
│  FileSystemWatcher (Downloads, Desktop, Temp, AppData)  │
└────────────────────────┬────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────┐
│                 ANALYSIS PIPELINE                       │
│  Static Analysis    │ Behavior Engine  │ YARA Rules     │
│  (hash, entropy,    │ (LOLBin args,    │ (10 embedded   │
│   PE parsing, sig)  │  cmd patterns)   │  rules)        │
│                     │                  │                │
│  MITRE ATT&CK      │ Network Monitor  │ Process Chain  │
│  (18 techniques)    │ (port + beacon)  │ (parent-child) │
│                     │                  │                │
│  Memory Scanner     │ AMSI Integration │ Ransomware Det │
│  (RWX, shellcode,   │ (script files)   │ (mass rename,  │
│   reflective PE)    │                  │  ransom notes) │
└────────────────────────┬────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────┐
│              WEIGHTED SCORING ENGINE                    │
│  Behavior 1.5x │ Memory 1.5x │ Chain 1.4x │ YARA 1.3x│
│  Network  1.2x │ Static 1.0x │ MITRE 0.8x │ Hash 1.0x│
│  + Corroboration bonus  │  + Signed binary discount    │
└────────────────────────┬────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────┐
│              RESPONSE ENGINE                            │
│  Monitor-only (default):                                │
│    Score ≥ 50 → Alert (JSON file + log)                 │
│                                                         │
│  With -AutoRespond (High confidence only):              │
│    Score ≥ 100 → Kill process                           │
│    Score ≥  80 → Quarantine file + block IPs            │
│    Score ≥  50 → Alert                                  │
└─────────────────────────────────────────────────────────┘
```

## Quick Start

```powershell
# Monitor-only (recommended to start with)
.\GorstaksEDR.ps1

# Monitor + auto-response for high-confidence threats
.\GorstaksEDR.ps1 -AutoRespond

# Scan a specific file or directory
.\GorstaksEDR.ps1 -ScanPath "C:\Downloads"
.\GorstaksEDR.ps1 -ScanPath "C:\suspect.exe"

# Install as persistent service
.\GorstaksEDR.ps1 -Install

# Clean removal
.\GorstaksEDR.ps1 -Uninstall
```

## Interactive Use

```powershell
# Dot-source for interactive functions
. .\GorstaksEDR.ps1

Start-EDR                    # Start all monitors
Show-EDRDashboard            # View status and recent alerts
Stop-EDR                     # Graceful shutdown
Invoke-EDRScan -Path "C:\Downloads"  # Manual scan
```

## Detection Capabilities

| Engine | What it does | Score weight |
|--------|-------------|-------------|
| **Static Analysis** | SHA256 hash, entropy, PE parsing, Authenticode signature, AMSI | 1.0x |
| **Behavior Engine** | 20+ LOLBins with per-binary arg matching, 23 command-line patterns | 1.5x |
| **YARA-like Rules** | 10 rules: Cobalt Strike, Mimikatz, PowerSploit, AMSI bypass, etc. | 1.3x |
| **Process Chain** | Parent-child trees, LOLBin chains, non-interactive→shell detection | 1.4x |
| **Memory Scanner** | RWX regions, shellcode signatures, reflective PE injection | 1.5x |
| **Network Monitor** | Suspicious port detection, beaconing via jitter analysis | 1.2x |
| **Ransomware** | Mass rename detection, 30+ ransom extensions, ransom note patterns | via alerts |
| **MITRE ATT&CK** | 18 technique mappings across 5 tactics | 0.8x |
| **Hash Reputation** | Local known-bad hash database | 1.0x |

## Scoring

| Score | Verdict | Default action | With -AutoRespond |
|-------|---------|---------------|-------------------|
| 0-24 | Clean | — | — |
| 25-49 | Low | Log | Log |
| 50-79 | Suspicious | **Alert** | **Alert** |
| 80-99 | Malicious | Alert | Alert + Quarantine + Block (High confidence only) |
| 100+ | Critical | Alert | Alert + Kill + Quarantine + Block (High confidence only) |

**Score adjustments:**
- Signed by trusted publisher (Microsoft, Google, etc.): **-50 pts**
- Valid signature (any): **-20 pts**
- 4+ detection sources agree: **+35 pts**
- 3 sources agree: **+25 pts**

## Configuration

### Whitelist (`whitelist.json`)
```json
{
    "Paths": ["C:\\Program Files\\TrustedApp"],
    "Hashes": ["SHA256_HASH_HERE"]
}
```

### Hash Reputation DB (`hashdb.json`)
```json
[
    { "Hash": "SHA256_HERE", "ThreatName": "Trojan.GenericKD" }
]
```

## Limitations

- No kernel-level visibility (rootkits can bypass)
- Memory scanner requires sufficient process access rights
- AMSI depends on registered AV engine (typically Defender)
- Network monitoring is connection-based, not packet-level
- Beaconing detection needs multiple observations over time
- PowerShell-based — an attacker with admin access can kill it

## License & Disclaimer

This project is for authorized defensive, administrative, research, or educational use only.

- Use only on systems where you have explicit permission
- Validate in a test environment before production use
- Provided "AS IS" without warranties of any kind
- Authors are not liable for damages, data loss, or downtime

---

<p align="center"><sub>Built by <strong>Gorstak</strong>, refactored for safety</sub></p>
