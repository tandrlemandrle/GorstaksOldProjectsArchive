# Gorstak EDR

![.NET Framework 4.x](https://img.shields.io/badge/.NET_Framework-4.x-blue)
![Platform](https://img.shields.io/badge/platform-Windows_10+-0078D6?logo=windows)
![License](https://img.shields.io/badge/license-GPL--3.0-green)
![Architecture](https://img.shields.io/badge/arch-x64_%7C_x86-lightgrey)
![Jobs](https://img.shields.io/badge/detection_jobs-55-orange)

Lightweight endpoint detection and response platform for Windows. Single native executable, zero infrastructure, transparent scoring. Combines YARA scanning, CAPA-like PE analysis, AMSI integration, ETW monitoring, hash reputation, and 55 scheduled detection jobs into one binary that compiles with `csc.exe`.

## Why GEdr?

Most open-source EDR tools (Wazuh, OpenEDR, Velociraptor, LimaCharlie) need agents, servers, databases, and significant setup. Commercial EDRs are expensive and opaque.

GEdr is different:

- **Single executable** — one `GEdr.exe`, no runtime dependencies beyond .NET Framework 4.x
- **Zero infrastructure** — no server, no database, no cloud account
- **Transparent scoring** — every detection shows exactly why it flagged, with MITRE ATT&CK IDs and evidence chains
- **Builds with notepad** — compiles with `csc.exe` from .NET Framework, no Visual Studio or SDK needed
- **Anti-tamper** — detects and repairs AMSI patching, ETW unhooking, debugger attachment, config tampering, and DLL hijacking
- **Runs anywhere Windows runs** — .NET Framework 4.x is preinstalled on every modern Windows machine

Designed for small teams, home labs, security researchers, and anyone who wants endpoint visibility without enterprise overhead.

## Features

### Scan Engines (8 engines)
- **Hash reputation** — CIRCL, Cymru, MalwareBazaar lookups with local cache
- **Authenticode verification** — signature validation with trusted publisher awareness
- **CAPA-like PE analysis** — import-based capability detection (20 capability patterns)
- **Direct syscall detection** — scans for SysWhispers/HellsGate/D/Invoke stub patterns in PE sections
- **YARA rule scanning** — 9 built-in rule sets + configurable external rule directories
- **Entropy analysis** — file and per-section entropy for packer/encryption detection
- **AMSI integration** — Windows Antimalware Scan Interface for deobfuscated script content
- **LOLBin identification** — 30+ Living Off The Land binaries flagged even when Microsoft-signed

### Real-Time Monitoring
- **ETW process creation** — Security Event 4688 subscription for zero-gap process events
- **WMI process events** — Win32_ProcessStartTrace with polling fallback
- **FileSystemWatcher** — all fixed drives, executable/script extensions, ransomware rename detection
- **Network monitoring** — beacon pattern detection, C2 communication analysis

### Detection Jobs (55 scheduled)
- **Process**: hollowing, token manipulation, parent-child chains, PPID spoofing, fileless attacks, memory scanning, short-lived process detection, renamed binary detection, command-line entropy analysis
- **DLL**: hijacking, reflective injection, keystroke injection, browser DLL monitoring
- **Persistence**: registry Run keys, scheduled tasks, WMI subscriptions, startup folder
- **System**: rootkit detection, BYOVD (13+ vulnerable drivers, any load path), driver monitoring, BCD security, service/firewall/event log tampering, USB, clipboard, shadow copies, DNS exfiltration, proxy detection, script host, credential protection, honeypots
- **Hardening**: CVE mitigation, ASR rules, DNS security, C2 block lists (356 IPs), COM monitoring, browser extensions
- **Named pipes**: Cobalt Strike, Metasploit, Sliver, Brute Ratel, Mimikatz, PsExec pipe patterns
- **Self-protection**: AMSI integrity (with auto-repair), ETW integrity, debugger detection, config tamper lockout, DLL hijack detection, executable integrity, service tamper detection

### Response
- Auto-quarantine, process termination, IP blocking via Windows Firewall
- Dry-run mode (`--dry-run`) for safe tuning in production
- Quarantine management (list, restore, purge)

### Operational
- Structured JSON logging (`gedr_events.jsonl`) for SIEM ingestion
- Hourly heartbeat events for "is the agent alive?" monitoring
- Rolling log files (5 MB × 5 rotations)
- 24-hour threat report command
- Health check command
- `config.json` for all tunable settings
- Service auto-restart on crash (10s/30s/60s recovery)
- Windows Security Center registration

## Requirements

- Windows 10+ (x64 recommended)
- .NET Framework 4.x (preinstalled)
- Administrator privileges
- YARA v4.5.0 (auto-downloaded via `bootstrap`)

## Quick Start

```
build.cmd                           # Compile
bin\GEdr.exe bootstrap              # Download YARA
bin\GEdr.exe scan C:\Users -r       # Scan a directory
bin\GEdr.exe monitor                # Start real-time monitoring
```

## Build

```
build.cmd                           # Compile only
build.cmd installer                 # Compile + build installer
build.cmd sign cert.pfx password    # Compile + sign + build installer
```

Output: `bin\GEdr.exe` and optionally `bin\GEdr-Setup-2.0.0.exe`

## Usage

```
GEdr.exe scan <file>                Scan a single file
GEdr.exe scan <directory>           Scan all executables in a directory
GEdr.exe scan <directory> -r        Scan recursively
GEdr.exe scan <target> --no-action  Scan without auto-quarantine
GEdr.exe scan <target> --output-json Output results as JSON lines
GEdr.exe monitor                    Start real-time EDR monitoring
GEdr.exe monitor --dry-run          Monitor without killing/quarantining
GEdr.exe monitor --no-delay         Skip 15s startup delay
GEdr.exe bootstrap                  Download YARA + VC++ redistributable
GEdr.exe config                     Create default config.json
GEdr.exe hash <file>                Compute hashes + check reputation
GEdr.exe restore                    List quarantined files
GEdr.exe restore <id> [dest]        Restore a quarantined file
GEdr.exe restore --purge <id>       Delete a quarantined file
GEdr.exe report                     24-hour threat summary
GEdr.exe health                     System health check
GEdr.exe info                       Show engine status
GEdr.exe --version                  Show version and build date
```

Global flags: `--quiet` / `-q`, `--verbose`

Exit codes: `0` = clean, `1` = error, `2` = threats found, `99` = crash


## Scan Output Example

```
=== SCAN: suspicious.exe ===
  Path:    C:\Downloads\suspicious.exe
  Size:    245,760 bytes
  SHA256:  A1B2C3...
  Signed:  NO
  Entropy: 7.62 (PACKED)
  Hash:    Not found in threat databases
  PE:      x64 EXE
  Compile: 2026-03-15 08:22:11 UTC
  Imports: 6 DLLs, 89 functions
  --- Capabilities (CAPA-like) ---
    [T1134] escalate-privileges (score:60) via AdjustTokenPrivileges+OpenProcessToken
    [T1055] execute-shellcode (score:65) via VirtualAlloc+VirtualProtect
    [T1106] direct-syscall (score:65) 12 syscall stubs
    [T1622] anti-debug (score:35) via IsDebuggerPresent+NtQueryInformationProcess

  VERDICT: CRITICAL (score: 250)
```

## Threat Scoring

| Score | Verdict | Action |
|-------|---------|--------|
| 80+ | Critical | Auto-kill + auto-quarantine |
| 70–79 | Malicious | Auto-quarantine |
| 40–69 | Suspicious | Alert only |
| < 40 | Clean | No action |

All thresholds are configurable via `config.json`. Signed binaries from trusted publishers have PE capability scores zeroed out (still logged for analysis). LOLBins are flagged regardless of trust status.

## Anti-Tamper & Self-Protection

GEdr actively detects attempts to blind or disable it:

| Attack | Detection | Response |
|--------|-----------|----------|
| AMSI patching (`AmsiScanBuffer` overwrite) | Prologue byte comparison every 120s | Auto-repairs original bytes |
| ETW unhooking (`EtwEventWrite` patch) | Event flow heartbeat + prologue check | Alerts, falls back to WMI polling |
| Debugger attachment | `IsDebuggerPresent` check every 30s | THREAT alert |
| Config tampering (allowlist injection) | Hash comparison on `config.json` | Allowlists frozen, not reloaded |
| DLL hijacking in install directory | Loaded module path + hash verification | CRITICAL alert |
| Service stop/delete | Command-line monitoring for `sc stop GEdr` | CRITICAL alert |
| Executable replacement | SHA256 hash comparison every 30s | THREAT alert |
| YARA rules deletion | Directory existence check | THREAT alert |
| Process termination (non-admin) | Restrictive DACL on process handle | Access denied |
| Process crash | Windows service recovery policy | Auto-restart (10s/30s/60s) |

## MITRE ATT&CK Coverage

| Technique | ID | Detection |
|-----------|----|-----------|
| Process Injection | T1055 | PE analysis, memory scanning, process hollowing |
| Direct Syscalls | T1106 | Syscall stub pattern scanning in PE sections |
| Access Token Manipulation | T1134 | PE analysis, token manipulation detection |
| PPID Spoofing | T1134.004 | Parent start time vs child start time comparison |
| Command & Scripting | T1059 | AMSI, command-line analysis, entropy detection |
| Obfuscated Files | T1027 | Command-line entropy analysis (>5.5 threshold) |
| Boot/Logon Autostart | T1547.001 | Registry persistence detection |
| Scheduled Task/Job | T1053 | Scheduled task monitoring |
| WMI Event Subscription | T1546.003 | WMI persistence detection |
| DLL Side-Loading | T1574 | DLL hijacking detection, install dir monitoring |
| Impair Defenses | T1562.001 | AMSI/ETW tamper detection, service tamper detection |
| Rootkit | T1014 | Rootkit detection, driver monitoring |
| BYOVD | T1068 | 13+ vulnerable drivers, any-path loaded driver scanning |
| Lateral Movement | T1021, T1570 | Named pipe detection (Cobalt Strike, PsExec, etc.) |
| Credential Access | T1003 | AMSI patterns (Mimikatz, Rubeus, etc.), credential protection |
| Data Exfiltration | T1041 | Network monitoring, DNS exfiltration detection |
| Ransomware | T1486 | File rename monitoring, shadow copy deletion detection |
| Defense Evasion | T1622, T1497 | Anti-debug, anti-VM detection in PE analysis |

## Configuration

Generate a default `config.json`:

```
GEdr.exe config
```

Key settings:

```json
{
  "autoKillThreshold": 80,
  "autoQuarantineThreshold": 70,
  "alertThreshold": 40,
  "autoKillThreats": true,
  "autoQuarantine": true,
  "jsonLogging": true,
  "exclusionPaths": [],
  "allowlistHashes": [],
  "allowlistPaths": [],
  "allowlistSigners": [],
  "additionalProtectedProcesses": [],
  "extraRulePaths": []
}
```

Config changes while the EDR is running are detected and allowlists are frozen to prevent tampering. Restart the service to apply config changes.

## Installation

Run `GEdr-Setup-2.0.0.exe` as administrator. The installer offers:

- **Defender exclusion** — prevents Defender from interfering (checked by default)
- **Defender passive mode** — optional, sets Defender to passive so GEdr takes over real-time protection
- **Windows service** — auto-starts on boot with crash recovery (checked by default)
- **YARA bootstrap** — downloads YARA scanner during install (checked by default)
- **Windows Security Center** — registers GEdr as a security provider

Uninstalling cleanly removes the service, Defender exclusion, restores Defender real-time, and removes firewall rules. Quarantined files are preserved for review.

## Project Structure

```
GEdr/
├── Core/                  Config, ConfigLoader, Logger, JsonLogger, SelfProtection,
│                          JobScheduler, NativeMethods, ThreatTypes
├── Detection/             ProcessDetection, DllDetection, PersistenceDetection,
│                          SystemDetection, HardeningDetection, PipeDetection
├── Engine/                ScanPipeline, PeAnalyzer, YaraEngine, EntropyAnalyzer,
│                          HashReputation, AmsiScanner
├── Monitors/              ProcessMonitor, FileMonitor, NetworkMonitor, EtwMonitor
├── Response/              ResponseEngine, ThreatActions
├── Rules/                 9 YARA rule files (.yar)
├── Installer/             InnoSetup installer script
├── examples/              Sample config.json, EICAR test script
├── build.cmd              Full build pipeline (compile + sign + installer)
├── sign.cmd               Standalone code signing script
├── app.manifest           UAC elevation manifest
├── GEdr.ico               Application icon
├── CHANGELOG.md           Version history
├── CONTRIBUTING.md        Development guide
├── LICENSE                GPL-3.0
└── Program.cs             Entry point (55 scheduled jobs, 4 real-time monitors)
```

## Known Limitations

- **User-mode only** — no kernel driver. An admin-level attacker with custom tooling can still bypass detection. Kernel-mode protection (ELAM driver, minifilter, PPL) would require Microsoft WHQL signing.
- **Windows only** — no Linux/macOS support
- **Single host** — no central management console (yet)
- **YARA optional** — full detection requires running `bootstrap` to download YARA

## Code Signing

```
build.cmd sign your_cert.pfx your_password
```

Compiles, signs the executable, verifies the signature, and builds the installer in one step.

## License

[GNU General Public License v3.0](LICENSE)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding detections, coding style, and development workflow.
