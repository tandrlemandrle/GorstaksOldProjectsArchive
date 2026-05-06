# GIDR — Gorstaks Intrusion Detection and Response

**v6.3.0** · A behavioral intrusion detection system for Windows. Files are innocent until proven guilty at runtime. When malicious behavior is detected, the entire attack chain is traced to root and eliminated.

---

## Philosophy

GIDR is not an antivirus. It doesn't quarantine files for looking suspicious. It doesn't care about entropy, imports, or missing signatures.

GIDR watches what processes **do**. When one crosses the line — dumps credentials, beacons to a C2 server, encrypts your files, opens a reverse shell, or records your microphone — GIDR traces the attack back to its root, kills every process in the chain, quarantines the attacker's files, removes their persistence, and blocks their IPs.

**What GIDR ignores:** high entropy, unsigned binaries, suspicious imports, packed executables, double extensions. These are logged for forensics but never trigger action.

**What GIDR acts on:** credential dumping, C2 beaconing, ransomware encryption, reverse shells, process injection, audio hijacking, ETW tampering, lateral movement, fileless execution, autonomous malware phoning home.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RUNTIME MONITORS                         │
│                                                             │
│  ProcessMonitor     ETW Monitor        NetworkMonitor       │
│  (WMI events +     (Event 4688/4689   (connection-to-PID   │
│   polling fallback)  zero-gap)          correlation)        │
│                                                             │
│  FileMonitor        SelfProtection                          │
│  (FileSystemWatcher (DACL, integrity,                       │
│   ransomware rename  ETW tamper check,                      │
│   detection)         debugger detect)                       │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                 BEHAVIORAL DETECTION                        │
│                                                             │
│  MemoryExecutionDetection  │  CredentialDumpDetection       │
│  (fileless, reflective DLL │  (LSASS access, SAM dump,      │
│   injection, hollowing,    │   known dumping tools)         │
│   download cradles)        │                                │
│                            │                                │
│  RansomwareDetection       │  AudioHijackDetection          │
│  (mass rename, shadow copy │  (microphone access by         │
│   deletion, ransom notes)  │   unknown processes)           │
│                            │                                │
│  NetworkMonitor (C2)       │  ModuleValidationDetection     │
│  (C2 beaconing, reverse    │  (DLL hijacking, module        │
│   shells, autonomous       │   integrity checks)            │
│   malware, cryptominers)   │                                │
│                            │                                │
│  IoCScanner                │  YaraScanner                   │
│  (hash, IP, domain IoCs)   │  (9 rule files, log-only)      │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              RESPONSE ENGINE (behavioral only)              │
│                                                             │
│  Static scan verdicts → LOG ONLY (never act)                │
│  Behavioral detections → CHAIN TRACE AND NUKE               │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    CHAIN TRACER                             │
│                                                             │
│  1. Walk parent chain to find attack root                   │
│  2. Collect all descendant processes                        │
│  3. Kill entire process tree (leaves first)                 │
│  4. Quarantine attacker executables (skip system binaries)  │
│  5. Hunt persistence (Run keys, scheduled tasks, startup)   │
│  6. Block attacker IPs (outbound firewall rules)            │
│  7. Collect forensic evidence + generate incident ticket    │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

```
# Build
build.cmd

# Bootstrap dependencies (downloads YARA + VC++ redist)
GIDR.exe bootstrap

# Start monitoring (requires Administrator)
GIDR.exe monitor

# Scan a file or directory (informational only — no auto-response)
GIDR.exe scan file.exe
GIDR.exe scan C:\Downloads
```

---

## Commands

| Command | Description |
|---------|-------------|
| `GIDR.exe monitor` | Start real-time behavioral monitoring (requires admin) |
| `GIDR.exe monitor --dry-run` | Monitor mode — log threats but take no action |
| `GIDR.exe scan <path>` | Scan file or directory with YARA (informational, no auto-response) |
| `GIDR.exe scan <path> <rule.yar>` | Scan with a specific rule file |
| `GIDR.exe hunt` | YARA hunt on suspicious locations (temp, appdata, etc.) |
| `GIDR.exe isolate` | Block all outbound traffic (network containment) |
| `GIDR.exe isolate --restore` | Restore network after isolation |
| `GIDR.exe bootstrap` | Download YARA engine and VC++ runtime |
| `GIDR.exe config` | Create default config.json |
| `GIDR.exe info` | Show engine status and configuration |
| `GIDR.exe restore` | List quarantined files |
| `GIDR.exe restore <index> <path>` | Restore a quarantined file |
| `GIDR.exe restore --purge <index>` | Delete a quarantined file |
| `GIDR.exe report` | Show last 24h threat summary |
| `GIDR.exe health` | System health check |
| `GIDR.exe version` | Print version |

---

## What Gets Detected and Acted On

### Behavioral Detections (auto-response: trace chain → kill → quarantine → block)

| Detection | What it catches | How |
|-----------|----------------|-----|
| **Reverse shell** | cmd/powershell with outbound connection to non-standard port | NetworkMonitor PID correlation |
| **C2 beaconing** | Regular-interval outbound connections (low jitter) | Statistical interval analysis |
| **Autonomous malware** | Unknown process from temp/appdata with outbound connections | Process-to-connection mapping |
| **Credential dumping** | LSASS access, SAM/SECURITY hive dumping, known tools (mimikatz, procdump, etc.) | Process + memory scanning |
| **Ransomware** | Mass file renames, shadow copy deletion, ransom notes | FileMonitor + command-line patterns |
| **Process injection** | CreateRemoteThread, APC injection, process hollowing | Memory scanning + API monitoring |
| **Fileless execution** | In-memory-only code, reflective DLL injection, .NET memory loading, download cradles | Memory region analysis |
| **Audio hijacking** | Microphone access by unknown or unexpected processes | Device access monitoring |
| **DLL hijacking** | DLL loaded from wrong path, module integrity mismatch | Module snapshot comparison |
| **Lateral movement** | PsExec, WMI remote exec, WinRM from unexpected sources | Command-line + network analysis |
| **ETW tampering** | ntdll!EtwEventWrite patched to RET (EDR blinding) | Memory prologue verification |
| **Service tampering** | Critical services being stopped or modified | Service state monitoring |
| **Persistence creation** | Run keys, scheduled tasks, startup folder modifications | Registry + task monitoring |

### Static Detections (log only — never triggers auto-response)

| Detection | What it logs |
|-----------|-------------|
| YARA rules | 9 rule files: C2 frameworks, credentials, injection, ransomware, persistence, LOLBins, AMSI bypass, exfiltration, generic malware |
| IoC scanning | Malicious hashes, IPs, and domains from threat intel feeds |
| PE analysis | Imports, sections, capabilities, packer indicators |

---

## Chain Tracer — How Response Works

When a behavioral detection fires, GIDR doesn't just kill the offending process. It traces the entire attack:

```
Example: Credential dump detected

  1. DETECT    mimikatz.exe (PID 4521) accessing LSASS
                    │
  2. TRACE UP  4521 ← powershell.exe (4200) ← cmd.exe (3800) ← dropper.exe (3100) ← explorer.exe (1200)
                                                                      ▲
  3. ROOT      dropper.exe is the attack root (first non-system ancestor)
                    │
  4. TRACE DOWN dropper.exe → cmd.exe → powershell.exe → mimikatz.exe
                            → beacon.exe → svchost_fake.exe
                    │
  5. KILL      Kill all 5 processes (leaves first: mimikatz, beacon, svchost_fake, then PS, cmd, dropper)
                    │
  6. QUARANTINE Move dropper.exe, beacon.exe, svchost_fake.exe to Quarantine/
               (cmd.exe, powershell.exe are system binaries — left alone)
                    │
  7. PERSISTENCE Check Run keys, scheduled tasks, startup folder for anything
                 pointing to quarantined files → remove
                    │
  8. BLOCK     Find all outbound connections from the chain → firewall block
                    │
  9. EVIDENCE  Collect memory dump, module list, network snapshot → Evidence/
               Generate incident ticket with full chain details
```

System binaries (cmd.exe, powershell.exe, svchost.exe, etc.) are never quarantined — they're legitimate tools that were abused. Only the attacker's own files get quarantined.

---

## Autonomous Malware Detection

GIDR handles the "hacker is gone but malware is still active" scenario.

The NetworkMonitor correlates every TCP connection to its owning process. When it finds an unknown process (not in the legitimate network process list) with outbound connections — especially from suspicious paths (temp, appdata, programdata), on non-standard ports, with beacon-like timing — it enqueues a behavioral threat. The ResponseEngine calls ChainTracer, which traces the process back to whatever dropped it, kills the tree, quarantines the binaries, and blocks the C2 IPs.

This catches RATs phoning home, cryptominers connecting to pools, backdoors waiting for commands, and data stealers uploading to attacker infrastructure.

---

## Incident Response (IDR)

When a behavioral threat is confirmed, GIDR optionally collects forensic evidence:

- **Memory dump** — minidump of the offending process
- **Module inventory** — list of all loaded DLLs with base addresses
- **Network snapshot** — TCP connection state at time of detection
- **Binary copy** — attacker executable copied to the evidence case folder
- **Incident ticket** — structured report with full chain details, MITRE ATT&CK mapping, and recommended actions

Evidence is saved to `Evidence/Case_<PID>_<timestamp>/`.

**Host isolation** (`GIDR.exe isolate`) blocks all outbound traffic except localhost, preserving the ability to log and investigate while preventing further exfiltration or C2 communication.

---

## Anti-Circumvention

| Feature | What it does |
|---------|-------------|
| **Process DACL** | Restricts the GIDR process handle so non-admin users can't taskkill it |
| **Self-integrity** | Hashes own executable at startup, verifies periodically |
| **Config tamper detection** | Freezes allowlists if config.json is modified at runtime |
| **ETW integrity** | Checks ntdll!EtwEventWrite prologue for RET patches |
| **Debugger detection** | Alerts if a debugger is attached to the GIDR process |
| **Module integrity** | Snapshots loaded DLLs, detects DLL hijacking in install directory |
| **ETW event flow** | Alerts if no process creation events arrive for 5 minutes |

---

## Configuration

Place `config.json` next to `GIDR.exe`. All settings are optional — defaults are sane.

```json
{
  "autoKillThreats": false,
  "autoQuarantine": false,
  "alertThreshold": 50,
  "jsonLogging": true,
  "autoCollectEvidence": true,
  "autoIsolateOnCritical": false,
  "alertEmail": "",
  "exclusionPaths": [],
  "allowlistHashes": [],
  "allowlistPaths": [],
  "allowlistSigners": [],
  "additionalProtectedProcesses": [],
  "extraRulePaths": []
}
```

> `autoKillThreats` and `autoQuarantine` only affect static scan results. Behavioral detections always trigger chain-trace-and-nuke regardless of these settings.

> `autoIsolateOnCritical` will block all outbound traffic when a Critical severity behavioral threat is confirmed. Use with caution in production.

---

## YARA Rules

GIDR ships with 9 YARA rule files in `Rules/`:

| Rule File | What it detects |
|-----------|----------------|
| `c2_frameworks.yar` | Cobalt Strike, Metasploit, Empire, Covenant, PowerSploit |
| `credential_tools.yar` | Mimikatz, pypykatz, LaZagne, procdump LSASS patterns |
| `process_injection.yar` | Shellcode loaders, reflective DLL injection, process hollowing |
| `ransomware.yar` | Shadow copy deletion, crypto API abuse, known ransomware families |
| `persistence.yar` | Registry Run keys, WMI subscriptions, scheduled task abuse, lateral movement |
| `lolbins.yar` | Certutil, bitsadmin, mshta, regsvr32, WMIC, PowerShell obfuscation |
| `amsi_bypass.yar` | AMSI bypass techniques, Defender tampering, event log clearing |
| `exfiltration.yar` | DNS tunneling tools, data staging, cryptominers |
| `malware_generic.yar` | PE import combinations for injection, keylogging, persistence, privilege escalation |

YARA scanning is **informational only** — matches are logged but never trigger auto-response. Add custom rules by placing `.yar` files in `Rules/` or adding paths to `extraRulePaths` in config.json.

---

## Windows Service Mode

GIDR can run as a Windows service for persistent monitoring:

```
# Install as service
sc create GIDR binPath= "C:\path\to\GIDR.exe monitor" start= auto
sc start GIDR

# Remove service
sc stop GIDR
sc delete GIDR
```

---

## Log Files

| File | Content |
|------|---------|
| `Logs/gidr_log.txt` | Main log (all events) |
| `Logs/stability_log.txt` | Startup, shutdown, health checks |
| `Logs/chain_tracer.log` | Full chain trace details |
| `Logs/incidents.log` | Incident response actions (isolation, evidence, tickets) |
| `Logs/network_detections.log` | Network threat detections |
| `Logs/process_monitor.log` | Process creation analysis |
| `Logs/etw_monitor.log` | ETW events and integrity checks |
| `Logs/self_protection.log` | Self-protection events |
| `Logs/ransomware_detections.log` | Ransomware-specific events |
| `Logs/gidr_events.jsonl` | Structured JSON events (for SIEM ingestion) |
| `Evidence/` | Forensic evidence cases (one folder per incident) |

---

## Building

```
# Requires .NET Framework 4.x (csc.exe)
build.cmd

# With code signing
build.cmd sign certificate.pfx password

# With Inno Setup installer
build.cmd installer
```

Output: `bin/GIDR.exe`

---

## Limitations

- No kernel-level visibility — kernel rootkits can hide from user-mode monitoring
- Memory scanner requires sufficient process access rights (run as admin)
- ETW monitoring requires "Audit Process Creation" policy enabled
- Network monitoring is connection-based, not packet-level (can't inspect payload)
- Chain tracing depends on the process still being alive when detected
- Memory dump collection requires dbghelp.dll (not currently bundled)

---

## License & Disclaimer

For authorized defensive, administrative, research, or educational use only.

- Use only on systems where you have explicit permission
- Validate in a test environment before production use
- Provided "AS IS" without warranties of any kind
- Authors are not liable for damages, data loss, or downtime

---

<p align="center"><sub>GIDR v6.3.0 — Built by <strong>Gorstak</strong></sub></p>
