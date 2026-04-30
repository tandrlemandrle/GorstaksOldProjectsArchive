# Changelog

## [2.0.0] - 2026-04-28

### Scan Engines
- Multi-engine scan pipeline: hash reputation, Authenticode, CAPA-like PE analysis, YARA, entropy
- Direct syscall stub detection (SysWhispers, HellsGate, D/Invoke patterns in PE .text sections)
- AMSI integration with tamper detection and auto-repair
- LOLBin identification (30+ binaries) that fires even for trusted publishers
- Renamed binary detection via PE OriginalFilename vs process name
- Scan result caching (ConcurrentDictionary, 30-min TTL, file-write-time keyed)
- File size limit (skip >100 MB files)
- File access retry (3 attempts with 200ms delay on sharing violations)

### Real-Time Monitoring
- ETW process creation via Security Event 4688 (zero-gap, supplements WMI)
- ETW process exit tracking via Security Event 4689
- WMI process events with polling fallback
- FileSystemWatcher on all fixed drives with ransomware rename detection
- Network beacon pattern detection

### Detection Jobs (55 total)
- Process: hollowing, token manipulation, parent-child chains, PPID spoofing, fileless, memory scanning, short-lived process detection, command-line entropy analysis, process auditing
- DLL: hijacking, reflective injection, keystroke injection, browser DLL monitoring
- Persistence: registry, scheduled tasks, WMI subscriptions, startup folder
- System: rootkit, BYOVD (13+ drivers, any-path WMI scanning), driver monitoring, BCD, services, firewall, event logs, USB, clipboard, shadow copies, DNS exfiltration, proxy, script host, credentials, honeypots, lateral movement, data exfiltration, quarantine management
- Hardening: CVE mitigation, ASR rules, DNS security, C2 block lists, COM monitoring, browser extensions
- Named pipes: Cobalt Strike, Metasploit, Sliver, Brute Ratel, Mimikatz, PsExec (20+ patterns)
- Self-protection: AMSI integrity (auto-repair), ETW integrity, service tamper detection

### Anti-Tamper & Self-Protection
- Process DACL hardening (non-admin terminate blocked)
- AMSI prologue verification with auto-restore on patch detection
- ETW event flow heartbeat + ntdll!EtwEventWrite prologue check
- Config tamper lockout (allowlists frozen if config.json modified at runtime)
- DLL hijack detection (modules loaded from install directory)
- Loaded module hash verification (every 5 minutes)
- Executable integrity monitoring (SHA256 every 30 seconds)
- Debugger attachment detection
- Service tamper detection (sc stop/delete/config targeting GEdr or security services)

### Response
- Auto-quarantine, process termination, IP blocking
- Dry-run mode (--dry-run) for safe tuning
- Quarantine management: list, restore, purge commands
- Service auto-restart on crash (10s/30s/60s recovery)

### CLI & Usability
- `--version` / `-v` flag
- `--quiet` / `--verbose` global flags
- `--output-json` for scan results
- `--dry-run` for monitor mode
- `--no-delay` to skip startup delay
- `config` command to generate default config.json
- `restore` command for quarantine management
- `report` command for 24-hour threat summary
- `health` command for system health check
- Admin check at startup with clear error message
- Scan progress with files/sec rate and running counts
- Global crash handler with crash log

### Configuration
- config.json support for all tunable settings
- Allowlisting by SHA256 hash, file path, certificate signer
- Extra YARA rule directories
- Additional protected processes
- Scan exclusion paths
- JSON structured logging toggle

### Logging
- Structured JSON logging (gedr_events.jsonl) for SIEM ingestion
- Rolling log files (5 MB × 5 rotations)
- Hourly heartbeat events
- JSON report generation

### Installer
- InnoSetup with service registration (checked by default)
- Service crash recovery (10s/30s/60s)
- Windows Defender exclusion
- Defender passive mode option
- Windows Security Center registration
- YARA bootstrap
- Default config.json generation
- Clean uninstall (service, exclusions, Defender restore)

### Documentation
- README with full feature documentation and MITRE ATT&CK mapping
- CONTRIBUTING.md with coding style and detection development guide
- CHANGELOG.md
- GPL-3.0 license
- Example config.json and EICAR test script

### YARA Rules (9 rule sets)
- amsi_bypass.yar, c2_frameworks.yar, credential_tools.yar
- exfiltration.yar, lolbins.yar, malware_generic.yar
- persistence.yar, process_injection.yar, ransomware.yar
