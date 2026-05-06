# Changelog

## v6.3.0 — GIDR (Gorstaks Intrusion Detection and Response)

### Fixes & Wiring
- Added missing `Config.Version`, `Config.EvidencePath`, `Config.AlertEmail`, `Config.Get()`, `Config.GetBool()`, and `Config.Set()` — resolves compilation errors in `IncidentResponse.cs`
- `FileMonitor` now properly initialized and shut down in `GIDRMonitor`; `CleanupCache` job registered on 5-minute interval
- `EtwMonitor.IntegrityCheck` now scheduled every 2 minutes
- `EvidencePath` added to `Config.EnsureDirectories()`
- `IncidentResponseConfig` cleaned up to use proper `Config` members

### Added
- Full YARA rule set (9 files) added to `Rules/`: `c2_frameworks`, `ransomware`, `credential_tools`, `process_injection`, `persistence`, `lolbins`, `exfiltration`, `amsi_bypass`, `malware_generic`

---

## v6.2.0 — GIDR (Gorstaks Intrusion Detection and Response)

**Complete paradigm shift from antivirus to intrusion detection and response.**

### Breaking Changes
- Renamed from GEdr to GIDR across the entire codebase
- Binary renamed from `GEdr.exe` to `GIDR.exe`
- Namespace changed from `GEdr.*` to `GIDR.*`
- All log files, PID files, and service names updated

### New: Behavioral-Only Response
- Static file analysis (entropy, imports, signatures) **never triggers auto-response**
- Only runtime behavioral detections trigger the response engine
- Files are innocent until a process is caught doing something malicious

### New: Chain Tracer (`ChainTracer.cs`)
- When a behavioral threat is detected, traces the full process tree to the attack root
- Kills every process in the attack chain (leaves first, then parents)
- Quarantines attacker executables (skips system binaries like cmd.exe, powershell.exe)
- Hunts and removes persistence (Run keys, scheduled tasks, startup folder)
- Blocks all outbound IPs from the attack chain via firewall rules

### New: Autonomous Malware Detection
- NetworkMonitor now correlates TCP connections to owning PIDs
- Detects unknown processes with outbound connections from suspicious paths
- Catches RATs, cryptominers, backdoors, and data stealers that phone home without user interaction
- Reverse shell detection: cmd/powershell with outbound connections to non-standard ports

### New: Enhanced Network Monitor
- Process-to-connection mapping via netstat PID correlation
- Legitimate process allowlist (browsers, Steam, Discord, dev tools, etc.)
- Improved beacon detection with per-process tracking
- DNS tunneling detection from non-system processes

### Changed: Response Engine
- `ResponseEngine.ProcessThreat()` now classifies threats as behavioral vs. static
- Only behavioral threats trigger `ChainTracer.TraceAndNuke()`
- Static scan verdicts are logged but never acted on
- All inline `ThreatActions` calls removed from monitors and detection modules
- All response flows through `ResponseEngine` → `ChainTracer`

### Changed: ScanPipeline
- `IsTrustedSigner()` now checks config's `allowlistSigners` (not just hardcoded list)
- Early path allowlist check before scoring (prevents false positive scoring entirely)

### Changed: Config
- `autoKillThreats` and `autoQuarantine` default to `false`
- These settings only affect static scan results
- Behavioral response is always enabled regardless of config

### Removed
- No more inline `ThreatActions.TerminateProcess()` calls in ProcessMonitor, FileMonitor, EtwMonitor, or detection modules
- No more static-scan-triggered quarantine

## v6.0.0

- Initial C# rewrite from PowerShell
- Multi-engine scan pipeline (hash, signature, PE analysis, YARA, entropy, AMSI)
- Real-time monitoring (WMI events, ETW, FileSystemWatcher)
- Self-protection (DACL, integrity, debugger detection, ETW tamper check)
- Job scheduler for periodic detection modules
- Windows service mode support
