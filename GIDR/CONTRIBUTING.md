# Contributing to GIDR

Thanks for your interest in contributing. This guide covers how to set up, develop, and submit changes.

## Getting Started

1. Fork and clone the repository
2. Ensure you have .NET Framework 4.x installed (check for `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`)
3. Run `build.cmd` to verify the project compiles
4. Run `bin\GIDR.exe info` to verify the build works

No Visual Studio or SDK is required. Any text editor works.

## Project Architecture

GIDR is a single-executable intrusion detection and response tool built with raw `csc.exe` compilation. All `.cs` files in the project tree are compiled together via `/recurse:*.cs`.

### Key Modules

| Directory | Purpose |
|-----------|---------|
| `Core/` | Configuration, logging, job scheduling, native P/Invoke, threat type definitions |
| `Detection/` | Scheduled detection jobs (process, DLL, persistence, system, hardening) |
| `Engine/` | Scan pipeline engines (PE analysis, YARA, entropy, hash reputation) |
| `Monitors/` | Real-time event watchers (process creation, file changes, network) |
| `Response/` | Automated response actions (quarantine, terminate, block) |
| `Rules/` | YARA rule files |

### Adding a New Detection Job

1. Add your detection method to the appropriate file in `Detection/` (or create a new file)
2. Make it a `public static void` method with no parameters
3. Register it in `Program.cs` inside `CmdMonitor()` using `RegisterJob()`:

```csharp
RegisterJob(scheduler, "MyDetection", new Action(Detection.SystemDetection.MyDetection), 60, ref loaded);
```

The third parameter is the interval in seconds between executions.

4. Use `Logger.Log()` for output and `EdrState.IncrementThreats()` when a threat is found
5. Map your detection to a MITRE ATT&CK technique ID where applicable

### Adding YARA Rules

1. Create a `.yar` file in `Rules/`
2. Follow the existing rule format with metadata (author, description, severity, score, mitre_id)
3. Rules are automatically picked up by the YARA engine at startup

### Coding Style

- Target .NET Framework 4.x — no C# 7+ features (no tuples, pattern matching, local functions)
- Use `string.Format()` instead of string interpolation (`$""`)
- Use explicit types instead of `var`
- Use `for` loops instead of LINQ where performance matters
- Keep methods focused and under 100 lines where practical
- Add XML doc comments (`///`) on public methods
- Log threats with `LogLevel.THREAT`, warnings with `LogLevel.WARN`, actions with `LogLevel.ACTION`

### Trusted Publisher Handling

Signed binaries from trusted publishers (Microsoft, Intel, major AV vendors) have their PE capability scores zeroed out to prevent false positives. If you add new detection logic that analyzes PE capabilities, check `isTrustedPublisher` before adding to the score. See `ScanPipeline.cs` for the pattern.

### Protected Processes

System-critical processes are listed in `Config.cs` under `ProtectedProcesses`. GIDR will refuse to terminate these. If your detection might flag a legitimate Windows process, add it to this list.

## Testing

Run GIDR in monitor mode on a clean system and verify:

- No false positive kills (check Task Manager)
- No self-triggering (honeypot files, own process)
- Warnings are informational, not actionable false positives

For scan testing:

```
bin\GIDR.exe scan C:\Windows\System32 -r --no-action
```

The `--no-action` flag prevents quarantine/termination so you can review verdicts safely.

## Submitting Changes

1. Create a feature branch: `git checkout -b my-detection`
2. Make your changes and verify with `build.cmd`
3. Test in monitor mode on a clean system
4. Submit a pull request with:
   - What the change does
   - Which MITRE ATT&CK techniques it covers (if applicable)
   - How you tested it

## Reporting Issues

When reporting false positives or missed detections, include:

- The full scan output or log entry
- The file/process that was flagged (or should have been)
- Your Windows version (`winver`)
- Whether YARA was enabled (`GIDR.exe info`)
