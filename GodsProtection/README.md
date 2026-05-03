# GodsProtection

A comprehensive PowerShell-based replacement for Windows administrative tools that configures a PC as a secure, single-user home PC with no remote access capabilities. Divine protection for your digital sanctuary.

## Overview

This solution replaces traditional Windows administrative tools (MMC snap-ins, Local Security Policy, Certificate Manager, etc.) with automated PowerShell scripts that:

1. **Initial Configuration**: Hardens the system for home use
2. **Continuous Monitoring**: Watches for unauthorized changes and reverts them automatically

## What It Does

### Security Areas Covered

| Administrative Tool | Script Function | What It Configures |
|---------------------|-----------------|-------------------|
| **Local Security Policy (secpol.msc)** | `Set-HomeSecurityPolicy` | Disables remote desktop, NLA, guest account, audit policies |
| **Services (services.msc)** | `Set-HomeServices` | Disables RDP, Remote Registry, AD services, Azure sync, SMB server |
| **Windows Firewall** | `Set-HomeFirewall` | Blocks all inbound, allows only essential outbound (DNS, DHCP) |
| **Certificate Manager** | `Clear-NonRootCertificates` | Removes all except unexpired root CAs; deletes AD/Azure certs |
| **Local Users & Groups** | `Set-HomeUserConfig` | Disables Guest, removes users from privileged groups |
| **Network Connections** | `Set-HomeNetwork` | Disables unused adapters, removes VPN connections |
| **Scheduled Tasks** | `Set-HomeScheduledTasks` | Disables enterprise/remote tasks, telemetry, cloud sync |
| **Registry Editor** | Embedded in security policy | RDP disable, SMB hardening, UAC settings, protocol security |

### Services Disabled

- **Remote Access**: TermService, RemoteRegistry, RpcLocator, RemoteAccess
- **Active Directory**: NTDS, Netlogon, kdc, ADWS, DFS
- **Azure/Cloud**: AzureADConnectHealthSync, ADSync, MSOnlineServicesSignInAssistant
- **Legacy Networking**: lmhosts, Browser, SSDPSRV, upnphost
- **File Sharing (Server)**: LanmanServer (disabled), LanmanWorkstation (manual)

### Firewall Rules Created

- **Blocked Inbound**: All ports by default
- **Allowed**: DHCP (UDP 68→67), DNS (UDP/TCP 53 outbound)
- **Explicitly Blocked**: RDP (3389), SMB (445, 139), NetBIOS (137-138), WinRM (5985-5986), SSH (22)

### Certificate Cleanup

Removes certificates that are:
- Expired (NotAfter < today)
- Not self-signed (issued by different CA)
- Unknown/untrusted roots (not from major CAs like Microsoft, DigiCert, GlobalSign, etc.)
- AD/Enterprise related (Subject contains "AD", "Domain", "Enterprise", "Corp")
- Azure/Cloud related (Subject contains "Azure", "MS-Organization", "Intune", "Device")
- Client authentication certificates

### Registry Hardening

```
HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections = 1
HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance\fAllowToGetHelp = 0
HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1 = 0
HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous = 1
HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0
```

## Files

| File | Purpose |
|------|---------|
| `GodsProtection.ps1` | **Single script** - installs, configures, and monitors automatically |
| `README.md` | This documentation |

## Quick Start

### Fire and Forget (Default Behavior)

**Simply run the script with no switches:**

```powershell
# Run as Administrator
.\GodsProtection.ps1
```

This **single command** will:
1. ✅ Run initial security hardening
2. ✅ Install scheduled tasks for automatic monitoring
3. ✅ Monitor every 5 minutes
4. ✅ Revert unauthorized changes automatically
5. ✅ Run at every system startup

**That's it. You're protected.**

### Uninstall

To remove GodsProtection:

```powershell
.\GodsProtection.ps1 -Uninstall
```

## Usage

| Command | What It Does |
|---------|--------------|
| `.\GodsProtection.ps1` | **Install and enable monitoring** (default, fire-and-forget) |
| `.\GodsProtection.ps1 -Uninstall` | Remove scheduled tasks and stop monitoring |

That's the entire interface. No other switches needed.

## Monitoring Behavior

When running in watchdog mode, the script:

1. **Captures a baseline** of:
   - Service states (disabled services should stay disabled)
   - Firewall rules
   - Local user accounts
   - Critical registry settings

2. **Every X minutes**, checks for:
   - Services that were re-enabled
   - New firewall rules allowing inbound
   - New user accounts
   - Registry changes that enable remote access
   - New certificates from AD/Azure

3. **Automatically reverts** any violations by:
   - Re-disabling services
   - Re-applying firewall rules
   - Removing unauthorized users
   - Re-applying registry settings
   - Re-running full certificate cleanup

## Log File

All actions are logged to: `C:\HomePC_SecurityLog.txt`

Example output:
```
[2026-05-03 12:30:00] [INFO] Starting Home PC Security Lockdown
[2026-05-03 12:30:01] [INFO] Configuring Local Security Policy for home PC...
[2026-05-03 12:30:05] [INFO] Disabled service: TermService
[2026-05-03 12:30:05] [INFO] Disabled service: RemoteRegistry
[2026-05-03 12:30:12] [INFO] Removed certificate: CN=Corp-AD-CA (AD/Enterprise certificate)
[2026-05-03 12:30:15] [INFO] Firewall configured - inbound blocked, essential outbound allowed
[2026-05-03 12:35:00] [WARN] Found 1 configuration violations!
[2026-05-03 12:35:01] [INFO] Restored service TermService to disabled state
```

## Management

### Check if Watchdog is Running

```powershell
Get-ScheduledTask | Where-Object { $_.TaskName -like "*GodsProtection*" }
```

### Stop/Start the Watchdog

```powershell
# Stop monitoring
Stop-ScheduledTask -TaskName "GodsProtection-Watchdog"

# Start monitoring again
Start-ScheduledTask -TaskName "GodsProtection-Watchdog"
```

### Completely Remove

```powershell
.\GodsProtection.ps1 -Uninstall
```

Or manually:
```powershell
Unregister-ScheduledTask -TaskName "GodsProtection-Watchdog" -Confirm:$false
Unregister-ScheduledTask -TaskName "GodsProtection-Startup" -Confirm:$false
```

## Security Considerations

### What This Breaks

This script is designed for a **pure home/single-user PC**. It will break:

- **Remote Desktop** (intentionally disabled)
- **File/Printer Sharing** (SMB server disabled)
- **HomeGroup/Network Discovery** (disabled)
- **VPN connections** (removed)
- **Active Directory domain join** (prevents/cleans up)
- **Azure AD join/registration** (prevented)
- **Windows Remote Management/WinRM** (firewall blocked)
- **PowerShell Remoting** (firewall blocked)
- **SSH Server** (firewall blocked)

### What Stays Working

- Internet browsing (HTTP/HTTPS outbound)
- Windows Updates
- Local software installation
- USB devices
- Audio/video
- Gaming
- Local file operations

### Before Running

1. **Ensure you have local admin access** - The script requires elevation
2. **Don't run on work/domain PCs** - This will break domain connectivity
3. **Create a system restore point** (optional but recommended):
   ```powershell
   Checkpoint-Computer -Description "Before GodsProtection" -RestorePointType "MODIFY_SETTINGS"
   ```

### Reverting Changes

To restore default Windows settings:

1. **System Restore**: Use a restore point created before running
2. **Manual Revert**: Use `secedit /configure` with `defltwk.inf` (default security template)
3. **Services**: Manually re-enable services via `services.msc`
4. **Firewall**: Reset to defaults: `netsh advfirewall reset`
5. **Certificates**: Import from backup or let Windows rebuild

## Customization

### Keep Additional Services

Edit `GodsProtection.ps1`, find `$servicesToDisable` array, and remove services you want to keep.

### Allow Specific Inbound Ports

After running the script, add your own firewall rules:

```powershell
# Example: Allow a game server on port 27015
New-NetFirewallRule -DisplayName "Game Server" -Direction Inbound -Protocol TCP -LocalPort 27015 -Action Allow
```

Note: The watchdog will not remove custom rules unless they conflict with blocked ports.

### Keep Certain Certificates

Edit the `Clear-NonRootCertificates` function and add subjects to the trusted patterns:

```powershell
elseif ($cert.Issuer -notmatch "Microsoft|DigiCert|GlobalSign|YOUR-CA-HERE") {
```

## Troubleshooting

### Script won't run

```powershell
# Check execution policy
Get-ExecutionPolicy

# Set to allow scripts (requires admin)
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
```

### Services won't disable

Some services are protected. The script logs warnings but continues. Check the log file.

### Can't access file shares after

Intentional - SMB server is disabled. To re-enable temporarily:

```powershell
Set-Service -Name LanmanServer -StartupType Manual
Start-Service LanmanServer
```

### Network issues

The script is aggressive about disabling network features. If you have connectivity issues:

1. Check `C:\GodsProtection_Log.txt` for what was disabled
2. Re-enable specific adapters or services as needed
3. Consider running with `-OneTime` only (no watchdog)

## Technical Details

### State File

The baseline is stored at: `C:\GodsProtection_State.json`

This JSON file contains hashes and states of monitored items.

### Scheduled Task Details

The script creates two tasks:

**GodsProtection-Watchdog**
- Runs every 5 minutes
- Executes as SYSTEM
- Hidden window
- Runs with highest privileges

**GodsProtection-Startup**
- Runs at system boot
- One-time configuration at startup

### Compatibility

- **Windows 10/11**: Yes
- **Windows 10/11 Home**: Yes (most features work)
- **Windows 10/11 Pro/Enterprise**: Yes (all features work)
- **Windows Server**: Not recommended
- **Domain-joined PCs**: Will break domain connectivity

## License

Use at your own risk. This is a security hardening script designed for personal use on home PCs.

## Support

This is a standalone script. For issues:
1. Check the log file: `C:\GodsProtection_Log.txt`
2. Review what was changed in the script functions
3. Manually revert specific changes as needed
