# IPSecPolicy

A PowerShell script to create and assign a Windows IPsec policy that blocks inbound and outbound traffic to common remote access ports (SSH, Telnet, and RDP).

## Overview

This script uses the `netsh` command-line tool to create a legacy IPsec policy compatible with `secpol.msc`. It creates the **GSecurity** policy which blocks:

- **SSH** (port 22)
- **Telnet** (port 23)
- **RDP** (port 3389)

## Features

- Blocks both inbound and outbound traffic for targeted ports
- Uses Windows built-in IPsec framework (no third-party software required)
- Compatible with `secpol.msc` for visual management
- Automatically assigns the policy upon creation
- Cleans up existing policies before creating new ones

## Requirements

- Windows OS with IPsec support
- PowerShell
- Administrator privileges (required for modifying IPsec policies)

## Usage

1. Open PowerShell as Administrator
2. Run the script:

```powershell
.\IPSecPolicy.ps1
```

## What It Does

The script performs the following actions:

1. **Checks for admin privileges** - Exits if not running as Administrator
2. **Removes existing policy** - Deletes any previous "GSecurity" policy
3. **Creates IPsec Policy** - Creates the "GSecurity" policy with description
4. **Creates filter actions** - Defines Block and Permit actions
5. **Creates rules for each port**:
   - Inbound filter list and rule (any source → local machine)
   - Outbound filter list and rule (local machine → any destination)
6. **Assigns the policy** - Activates the policy immediately
7. **Verifies configuration** - Displays the created policy details

## Viewing the Policy

After running the script, you can view and manage the policy in the Windows GUI:

1. Press `Win + R`, type `secpol.msc`, and press Enter
2. Navigate to **Local Policies** → **IP Security Policies on Local Computer**
3. Look for the **GSecurity** policy

## Removing the Policy

To remove the policy, run in an elevated PowerShell:

```powershell
netsh ipsec static delete policy name=GSecurity
```

Or use `secpol.msc` to unassign and delete the policy.

## Disclaimer

**Use at your own risk.** This script modifies system-level IPsec policies that can affect network connectivity. Blocking RDP (port 3389) may prevent remote access to the machine. Ensure you have alternative access methods (physical console, out-of-band management) before running this script. The author is not responsible for any damage, data loss, or lockouts resulting from the use of this software.

## License

MIT
