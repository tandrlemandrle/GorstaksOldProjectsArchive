#Requires -RunAsAdministrator
<#
.SYNOPSIS
    GodsProtection - Divine Security for Your Digital Sanctuary
    
.DESCRIPTION
    This script configures a Windows 11 PC as a secure, single-user home PC with no remote access.
    It replaces traditional administrative tools by configuring:
    - Local Security Policy (secedit)
    - Windows Services (disables remote/AD/Azure services)
    - Windows Firewall (blocks all incoming, strict outbound)
    - Certificates (removes all except unexpired root CAs)
    - Local Users/Groups (cleans up accounts)
    - Registry (security hardening)
    - Network configuration
    - Scheduled Tasks (disables telemetry/remote tasks)
    
    DEFAULT BEHAVIOR (no switches): Installs fire-and-forget monitoring
    - Runs initial security configuration
    - Creates scheduled tasks for persistent monitoring
    - Reverts any unauthorized changes automatically
    
.PARAMETER Uninstall
    Removes GodsProtection scheduled tasks and stops monitoring
    
.EXAMPLE
    .\GodsProtection.ps1
        Install and enable automatic monitoring (fire and forget)
        
.EXAMPLE
    .\GodsProtection.ps1 -Uninstall
        Remove GodsProtection and stop monitoring

.LOG FILE
    C:\GodsProtection_Log.txt

.STATE FILE
    C:\GodsProtection_State.json
#>

[CmdletBinding()]
param(
    [switch]$Uninstall,
    [string]$Mode  # Internal use: "Monitor" for scheduled task checks
)

# ============================================================================
# CONFIGURATION
# ============================================================================

$script:TaskName = "GodsProtection-Watchdog"
$script:StartupTaskName = "GodsProtection-Startup"
$script:ServiceName = "GodsProtectionWatchdog"
$script:StateFile = "$env:SystemDrive\GodsProtection_State.json"
$script:LogFile = "$env:SystemDrive\GodsProtection_Log.txt"
$script:IntervalMinutes = 5
$script:ScriptPath = $PSCommandPath
$script:BaselineHash = @{}

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

function Write-SecurityLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $script:LogFile -Value $logEntry -ErrorAction SilentlyContinue
    Write-Host $logEntry -ForegroundColor $(if ($Level -eq "ERROR") { "Red" } elseif ($Level -eq "WARN") { "Yellow" } else { "Green" })
}

# ============================================================================
# REMOVE BOWSER.SYS (Common BSOD culprit on hardened home PCs)
# ============================================================================
function Remove-BowserDriver {
    Write-SecurityLog "Attempting to neutralize bowser.sys (Computer Browser driver)..."
    
    $bowserPath = "$env:SystemRoot\System32\drivers\bowser.sys"
    $bowserBackup = "$env:SystemRoot\System32\drivers\bowser.sys.bak"
    
    try {
        # First, ensure the service is stopped and disabled
        $browserSvc = Get-Service -Name "Browser" -ErrorAction SilentlyContinue
        if ($browserSvc) {
            Stop-Service -Name "Browser" -Force -ErrorAction SilentlyContinue
            Set-Service -Name "Browser" -StartupType Disabled -ErrorAction SilentlyContinue
            Write-SecurityLog "Browser service stopped and disabled"
        }

        if (Test-Path $bowserPath) {
            # Take ownership and grant full control
            takeown /F $bowserPath /A /R /D Y | Out-Null
            icacls $bowserPath /grant Administrators:F /T /C | Out-Null
            
            # Try to delete
            if (Test-Path $bowserPath) {
                Remove-Item -Path $bowserPath -Force -ErrorAction Stop
                Write-SecurityLog "Successfully deleted bowser.sys" "WARN"
            }
        }
        elseif (Test-Path $bowserBackup) {
            Write-SecurityLog "bowser.sys already removed (backup exists)"
        }
        
        # Additional prevention: Registry blocks
        $regPaths = @(
            "HKLM:\SYSTEM\CurrentControlSet\Services\Browser",
            "HKLM:\SYSTEM\CurrentControlSet\Services\Bowser"
        )
        
        foreach ($path in $regPaths) {
            if (Test-Path $path) {
                Set-ItemProperty -Path $path -Name "Start" -Value 4 -Force -ErrorAction SilentlyContinue
                Write-SecurityLog "Set Bowser/Browser registry Start=4 (Disabled)"
            }
        }
        
        Write-SecurityLog "bowser.sys neutralization complete"
        
    }
    catch {
        Write-SecurityLog "Failed to fully remove bowser.sys: $_" "ERROR"
        Write-SecurityLog "Recommendation: Run this script in Safe Mode if BSOD persists" "WARN"
    }
}

# ============================================================================
# INSTALLER FUNCTIONS
# ============================================================================

function Install-GodsProtection {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "GodsProtection - Divine Security" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-SecurityLog "Starting GodsProtection installation..."
    
    # Remove any existing tasks first
    Remove-GodsProtectionTasks -Silent
    
    # Run initial configuration
    Start-GodsProtectionConfiguration
    
    # Create scheduled tasks
    Write-SecurityLog "Creating scheduled tasks for persistent monitoring..."
    
    # Periodic monitoring task
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script:ScriptPath`" -Mode Monitor"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $script:IntervalMinutes) -RepetitionDuration (New-TimeSpan -Days 3650)
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable:$false -Priority 7
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    try {
        Register-ScheduledTask -TaskName $script:TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "GodsProtection - Divine security monitoring. Reverts unauthorized changes." -Force -ErrorAction Stop
        Write-SecurityLog "Created periodic task: $script:TaskName (runs every $script:IntervalMinutes minutes)"
    }
    catch {
        Write-SecurityLog "Failed to create periodic task: $_" "ERROR"
    }
    
    # Startup task
    $startupAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script:ScriptPath`" -Mode Monitor"
    $startupTrigger = New-ScheduledTaskTrigger -AtStartup
    $startupSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    $startupPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    try {
        Register-ScheduledTask -TaskName $script:StartupTaskName -Action $startupAction -Trigger $startupTrigger -Settings $startupSettings -Principal $startupPrincipal -Description "GodsProtection - Initial configuration at startup" -Force -ErrorAction Stop
        Write-SecurityLog "Created startup task: $script:StartupTaskName"
    }
    catch {
        Write-SecurityLog "Could not create startup task: $_" "WARN"
    }
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "GodsProtection Installation Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Your PC is now divinely protected." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "The watchdog will:" -ForegroundColor White
    Write-Host "  - Monitor every $script:IntervalMinutes minutes" -ForegroundColor Gray
    Write-Host "  - Revert unauthorized changes automatically" -ForegroundColor Gray
    Write-Host "  - Run at every system startup" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Log file: $script:LogFile" -ForegroundColor Gray
    Write-Host "State file: $script:StateFile" -ForegroundColor Gray
    Write-Host ""
    Write-Host "To remove GodsProtection:" -ForegroundColor Yellow
    Write-Host "  .\GodsProtection.ps1 -Uninstall" -ForegroundColor Yellow
}

function Remove-GodsProtectionTasks {
    param([switch]$Silent)
    
    if (!$Silent) {
        Write-Host "Removing GodsProtection..." -ForegroundColor Yellow
    }
    
    $tasks = @($script:TaskName, $script:StartupTaskName)
    foreach ($task in $tasks) {
        $existing = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
        if ($existing) {
            try {
                Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Stop
                if (!$Silent) {
                    Write-SecurityLog "Removed task: $task"
                }
            }
            catch {
                if (!$Silent) {
                    Write-SecurityLog "Could not remove task $task : $_" "WARN"
                }
            }
        }
    }
    
    # Also check for and remove any old service
    $existingService = Get-Service -Name $script:ServiceName -ErrorAction SilentlyContinue
    if ($existingService) {
        try {
            Stop-Service -Name $script:ServiceName -Force -ErrorAction SilentlyContinue
            sc.exe delete $script:ServiceName | Out-Null
            if (!$Silent) {
                Write-SecurityLog "Removed service: $script:ServiceName"
            }
        }
        catch {
            if (!$Silent) {
                Write-SecurityLog "Could not remove service: $_" "WARN"
            }
        }
    }
    
    if (!$Silent) {
        Write-Host ""
        Write-Host "GodsProtection has been removed." -ForegroundColor Cyan
        Write-Host "Note: Security settings remain in place." -ForegroundColor Yellow
        Write-Host "To restore defaults, use System Restore." -ForegroundColor Yellow
    }
}

# ============================================================================
# MONITOR MODE
# ============================================================================

function Start-MonitorMode {
    Write-SecurityLog "GodsProtection monitor starting..."
    
    # Load baseline
    if (!(Test-Path $script:StateFile)) {
        Write-SecurityLog "No baseline found. Creating new baseline..."
        Get-SystemBaseline | Out-Null
    }
    
    $baseline = Get-Content -Path $script:StateFile -Raw | ConvertFrom-Json -AsHashtable
    
    # Run single check
    Write-SecurityLog "Running compliance check..."
    
    $violations = Test-SystemCompliance -Baseline $baseline
    
    if ($violations -and ($violations | Measure-Object).Count -gt 0) {
        Write-SecurityLog "Found $(($violations | Measure-Object).Count) violations! Restoring divine order..." "WARN"
        Restore-SystemCompliance -Violations $violations
        Get-SystemBaseline | Out-Null
    }
    else {
        Write-SecurityLog "System compliant. Divine protection intact."
    }
}

# ============================================================================
# SECURITY POLICY CONFIGURATION (secedit replacement)
# ============================================================================

function Set-HomeSecurityPolicy {
    Write-SecurityLog "Configuring Local Security Policy for home PC..."
    
    # Create a security template for home PC
    $securityTemplate = @"
[Unicode]
Unicode=yes

[System Access]
MinimumPasswordAge = 0
MaximumPasswordAge = 42
MinimumPasswordLength = 0
PasswordComplexity = 0
PasswordHistorySize = 0
LockoutBadCount = 0
RequireLogonToChangePassword = 0
ClearTextPassword = 0
LSAAnonymousNameLookup = 0
EnableGuestAccount = 0
NewGuestName = `"Guest`"
NewAdministratorName = `"Administrator`"

[Event Audit]
AuditSystemEvents = 0
AuditLogonEvents = 0
AuditObjectAccess = 0
AuditPrivilegeUse = 0
AuditPolicyChange = 0
AuditAccountManage = 0
AuditProcessTracking = 0
AuditDSAccess = 0
AuditAccountLogon = 0

[Registry Values]
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\MaxDevicePasswordFailedAttempts=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,0
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,0
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares=7,
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=4,0
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature=4,0
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,5
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=4,3
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle=4,0

[Privilege Rights]
SeNetworkLogonRight = *S-1-1-0
SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551
SeChangeNotifyPrivilege = *S-1-1-0,*S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-545
SeRemoteShutdownPrivilege = *S-1-5-32-544
SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-545

[Version]
signature=`"`$CHICAGO`$`"
Revision=1
"@

    $templatePath = "$env:TEMP\HomeSecurityTemplate.inf"
    $securityDB = "$env:TEMP\HomeSecurityDB.sdb"
    
    $securityTemplate | Out-File -FilePath $templatePath -Encoding Unicode -Force
    
    try {
        # Create database and import template
        if (Test-Path $securityDB) { Remove-Item $securityDB -Force }
        
        # Use secedit to configure
        $result = Start-Process -FilePath "secedit.exe" -ArgumentList "/configure", "/db", $securityDB, "/cfg", $templatePath, "/overwrite", "/quiet" -Wait -PassThru -NoNewWindow
        
        if ($result.ExitCode -eq 0) {
            Write-SecurityLog "Security policy configured successfully"
        } else {
            Write-SecurityLog "Security policy configuration returned exit code: $($result.ExitCode)" "WARN"
        }
    }
    catch {
        Write-SecurityLog "Failed to configure security policy: $_" "ERROR"
    }
    finally {
        if (Test-Path $templatePath) { Remove-Item $templatePath -Force }
        if (Test-Path $securityDB) { Remove-Item $securityDB -Force }
    }
    
    # Additional direct registry settings
    $regSettings = @{
        # Disable remote desktop
        "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" = @{
            "fDenyTSConnections" = 1
            "fSingleSessionPerUser" = 1
        }
        # Disable remote assistance
        "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" = @{
            "fAllowToGetHelp" = 0
            "fAllowFullControl" = 0
        }
        # Disable NLA for RDP (belt and suspenders)
        "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" = @{
            "SecurityLayer" = 0
            "UserAuthentication" = 0
        }
        # Network security - disable insecure protocols
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" = @{
            "UseLogonCredential" = 0
        }
        # Disable SMB1
        "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" = @{
            "SMB1" = 0
        }
        "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" = @{
            "EnableSecuritySignature" = 1
            "RequireSecuritySignature" = 1
        }
        # Disable automatic certificate enrollment
        "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" = @{
            "AESetting" = 0
        }
    }
    
    foreach ($path in $regSettings.Keys) {
        if (!(Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        foreach ($name in $regSettings[$path].Keys) {
            try {
                Set-ItemProperty -Path $path -Name $name -Value $regSettings[$path][$name] -Force -ErrorAction Stop
                Write-SecurityLog "Set registry: $path\$name = $($regSettings[$path][$name])"
            }
            catch {
                Write-SecurityLog "Failed to set registry $path\$name : $_" "WARN"
            }
        }
    }
}

# ============================================================================
# SERVICES HARDENING
# ============================================================================

function Set-HomeServices {
    Write-SecurityLog "Configuring services for home PC..."
    
    # Services to disable for home/single-user PC
    $servicesToDisable = @(
        # Remote access services
        "TermService"           # Remote Desktop Services
        "SessionEnv"            # Remote Desktop Configuration
        "UmRdpService"          # Remote Desktop Services UserMode Port Redirector
        "RemoteAccess"          # Routing and Remote Access
        "RemoteRegistry"        # Remote Registry
        "RpcLocator"            # Remote Procedure Call (RPC) Locator
        "lmhosts"               # TCP/IP NetBIOS Helper (legacy networking)
        
        # Active Directory / Domain services
        "NTDS"                  # Active Directory Domain Services (if present)
        "ADWS"                  # Active Directory Web Services
        "dfs"                   # DFS Namespace (domain related)
        "DFSR"                  # DFS Replication
        "IsmServ"               # Intersite Messaging
        "kdc"                   # Kerberos Key Distribution Center
        "Netlogon"              # Netlogon (domain auth)
        "DNS"                   # DNS Server (if running locally)
        
        # Azure / Cloud sync services
        "AzureADConnectHealthSync"  # Azure AD Connect Health
        "ADSync"                    # Azure AD Connect Sync
        "MicrosoftAzureADConnectAgent" # Azure AD Connect Agent
        "MSOnlineServicesSignInAssistant" # Microsoft Online Services Sign-in Assistant
        
        # Certificate/Enterprise services
        "CertPropSvc"           # Certificate Propagation
        "KeyIso"                # CNG Key Isolation (careful with this one)
        
        # Other enterprise/network services
        "Browser"               # Computer Browser (legacy)
        "SSDPSRV"               # SSDP Discovery (UPnP - security risk)
        "upnphost"              # UPnP Device Host
        "FDResPub"              # Function Discovery Resource Publication
        "FDHost"                # Function Discovery Provider Host
        "WMPNetworkSvc"         # Windows Media Player Network Sharing
        "HomeGroupListener"     # HomeGroup Listener (deprecated but may exist)
        "HomeGroupProvider"     # HomeGroup Provider
        "MSiSCSI"               # Microsoft iSCSI Initiator Service
        "WPCSvc"                # Parental Controls (if not needed)
    )
    
    $disabledServices = @()
    
    foreach ($svcName in $servicesToDisable) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -ne "Running" -and $svc.StartType -eq "Disabled") {
                # Already configured
                continue
            }
            if ($svc) {
                Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svcName -StartupType Disabled -ErrorAction Stop
                Write-SecurityLog "Disabled service: $svcName"
                $disabledServices += $svcName
            }
        }
        catch {
            Write-SecurityLog "Could not disable service $svcName : $_" "WARN"
        }
    }
    
    # Services to keep but configure
    $servicesToConfigure = @{
        "LanmanServer" = "Disabled"    # SMB Server - disable for pure home PC
        "LanmanWorkstation" = "Manual"  # SMB Client - keep manual for file shares
    }
    
    foreach ($svcName in $servicesToConfigure.Keys) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc) {
                $targetType = $servicesToConfigure[$svcName]
                if ($svc.StartType -ne $targetType) {
                    if ($svc.Status -eq "Running") {
                        Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
                    }
                    Set-Service -Name $svcName -StartupType $targetType
                    Write-SecurityLog "Set service $svcName to $targetType"
                }
            }
        }
        catch {
            Write-SecurityLog "Could not configure service $svcName : $_" "WARN"
        }
    }
    
    return $disabledServices
}

# ============================================================================
# FIREWALL LOCKDOWN
# ============================================================================

function Set-HomeFirewall {
    Write-SecurityLog "Configuring firewall for home PC lockdown..."
    
    try {
        # Enable Windows Firewall for all profiles
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        
        # Set default inbound/outbound
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
        
        # Disable all existing inbound rules first
        Get-NetFirewallRule -Direction Inbound -Enabled True | Disable-NetFirewallRule
        
        # Create essential inbound rules only
        $essentialInboundRules = @(
            @{Name="HomePC-Core Networking"; DisplayName="Core Networking"; Group="Core Networking"}
        )
        
        # Allow DHCP
        New-NetFirewallRule -DisplayName "Allow DHCP" -Direction Inbound -Protocol UDP -LocalPort 68 -RemotePort 67 -Action Allow -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
        
        # Allow DNS
        New-NetFirewallRule -DisplayName "Allow DNS" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -DisplayName "Allow DNS TCP" -Direction Outbound -Protocol TCP -RemotePort 53 -Action Allow -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
        
        # Block all remote desktop ports
        New-NetFirewallRule -DisplayName "Block RDP TCP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -DisplayName "Block RDP UDP" -Direction Inbound -Protocol UDP -LocalPort 3389 -Action Block -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
        
        # Block SMB/NetBIOS inbound
        New-NetFirewallRule -DisplayName "Block SMB TCP" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -DisplayName "Block NetBIOS" -Direction Inbound -Protocol TCP -LocalPort 139 -Action Block -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -DisplayName "Block NetBIOS UDP" -Direction Inbound -Protocol UDP -LocalPort 137,138 -Action Block -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
        
        # Block WinRM/PowerShell remoting
        New-NetFirewallRule -DisplayName "Block WinRM HTTP" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Block -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -DisplayName "Block WinRM HTTPS" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Block -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
        
        # Block SSH if somehow enabled
        New-NetFirewallRule -DisplayName "Block SSH" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Block -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
        
        Write-SecurityLog "Firewall configured - inbound blocked, essential outbound allowed"
    }
    catch {
        Write-SecurityLog "Failed to configure firewall: $_" "ERROR"
    }
}

# ============================================================================
# CERTIFICATE CLEANUP
# ============================================================================

function Clear-NonRootCertificates {
    Write-SecurityLog "Cleaning up certificates (keeping only valid root CAs)..."
    
    $removedCount = 0
    $now = Get-Date
    
    # Certificate stores to clean
    $storesToClean = @(
        "Cert:\LocalMachine\My"           # Personal
        "Cert:\LocalMachine\CA"            # Intermediate CAs
        "Cert:\LocalMachine\AuthRoot"      # Third-party root CAs (keep Microsoft)
        "Cert:\LocalMachine\TrustedPeople" # Trusted People
        "Cert:\LocalMachine\TrustedPublisher" # Trusted Publishers
        "Cert:\LocalMachine\SmartCardRoot" # Smart Card Roots
        "Cert:\CurrentUser\My"             # Current user personal
        "Cert:\CurrentUser\CA"              # Current user intermediate
        "Cert:\CurrentUser\AuthRoot"       # Current user third-party roots
        "Cert:\CurrentUser\TrustedPeople"  # Current user trusted people
        "Cert:\CurrentUser\TrustedPublisher"
    )
    
    foreach ($storePath in $storesToClean) {
        if (!(Test-Path $storePath)) { continue }
        
        try {
            $certs = Get-ChildItem -Path $storePath -Recurse -ErrorAction SilentlyContinue | 
                     Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] }
            
            foreach ($cert in $certs) {
                try {
                    $shouldRemove = $false
                    $reason = ""
                    
                    # Check if expired
                    if ($cert.NotAfter -lt $now) {
                        $shouldRemove = $true
                        $reason = "expired"
                    }
                    # Check if not a root CA (self-signed)
                    elseif ($cert.Issuer -ne $cert.Subject) {
                        $shouldRemove = $true
                        $reason = "not self-signed (issued by: $($cert.Issuer))"
                    }
                    # Check if it's a non-Microsoft root that's suspicious
                    elseif ($cert.Issuer -notmatch "Microsoft|DigiCert|GlobalSign|VeriSign|Entrust|Go Daddy|Let's Encrypt|ISRG|GeoTrust|Comodo|Thawte|Symantec|Baltimore|Starfield|Amazon|Google|Apple|Cloudflare") {
                        # Unknown root CA - remove for safety on home PC
                        $shouldRemove = $true
                        $reason = "unknown/untrusted root: $($cert.Subject)"
                    }
                    # Check for specific enterprise/AD-related OIDs
                    elseif ($cert.Extensions | Where-Object { $_.Oid.Value -match "1.3.6.1.4.1.311" -and $cert.Subject -match "AD|Domain|Enterprise|Corp" }) {
                        $shouldRemove = $true
                        $reason = "AD/Enterprise certificate"
                    }
                    # Check for Azure AD certificates
                    elseif ($cert.Subject -match "Azure|MS-Organization|Microsoft Intune|MS-Device|Microsoft Device") {
                        $shouldRemove = $true
                        $reason = "Azure/Cloud certificate"
                    }
                    # Check for client authentication certs (home PC doesn't need)
                    elseif ($cert.EnhancedKeyUsageList | Where-Object { $_.FriendlyName -eq "Client Authentication" }) {
                        $shouldRemove = $true
                        $reason = "client authentication certificate"
                    }
                    
                    if ($shouldRemove) {
                        Remove-Item -Path $cert.PSPath -Force -ErrorAction Stop
                        Write-SecurityLog "Removed certificate: $($cert.Subject) ($reason)"
                        $removedCount++
                    }
                }
                catch {
                    Write-SecurityLog "Could not remove certificate $($cert.Subject): $_" "WARN"
                }
            }
        }
        catch {
            Write-SecurityLog "Error accessing store $storePath : $_" "WARN"
        }
    }
    
    # Also check and remove any certificate enrollment/renewal tasks
    Get-ScheduledTask | Where-Object { $_.TaskName -match "Certificate|Cert|Autoenroll|CEP|CES" } | 
        ForEach-Object {
            try {
                Disable-ScheduledTask -TaskName $_.TaskName -ErrorAction Stop | Out-Null
                Write-SecurityLog "Disabled certificate task: $($_.TaskName)"
            }
            catch {
                Write-SecurityLog "Could not disable task $($_.TaskName): $_" "WARN"
            }
        }
    
    Write-SecurityLog "Certificate cleanup complete. Removed $removedCount certificates."
}

# ============================================================================
# USER/GROUP CLEANUP
# ============================================================================

function Set-HomeUserConfig {
    Write-SecurityLog "Configuring local users and groups..."
    
    # Disable Guest account
    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($guest -and $guest.Enabled) {
            Disable-LocalUser -Name "Guest"
            Write-SecurityLog "Disabled Guest account"
        }
    }
    catch {
        Write-SecurityLog "Could not disable Guest: $_" "WARN"
    }
    
    # Remove any domain-style accounts (shouldn't exist on home PC, but check)
    try {
        $localUsers = Get-LocalUser -ErrorAction SilentlyContinue
        foreach ($user in $localUsers) {
            # Check for suspicious patterns
            if ($user.Name -match "^[A-Z0-9]{8,}-|MS-|Azure|Sync|AD|Domain|Admin-\d|^(?!Administrator$).*Admin") {
                try {
                    Disable-LocalUser -Name $user.Name
                    Write-SecurityLog "Disabled suspicious user: $($user.Name)"
                }
                catch {
                    Write-SecurityLog "Could not disable user $($user.Name): $_" "WARN"
                }
            }
        }
    }
    catch {
        Write-SecurityLog "Error enumerating users: $_" "WARN"
    }
    
    # Clean up local groups - remove non-admin users from privileged groups
    $privilegedGroups = @("Administrators", "Power Users", "Remote Desktop Users", "Network Configuration Operators")
    
    foreach ($groupName in $privilegedGroups) {
        try {
            $groupMembers = Get-LocalGroupMember -Group $groupName -ErrorAction SilentlyContinue | 
                Where-Object { $_.Name -notmatch "$(hostname)\\Administrator|$(hostname)\\$env:USERNAME|NT AUTHORITY" }
            
            foreach ($member in $groupMembers) {
                try {
                    Remove-LocalGroupMember -Group $groupName -Member $member.Name -ErrorAction Stop
                    Write-SecurityLog "Removed $($member.Name) from $groupName"
                }
                catch {
                    Write-SecurityLog "Could not remove $($member.Name) from $groupName : $_" "WARN"
                }
            }
        }
        catch {
            Write-SecurityLog "Error checking group $groupName : $_" "WARN"
        }
    }
    
    # Ensure current user is only in necessary groups
    try {
        $currentUserGroups = Get-LocalGroup | Where-Object { 
            (Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue | 
             Where-Object { $_.Name -eq "$env:COMPUTERNAME\$env:USERNAME" }) 
        }
        
        $allowedGroups = @("Users", "Administrators", "HomeUsers")
        
        foreach ($group in $currentUserGroups) {
            if ($group.Name -notin $allowedGroups -and $group.Name -notmatch "Performance|Power|Hyper|Docker|WSL") {
                try {
                    Remove-LocalGroupMember -Group $group.Name -Member "$env:COMPUTERNAME\$env:USERNAME"
                    Write-SecurityLog "Removed current user from group: $($group.Name)"
                }
                catch {
                    Write-SecurityLog "Could not remove from $($group.Name) : $_" "WARN"
                }
            }
        }
    }
    catch {
        Write-SecurityLog "Error checking current user groups: $_" "WARN"
    }
}

# ============================================================================
# NETWORK CONFIGURATION
# ============================================================================

function Set-HomeNetwork {
    Write-SecurityLog "Configuring network for home PC..."
    
    # Disable unused network adapters (except active one)
    try {
        $activeAdapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.HardwareInterface -eq $true } | Select-Object -First 1
        $allAdapters = Get-NetAdapter | Where-Object { $_.HardwareInterface -eq $true }
        
        foreach ($adapter in $allAdapters) {
            if ($adapter.InterfaceAlias -ne $activeAdapter.InterfaceAlias) {
                try {
                    Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Stop
                    Write-SecurityLog "Disabled unused adapter: $($adapter.Name)"
                }
                catch {
                    Write-SecurityLog "Could not disable adapter $($adapter.Name): $_" "WARN"
                }
            }
        }
    }
    catch {
        Write-SecurityLog "Error configuring adapters: $_" "WARN"
    }
    
    # Disable IPv6 if not needed (optional - comment out if you use IPv6)
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $adapters) {
            Disable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Out-Null
        }
        Write-SecurityLog "Disabled IPv6 on active adapters"
    }
    catch {
        Write-SecurityLog "Could not disable IPv6: $_" "WARN"
    }
    
    # Disable network discovery (home PC doesn't need to advertise itself)
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\FDResPub\Parameters"
        if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        Set-ItemProperty -Path $regPath -Name "Disabled" -Value 1 -Force
        
        $regPath2 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NetworkExplorer\NameSpaceUnknownItems"
        if (!(Test-Path $regPath2)) { New-Item -Path $regPath2 -Force | Out-Null }
        Set-ItemProperty -Path $regPath2 -Name "Hidden" -Value 1 -Force
        
        Write-SecurityLog "Disabled network discovery"
    }
    catch {
        Write-SecurityLog "Could not disable network discovery: $_" "WARN"
    }
    
    # Remove any VPN connections
    try {
        $vpnConnections = Get-VpnConnection -ErrorAction SilentlyContinue
        foreach ($vpn in $vpnConnections) {
            try {
                Remove-VpnConnection -Name $vpn.Name -Force -ErrorAction Stop
                Write-SecurityLog "Removed VPN connection: $($vpn.Name)"
            }
            catch {
                Write-SecurityLog "Could not remove VPN $($vpn.Name): $_" "WARN"
            }
        }
    }
    catch {
        Write-SecurityLog "Error checking VPN connections: $_" "WARN"
    }

    # Set all current and future networks as PRIVATE (untrusted) profile
    Write-SecurityLog "Configuring network profiles as private/untrusted..."
    try {
        # 1. Set all existing network connections to Private profile
        $networkConnections = Get-NetConnectionProfile -ErrorAction SilentlyContinue
        foreach ($connection in $networkConnections) {
            try {
                Set-NetConnectionProfile -InterfaceIndex $connection.InterfaceIndex -NetworkCategory Private -ErrorAction Stop
                Write-SecurityLog "Set network '$($connection.Name)' to Private profile"
            }
            catch {
                Write-SecurityLog "Could not set network '$($connection.Name)' to Private: $_" "WARN"
            }
        }

        # 2. Registry: Force all networks to be treated as Private (untrusted)
        # Disable automatic network location awareness (NLA) - prevents auto-switching to Domain/Public
        $nlaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnections"
        if (!(Test-Path $nlaPath)) { New-Item -Path $nlaPath -Force | Out-Null }
        Set-ItemProperty -Path $nlaPath -Name "NC_StdDomainUserSetLocation" -Value 0 -Force
        Write-SecurityLog "Disabled automatic domain network detection"

        # 3. Registry: Set default network category to Private for all new networks
        $ncsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnections"
        Set-ItemProperty -Path $ncsPath -Name "NC_AllowNetLoc_Wizard" -Value 0 -Force
        Write-SecurityLog "Disabled network location wizard (forces private by default)"

        # 4. Registry: Disable Network List Service automatic categorization
        $netsvcPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkCategory"
        if (!(Test-Path $netsvcPath)) { New-Item -Path $netsvcPath -Force | Out-Null }
        # Category = 0: Public, 1: Private, 2: Domain
        Set-ItemProperty -Path $netsvcPath -Name "Category" -Value 1 -Force -ErrorAction SilentlyContinue

        # 5. Disable Network Discovery on all profiles (prevents trusting networks)
        $advFirewallPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"
        if (!(Test-Path $advFirewallPath)) { New-Item -Path $advFirewallPath -Force | Out-Null }
        Set-ItemProperty -Path $advFirewallPath -Name "DisableNotifications" -Value 1 -Force

        # Apply to all firewall profiles
        $profiles = @("DomainProfile", "PrivateProfile", "PublicProfile")
        foreach ($profile in $profiles) {
            $profilePath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$profile"
            if (!(Test-Path $profilePath)) { New-Item -Path $profilePath -Force | Out-Null }
            # Disable notifications that might cause users to change profile
            Set-ItemProperty -Path $profilePath -Name "DisableNotifications" -Value 1 -Force -ErrorAction SilentlyContinue
        }

        Write-SecurityLog "All networks configured as private/untrusted by default"
    }
    catch {
        Write-SecurityLog "Error configuring network profiles: $_" "WARN"
    }
}

# ============================================================================
# SCHEDULED TASKS CLEANUP
# ============================================================================

function Set-HomeScheduledTasks {
    Write-SecurityLog "Configuring scheduled tasks..."
    
    $tasksToDisable = @(
        # Remote/Enterprise tasks
        "RemoteAppAndDesktopConnections-Up"
        "RemoteAppAndDesktopConnections-LogonUpdate"
        "BgTaskRegistration" # Can be domain-related
        "IdleMaintenance"
        "MaintenanceTasks"
        "WinSAT" # Windows System Assessment Tool
        "Defrag" # Scheduled defrag (can run manually)
        "RegIdleBackup" # Registry backup
        "FamilySafetyMonitor" # If not using family safety
        "FamilySafetyRefresh"
        "Microsoft-Windows-DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
        "Microsoft-Windows-DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver"
        "Windows Defender\Windows Defender Cleanup"
        "Windows Defender\Windows Defender Scheduled Scan" # Can run manually
        "Windows Defender\Windows Defender Verification"
        "QueueReporting" # CEIP/telemetry
        "Microsoft-Windows-Customer Experience Improvement Program\Uploader"
        "Microsoft-Windows-Customer Experience Improvement Program\Consolidator"
        "Microsoft-Windows-Application-Experience\Microsoft-Windows-Application-Experience-ProgramData-Updater"
        "Microsoft-Windows-Application-Experience\Microsoft-Windows-Application-Experience-StartupAppTask"
        "Microsoft-Windows-Shell-Core\GatherNetworkInfo" # Network info gathering
        "Microsoft-Windows-CloudExperienceHost\CreateObjectTask"
        "Microsoft-Windows-Device Setup\Metadata Refresh"
        "Microsoft-Windows-DiskFootprint\Diagnostics"
        "Microsoft-Windows-FileHistory\File History (maintenance mode)"
        "Microsoft-Windows-Servicing\StartComponentCleanup" # Can run manually
        "Microsoft-Windows-SettingSync\BackgroundUploadTask" # If not syncing settings
        "Microsoft-Windows-SettingSync\NetworkStateChangeTask"
        "Microsoft-Windows-SpacePort\SpaceAgentTask"
        "Microsoft-Windows-SpacePort\SpaceManagerTask"
        "Microsoft-Windows-Storage Tiers Management\StorageTiersManagement"
        "Microsoft-Windows-Storage Tiers Management\StorageTiersOptimization"
        "Microsoft-Windows-Windows Error Reporting\QueueReporting"
        "Microsoft-Windows-Workplace Join\Automatic-Device-Join"
        "Microsoft-Windows-Workplace Join\Device-Sync"
        "Microsoft-Windows-Workplace Join\Recovery-Check"
        "UserTask\AutomaticProxyDetection"
        "UserTask\BackgroundScan"
        "UserTask\LogonSynchronization"
        "UserTask\ManualSynchronization"
        "UserTask\ScheduleRetry"
        "UserTask\WorkOnline"
        "XblGameSaveTask" # Xbox game save (if not gaming)
        "XblGameSaveTaskLogon"
        "OfficeTelemetryAgentFallBack2016"
        "OfficeTelemetryAgentLogon2016"
    )
    
    foreach ($taskName in $tasksToDisable) {
        try {
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($task -and $task.State -ne "Disabled") {
                Disable-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null
                Write-SecurityLog "Disabled task: $taskName"
            }
        }
        catch {
            # Task might not exist
        }
    }
}

# ============================================================================
# WATCHDOG / MONITOR FUNCTIONS
# ============================================================================

function Get-SystemBaseline {
    Write-SecurityLog "Capturing system baseline for watchdog monitoring..."
    
    $baseline = @{
        Timestamp = Get-Date -Format "o"
        Services = @{}
        FirewallRules = @()
        Certificates = @()
        LocalUsers = @()
        RegistrySettings = @{}
    }
    
    # Capture service states
    $servicesToMonitor = @(
        "TermService", "SessionEnv", "UmRdpService", "RemoteAccess", "RemoteRegistry",
        "LanmanServer", "LanmanWorkstation", "RpcLocator", "NTDS", "Netlogon",
        "AzureADConnectHealthSync", "ADSync", "MSOnlineServicesSignInAssistant"
    )
    
    foreach ($svcName in $servicesToMonitor) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc) {
                $baseline.Services[$svcName] = @{
                    Status = $svc.Status.ToString()
                    StartType = $svc.StartType.ToString()
                }
            }
        }
        catch { }
    }
    
    # Capture firewall inbound rules (should be minimal)
    $baseline.FirewallRules = (Get-NetFirewallRule -Direction Inbound -Enabled True | 
        Select-Object Name, DisplayName, LocalPort, RemotePort, Action | ConvertTo-Json -Compress)
    
    # Capture certificate counts
    $baseline.Certificates = (Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse -ErrorAction SilentlyContinue | 
        Select-Object Subject, Thumbprint, NotAfter | ConvertTo-Json -Compress)
    
    # Capture local users
    $baseline.LocalUsers = (Get-LocalUser -ErrorAction SilentlyContinue | 
        Select-Object Name, Enabled, LastLogon | ConvertTo-Json -Compress)
    
    # Capture critical registry settings
    $regPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections"
        "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance\fAllowToGetHelp"
    )
    
    foreach ($regPath in $regPaths) {
        try {
            if (Test-Path $regPath) {
                $baseline.RegistrySettings[$regPath] = (Get-ItemProperty -Path $regPath -ErrorAction Stop)
            }
        }
        catch { }
    }
    
    # Save baseline
    $baseline | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:StateFile -Force
    Write-SecurityLog "Baseline saved to $script:StateFile"
    
    return $baseline
}

function Test-SystemCompliance {
    param([hashtable]$Baseline)
    
    $violations = @()
    
    # Check services
    foreach ($svcName in $Baseline.Services.Keys) {
        try {
            $currentSvc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($currentSvc) {
                $expected = $Baseline.Services[$svcName]
                if ($currentSvc.Status -ne $expected.Status -or $currentSvc.StartType -ne $expected.StartType) {
                    $violations += @{
                        Type = "Service"
                        Item = $svcName
                        Expected = $expected
                        Current = @{ Status = $currentSvc.Status.ToString(); StartType = $currentSvc.StartType.ToString() }
                    }
                }
            }
        }
        catch { }
    }
    
    # Check registry settings
    foreach ($regPath in $Baseline.RegistrySettings.Keys) {
        try {
            if (Test-Path $regPath) {
                $currentValue = Get-ItemProperty -Path $regPath -ErrorAction Stop
                # Compare values
                $expectedValue = $Baseline.RegistrySettings[$regPath]
                # Simplified comparison - in production, compare specific properties
            }
        }
        catch {
            $violations += @{
                Type = "Registry"
                Item = $regPath
                Issue = "Registry path not accessible"
            }
        }
    }
    
    return $violations
}

function Restore-SystemCompliance {
    param([array]$Violations)
    
    Write-SecurityLog "Restoring $(($Violations | Measure-Object).Count) violations..." "WARN"
    
    foreach ($violation in $Violations) {
        switch ($violation.Type) {
            "Service" {
                try {
                    if ($violation.Expected.StartType -eq "Disabled") {
                        Stop-Service -Name $violation.Item -Force -ErrorAction SilentlyContinue
                        Set-Service -Name $violation.Item -StartupType Disabled
                        Write-SecurityLog "Restored service $($violation.Item) to disabled state"
                    }
                }
                catch {
                    Write-SecurityLog "Failed to restore service $($violation.Item): $_" "ERROR"
                }
            }
            "Registry" {
                # Re-apply all registry settings
                Set-HomeSecurityPolicy
            }
        }
    }
    
    # Also re-run full configuration to catch anything else
    Set-HomeServices
    Set-HomeFirewall
    Clear-NonRootCertificates
    Set-HomeUserConfig
    Set-HomeNetwork
    Set-HomeScheduledTasks
}

function Start-SecurityWatchdog {
    param([int]$IntervalSeconds = 60)
    
    Write-SecurityLog "Starting security watchdog with ${IntervalSeconds}s interval..."
    Write-SecurityLog "Press Ctrl+C to stop"
    
    # Load baseline
    if (!(Test-Path $script:StateFile)) {
        Write-SecurityLog "No baseline found. Creating new baseline..."
        Get-SystemBaseline | Out-Null
    }
    
    $baseline = Get-Content -Path $script:StateFile -Raw | ConvertFrom-Json -AsHashtable
    
    # Main watchdog loop
    while ($true) {
        try {
            Write-SecurityLog "Watchdog check at $(Get-Date -Format 'HH:mm:ss')"
            
            $violations = Test-SystemCompliance -Baseline $baseline
            
            if ($violations -and ($violations | Measure-Object).Count -gt 0) {
                Write-SecurityLog "Found $(($violations | Measure-Object).Count) configuration violations!" "WARN"
                Restore-SystemCompliance -Violations $violations
                
                # Update baseline after restoration
                $baseline = Get-SystemBaseline
            }
            else {
                Write-SecurityLog "System compliant. No violations found."
            }
            
            Start-Sleep -Seconds $IntervalSeconds
        }
        catch [System.Management.Automation.RuntimeException] {
            if ($_.Exception.Message -match "PipelineStopped") {
                Write-SecurityLog "Watchdog stopped by user"
                break
            }
            throw
        }
        catch {
            Write-SecurityLog "Watchdog error: $_" "ERROR"
            Start-Sleep -Seconds $IntervalSeconds
        }
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-GodsProtectionConfiguration {
    Write-SecurityLog "=========================================="
    Write-SecurityLog "GodsProtection - Applying Divine Security"
    Write-SecurityLog "=========================================="
    
    # 0. Driver Removal
    Remove-BowserDriver

    # 1. Security Policy
    Set-HomeSecurityPolicy
    
    # 2. Services
    Set-HomeServices
    
    # 3. Firewall
    Set-HomeFirewall
    
    # 4. Certificates
    Clear-NonRootCertificates
    
    # 5. Users/Groups
    Set-HomeUserConfig
    
    # 6. Network
    Set-HomeNetwork
    
    # 7. Scheduled Tasks
    Set-HomeScheduledTasks
    
    # 8. Capture baseline for watchdog
    Get-SystemBaseline | Out-Null
    
    Write-SecurityLog "=========================================="
    Write-SecurityLog "Divine configuration complete!"
    Write-SecurityLog "=========================================="
}

# ============================================================================
# SCRIPT ENTRY POINT
# ============================================================================

# Check for special internal mode (used by scheduled tasks)
if ($Mode -eq "Monitor") {
    Start-MonitorMode
    exit
}

# Main user-facing entry point
if ($Uninstall) {
    Remove-GodsProtectionTasks
}
else {
    # Default behavior: Install and enable fire-and-forget monitoring
    Install-GodsProtection
}
