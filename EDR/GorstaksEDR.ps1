#Requires -Version 5.1
<#
.SYNOPSIS
    GorstaksEDR - Lightweight Endpoint Detection & Response
.DESCRIPTION
    A single-file PowerShell EDR focused on detection and alerting.
    Monitor-only by default. Auto-response requires explicit opt-in.
    No dangerous modules (no retaliation, no password rotation).
.PARAMETER Install
    Copy script to C:\ProgramData\GorstaksEDR and register startup task.
.PARAMETER Uninstall
    Remove scheduled task, Defender exclusion, and install directory.
.PARAMETER AutoRespond
    Enable automatic kill/quarantine/block for high-confidence threats.
    Without this flag the EDR only logs and alerts.
.PARAMETER ScanPath
    Run a one-shot scan on a file or directory, then exit.
.EXAMPLE
    .\GorstaksEDR.ps1                       # Monitor-only mode
    .\GorstaksEDR.ps1 -AutoRespond          # Monitor + auto-response
    .\GorstaksEDR.ps1 -ScanPath C:\Downloads  # One-shot scan
    .\GorstaksEDR.ps1 -Install              # Install as service
    .\GorstaksEDR.ps1 -Uninstall            # Clean removal
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter(ParameterSetName = 'Install')][switch]$Install,
    [Parameter(ParameterSetName = 'Uninstall')][switch]$Uninstall,
    [Parameter(ParameterSetName = 'Run')][switch]$AutoRespond,
    [Parameter(ParameterSetName = 'Scan')][string]$ScanPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ═══════════════════════════════════════════════════════════════
# SECTION 1: CONFIGURATION
# ═══════════════════════════════════════════════════════════════
$Script:EDR = @{
    Name              = 'GorstaksEDR'
    Version           = '2.0.0'
    InstallDir        = 'C:\ProgramData\GorstaksEDR'
    SelfPID           = $PID
    SelfHash          = ''
    AutoRespond       = [bool]$AutoRespond

    # Scoring thresholds
    AlertThreshold    = 50
    QuarantineThreshold = 80
    KillThreshold     = 100

    # Timing
    ScanIntervalSec   = 5
    ChainTTLSec       = 300
    IntegrityCheckSec = 300
    MainLoopSec       = 60
    DriveSweepSec     = 120   # Periodic scan of all drive roots for new executables

    # Limits
    MaxLogSizeMB      = 50
    MaxAlertHistory   = 500
    MaxChainDepth     = 20
    MaxMemRegions     = 256
    MaxMemRegionBytes = 1048576  # 1 MB

    # Paths (set during init)
    LogPath           = ''
    QuarantinePath    = ''
    AlertPath         = ''
    WhitelistPath     = ''
    HashDBPath        = ''
}

# Resolve paths relative to install dir or script dir
$Script:BaseDir = if (Test-Path $Script:EDR.InstallDir) { $Script:EDR.InstallDir } else { $PSScriptRoot }
$Script:EDR.LogPath        = Join-Path $Script:BaseDir 'Logs'
$Script:EDR.QuarantinePath = Join-Path $Script:BaseDir 'Quarantine'
$Script:EDR.AlertPath      = Join-Path $Script:BaseDir 'Alerts'
$Script:EDR.WhitelistPath  = Join-Path $Script:BaseDir 'whitelist.json'
$Script:EDR.HashDBPath     = Join-Path $Script:BaseDir 'hashdb.json'

# Protected processes — never kill these
$Script:ProtectedProcesses = @(
    'System','Idle','Registry','smss','csrss','wininit','winlogon','services',
    'lsass','svchost','dwm','explorer','fontdrvhost','RuntimeBroker','sihost',
    'taskhostw','SearchIndexer','spoolsv','WmiPrvSE','dllhost','conhost','ctfmon',
    'SecurityHealthService','MsMpEng','NisSrv','audiodg','dasHost','WUDFHost',
    'SearchHost','StartMenuExperienceHost','ShellExperienceHost','TextInputHost',
    'powershell','pwsh','WindowsTerminal','cmd',
    'Code','code','Cursor','electron','node','devenv',
    'chrome','firefox','msedge','brave','opera'
)

# ═══════════════════════════════════════════════════════════════
# SECTION 2: THREAT INTELLIGENCE DATA
# ═══════════════════════════════════════════════════════════════

# LOLBin suspicious argument patterns
$Script:LOLBinArgs = @{
    'powershell.exe'  = @('-enc','-encodedcommand','-nop','-noprofile','-w hidden','-windowstyle hidden','-ep bypass','-executionpolicy bypass','iex','invoke-expression','downloadstring','downloadfile','frombase64string')
    'cmd.exe'         = @('/c powershell','/c mshta','/c certutil','/c bitsadmin','/c wscript','/c cscript')
    'mshta.exe'       = @('javascript:','vbscript:','http://','https://')
    'rundll32.exe'    = @('javascript:','shell32.dll','url.dll','advpack.dll')
    'regsvr32.exe'    = @('/s','/u','/i:http','scrobj.dll')
    'certutil.exe'    = @('-urlcache','-decode','-encode','http://','https://','-split')
    'wmic.exe'        = @('process call create','os get','/node:','shadowcopy delete','/format:')
    'msiexec.exe'     = @('/q','http://','https://')
    'cscript.exe'     = @('//e:','//b','.vbs','.js')
    'wscript.exe'     = @('//e:','//b','.vbs','.js')
    'bitsadmin.exe'   = @('/transfer','/create','/addfile','http://')
    'schtasks.exe'    = @('/create','/change','/run','/tn')
    'sc.exe'          = @('create','config','binpath=')
    'reg.exe'         = @('add','delete','CurrentVersion\\Run')
    'net.exe'         = @('user /add','localgroup administrators','share','use \\\\')
    'msbuild.exe'     = @('/noautoresponse','/target:','/property:')
    'installutil.exe' = @('/logfile=','/LogToConsole=','/u')
    'bash.exe'        = @('-c','curl','wget','python','nc ')
    'forfiles.exe'    = @('/p','/m','/c','cmd')
}

# Command-line heuristic patterns with MITRE mapping
$Script:CmdPatterns = @(
    @{ Pat='-enc\s';                           Sc=30; Desc='Encoded command';         M='T1059.001' }
    @{ Pat='-encodedcommand\s';                Sc=30; Desc='Encoded command (full)';  M='T1059.001' }
    @{ Pat='-nop\s.*-w\s+hidden';              Sc=35; Desc='Hidden PowerShell';       M='T1059.001' }
    @{ Pat='-ep\s+bypass';                     Sc=25; Desc='Exec policy bypass';      M='T1059.001' }
    @{ Pat='invoke-expression';                Sc=20; Desc='IEX usage';               M='T1059.001' }
    @{ Pat='iex\s*\(';                         Sc=25; Desc='IEX shorthand';           M='T1059.001' }
    @{ Pat='frombase64string';                 Sc=30; Desc='Base64 decode';           M='T1140' }
    @{ Pat='reflection\.assembly';             Sc=40; Desc='Reflective loading';      M='T1620' }
    @{ Pat='net\s+user\s+.*\/add';             Sc=35; Desc='User creation';           M='T1136.001' }
    @{ Pat='net\s+localgroup\s+admin';         Sc=40; Desc='Admin group mod';         M='T1136.001' }
    @{ Pat='reg\s+add.*\\run\s';               Sc=35; Desc='Run key persistence';     M='T1547.001' }
    @{ Pat='schtasks\s+/create';               Sc=30; Desc='Scheduled task';          M='T1053.005' }
    @{ Pat='wmic\s+.*process\s+call\s+create'; Sc=40; Desc='WMI process create';     M='T1047' }
    @{ Pat='vssadmin.*delete\s+shadows';       Sc=50; Desc='Shadow copy deletion';    M='T1490' }
    @{ Pat='bcdedit.*recoveryenabled.*no';     Sc=50; Desc='Recovery disabled';       M='T1490' }
    @{ Pat='wbadmin\s+delete';                 Sc=45; Desc='Backup deletion';         M='T1490' }
    @{ Pat='netsh\s+advfirewall.*off';         Sc=40; Desc='Firewall disabled';       M='T1562.004' }
    @{ Pat='Set-MpPreference.*-Disable';       Sc=45; Desc='Defender disabled';       M='T1562.001' }
    @{ Pat='Add-MpPreference.*-ExclusionPath'; Sc=40; Desc='Defender exclusion';      M='T1562.001' }
    @{ Pat='\|\s*iex';                         Sc=40; Desc='Pipeline to IEX';         M='T1059.001' }
    @{ Pat='downloadstring\s*\(.*http';        Sc=45; Desc='Download and execute';    M='T1059.001' }
    @{ Pat='add-type.*dllimport';              Sc=50; Desc='P/Invoke via Add-Type';   M='T1106' }
    @{ Pat='clear-eventlog|wevtutil\s+cl';     Sc=50; Desc='Event log clearing';      M='T1070.001' }
)

# Suspicious parent-child process chains
$Script:SuspiciousChains = @(
    @{ Parent='winword.exe';   Child='cmd.exe';        Score=40; Desc='Office->cmd' }
    @{ Parent='winword.exe';   Child='powershell.exe'; Score=50; Desc='Office->PS' }
    @{ Parent='excel.exe';     Child='cmd.exe';        Score=40; Desc='Excel->cmd' }
    @{ Parent='excel.exe';     Child='powershell.exe'; Score=50; Desc='Excel->PS' }
    @{ Parent='outlook.exe';   Child='cmd.exe';        Score=45; Desc='Outlook->cmd' }
    @{ Parent='outlook.exe';   Child='powershell.exe'; Score=55; Desc='Outlook->PS' }
    @{ Parent='mshta.exe';     Child='powershell.exe'; Score=60; Desc='MSHTA->PS' }
    @{ Parent='wscript.exe';   Child='powershell.exe'; Score=50; Desc='WScript->PS' }
    @{ Parent='cscript.exe';   Child='powershell.exe'; Score=50; Desc='CScript->PS' }
    @{ Parent='services.exe';  Child='cmd.exe';        Score=40; Desc='Services->CMD' }
    @{ Parent='wmiprvse.exe';  Child='powershell.exe'; Score=55; Desc='WMI->PS' }
    @{ Parent='wmiprvse.exe';  Child='cmd.exe';        Score=45; Desc='WMI->CMD' }
    @{ Parent='rundll32.exe';  Child='cmd.exe';        Score=45; Desc='Rundll32->CMD' }
    @{ Parent='regsvr32.exe';  Child='cmd.exe';        Score=50; Desc='Regsvr32->CMD' }
    @{ Parent='w3wp.exe';      Child='cmd.exe';        Score=80; Desc='IIS->CMD (webshell?)' }
    @{ Parent='w3wp.exe';      Child='powershell.exe'; Score=90; Desc='IIS->PS (webshell?)' }
    @{ Parent='sqlservr.exe';  Child='cmd.exe';        Score=80; Desc='SQL->CMD' }
)

# YARA-like detection rules
$Script:YaraRules = @(
    @{ Name='CobaltStrike';   Desc='Cobalt Strike beacon';  Cat='C2';          Sev='Critical'; Score=90; Patterns=@('beacon\.dll','cobaltstrike','sleeptime','%COMSPEC%','IEX.*downloadstring.*http'); Cond='any' }
    @{ Name='PowerSploit';    Desc='PowerSploit framework'; Cat='Execution';   Sev='High';     Score=75; Patterns=@('invoke-shellcode','invoke-reflectivepeinjection','invoke-dllinjection','invoke-tokenmanipulation','get-gpppassword','invoke-kerberoast'); Cond='any' }
    @{ Name='Mimikatz';       Desc='Credential dumping';    Cat='CredAccess';  Sev='Critical'; Score=95; Patterns=@('mimikatz','sekurlsa','kerberos::','lsadump::','privilege::debug','token::elevate','dpapi::'); Cond='any' }
    @{ Name='SharpTools';     Desc='C# offensive tools';    Cat='Execution';   Sev='High';     Score=70; Patterns=@('sharphound','rubeus','seatbelt','sharpup','certify','whisker'); Cond='any' }
    @{ Name='DownloadCradle'; Desc='Download cradles';      Cat='Delivery';    Sev='High';     Score=65; Patterns=@('certutil.*-urlcache','bitsadmin.*\/transfer','Invoke-WebRequest.*http','Start-BitsTransfer','Net\.WebClient','DownloadFile\(','DownloadString\('); Cond='any' }
    @{ Name='ProcessInject';  Desc='Process injection';     Cat='DefEvasion';  Sev='Critical'; Score=85; Patterns=@('VirtualAllocEx','WriteProcessMemory','CreateRemoteThread','NtMapViewOfSection','QueueUserAPC','RtlCreateUserThread'); Cond='any' }
    @{ Name='AMSIBypass';     Desc='AMSI bypass';           Cat='DefEvasion';  Sev='Critical'; Score=80; Patterns=@('amsiInitFailed','AmsiScanBuffer','amsi\.dll','AmsiUtils','amsiContext'); Cond='any' }
    @{ Name='Persistence';    Desc='Persistence techniques';Cat='Persistence'; Sev='High';     Score=60; Patterns=@('schtasks.*\/create','New-ScheduledTask','HKCU:\\\\.*\\\\Run','HKLM:\\\\.*\\\\Run','New-Service','sc\.exe.*create'); Cond='any' }
    @{ Name='LateralMove';    Desc='Lateral movement';      Cat='LateralMove'; Sev='High';     Score=70; Patterns=@('Enter-PSSession','Invoke-Command.*-Computer','New-PSSession','wmic.*\/node:','psexec','winrm'); Cond='any' }
    @{ Name='Exfiltration';   Desc='Data exfiltration';     Cat='Exfiltration';Sev='High';     Score=60; Patterns=@('Compress-Archive','tar.*-czf','7z.*a\s','ToBase64String','nslookup.*txt','dns.*tunnel'); Cond='any' }
)

# MITRE ATT&CK technique database
$Script:MitreDB = @{
    'T1059.001' = @{ Name='PowerShell';                    Tactic='Execution' }
    'T1059.003' = @{ Name='Windows Command Shell';         Tactic='Execution' }
    'T1047'     = @{ Name='WMI';                           Tactic='Execution' }
    'T1106'     = @{ Name='Native API';                    Tactic='Execution' }
    'T1053.005' = @{ Name='Scheduled Task';                Tactic='Persistence' }
    'T1547.001' = @{ Name='Registry Run Keys';             Tactic='Persistence' }
    'T1136.001' = @{ Name='Local Account';                 Tactic='Persistence' }
    'T1027'     = @{ Name='Obfuscated Files';              Tactic='DefenseEvasion' }
    'T1140'     = @{ Name='Deobfuscate/Decode';            Tactic='DefenseEvasion' }
    'T1218'     = @{ Name='System Binary Proxy Execution'; Tactic='DefenseEvasion' }
    'T1562.001' = @{ Name='Disable Security Tools';        Tactic='DefenseEvasion' }
    'T1562.004' = @{ Name='Disable Firewall';              Tactic='DefenseEvasion' }
    'T1620'     = @{ Name='Reflective Code Loading';       Tactic='DefenseEvasion' }
    'T1055'     = @{ Name='Process Injection';             Tactic='DefenseEvasion' }
    'T1070.001' = @{ Name='Clear Event Logs';              Tactic='DefenseEvasion' }
    'T1490'     = @{ Name='Inhibit System Recovery';       Tactic='Impact' }
    'T1033'     = @{ Name='System Owner Discovery';        Tactic='Discovery' }
    'T1018'     = @{ Name='Remote System Discovery';       Tactic='Discovery' }
}

$Script:SuspiciousPorts = @(4444,5555,6666,8888,9999,1337,31337,12345,4443,8443,6667,6697)

$Script:RansomwareExtensions = @(
    '.encrypted','.locked','.crypt','.crypto','.enc','.locky','.cerber','.zepto',
    '.thor','.aesir','.zzzzz','.xxx','.ttt','.ecc','.ezz','.exx','.abc','.aaa',
    '.xtbl','.crysis','.crypz','.dharma','.wallet','.onion','.wncry','.wcry',
    '.wnry','.petya','.bad','.globe','.bleep','.crypted','.pay','.ransom','.rip'
)

$Script:RansomNotePatterns = @(
    'readme','recover','restore','decrypt','how to','help_decrypt',
    'help_recover','ransom','payment','_readme','!readme'
)

# Score weights for the scoring engine
$Script:ScoreWeights = @{
    Static   = 1.0
    Behavior = 1.5
    Yara     = 1.3
    Mitre    = 0.8
    Network  = 1.2
    Chain    = 1.4
    Memory   = 1.5
    HashRep  = 1.0
}

# ═══════════════════════════════════════════════════════════════
# SECTION 3: GLOBAL STATE
# ═══════════════════════════════════════════════════════════════
$Script:ProcessTracker  = @{}
$Script:AlertHistory    = [System.Collections.ArrayList]::new()
$Script:ActiveWatchers  = [System.Collections.ArrayList]::new()
$Script:BeaconTracker   = @{}
$Script:HashRepDB       = @{}
$Script:Whitelist       = @{ Paths = @(); Hashes = @() }
$Script:RansomRenames   = 0
$Script:RansomExtChanges = @{}
$Script:RansomWindowStart = Get-Date
$Script:PInvokeLoaded   = $false
$Script:AMSIAvailable   = $false
$Script:AMSIContext      = [IntPtr]::Zero
$Script:Stats = @{
    ProcessesAnalyzed = 0
    FilesScanned      = 0
    AlertsGenerated   = 0
    ThreatsBlocked    = 0
    StartTime         = Get-Date
}

# ═══════════════════════════════════════════════════════════════
# SECTION 4: LOGGING
# ═══════════════════════════════════════════════════════════════
function Write-EDRLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ALERT','CRITICAL','DEBUG')]
        [string]$Level = 'INFO'
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $entry = "[$ts] [$Level] $Message"

    try {
        if (-not (Test-Path $Script:EDR.LogPath)) {
            New-Item -ItemType Directory -Path $Script:EDR.LogPath -Force | Out-Null
        }
        $logFile = Join-Path $Script:EDR.LogPath "edr_$(Get-Date -Format 'yyyyMMdd').log"

        # Rotate if too large
        if ((Test-Path $logFile) -and (Get-Item $logFile).Length -gt ($Script:EDR.MaxLogSizeMB * 1MB)) {
            $archive = $logFile -replace '\.log$', "_$(Get-Date -Format 'HHmmss').log.bak"
            Move-Item $logFile $archive -Force -ErrorAction SilentlyContinue
        }

        Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue
    }
    catch { }

    # Console output for ALERT and above
    switch ($Level) {
        'CRITICAL' { Write-Host $entry -ForegroundColor Red }
        'ALERT'    { Write-Host $entry -ForegroundColor Yellow }
        'WARN'     { Write-Host $entry -ForegroundColor DarkYellow }
    }
}

# ═══════════════════════════════════════════════════════════════
# SECTION 5: INSTALL / UNINSTALL
# ═══════════════════════════════════════════════════════════════
function Install-EDR {
    $dir = $Script:EDR.InstallDir
    Write-Host "[+] Installing GorstaksEDR to $dir" -ForegroundColor Cyan

    foreach ($sub in @('Logs','Quarantine','Alerts')) {
        $p = Join-Path $dir $sub
        if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    }

    $dest = Join-Path $dir 'GorstaksEDR.ps1'
    Copy-Item -Path $PSCommandPath -Destination $dest -Force
    Write-Host "[+] Script copied to $dest" -ForegroundColor Green

    # Scheduled task — runs at logon, highest privileges
    $taskName = 'GorstaksEDR'
    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        $action   = New-ScheduledTaskAction -Execute 'powershell.exe' `
                      -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dest`""
        $trigger  = New-ScheduledTaskTrigger -AtLogOn
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                      -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
            -Settings $settings -RunLevel Highest -Force -ErrorAction Stop | Out-Null
        Write-Host "[+] Scheduled task '$taskName' registered" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Failed to register scheduled task: $_" -ForegroundColor Red
    }

    # Defender exclusion for quarantine path only (not the whole install dir)
    try {
        Add-MpPreference -ExclusionPath (Join-Path $dir 'Quarantine') -ErrorAction SilentlyContinue
        Write-Host "[+] Defender exclusion added for Quarantine folder" -ForegroundColor Green
    }
    catch { }

    Write-Host "[+] Installation complete." -ForegroundColor Green
    exit 0
}

function Uninstall-EDR {
    Write-Host "[*] Uninstalling GorstaksEDR..." -ForegroundColor Cyan

    try {
        Unregister-ScheduledTask -TaskName 'GorstaksEDR' -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "[+] Scheduled task removed" -ForegroundColor Green
    }
    catch { Write-Host "[!] Could not remove scheduled task: $_" -ForegroundColor Yellow }

    try {
        Remove-MpPreference -ExclusionPath (Join-Path $Script:EDR.InstallDir 'Quarantine') -ErrorAction SilentlyContinue
        Write-Host "[+] Defender exclusion removed" -ForegroundColor Green
    }
    catch { }

    if (Test-Path $Script:EDR.InstallDir) {
        Write-Host "[!] Install directory preserved at $($Script:EDR.InstallDir)" -ForegroundColor Yellow
        Write-Host "    Delete manually if you want to remove logs and quarantined files." -ForegroundColor Yellow
    }

    Write-Host "[+] Uninstall complete." -ForegroundColor Green
    exit 0
}

# ═══════════════════════════════════════════════════════════════
# SECTION 6: SELF-PROTECTION & HELPERS
# ═══════════════════════════════════════════════════════════════
function Test-IsExcludedPath {
    param([string]$Path)
    if (-not $Path) { return $false }
    $low = $Path.ToLower()
    # Only exclude the EDR's own quarantine and log dirs
    foreach ($ex in @($Script:EDR.QuarantinePath, $Script:EDR.LogPath, $Script:EDR.AlertPath)) {
        if ($ex -and $low.StartsWith($ex.ToLower())) { return $true }
    }
    return $false
}

function Test-IsSelfProcess {
    param([int]$ProcessId)
    return ($ProcessId -eq $Script:EDR.SelfPID)
}

function Test-IsWhitelisted {
    param([string]$FilePath, [string]$SHA256)
    if ($FilePath) {
        $low = $FilePath.ToLower()
        foreach ($wp in $Script:Whitelist.Paths) {
            if ($wp -and $low.StartsWith($wp.ToLower())) { return $true }
        }
    }
    if ($SHA256 -and $Script:Whitelist.Hashes -contains $SHA256) { return $true }
    return $false
}

function Initialize-SelfIntegrity {
    try {
        if ($PSCommandPath -and (Test-Path $PSCommandPath)) {
            $Script:EDR.SelfHash = (Get-FileHash $PSCommandPath -Algorithm SHA256).Hash
        }
    }
    catch { }
}

function Test-SelfIntegrity {
    if (-not $Script:EDR.SelfHash -or -not $PSCommandPath) { return $true }
    try {
        $current = (Get-FileHash $PSCommandPath -Algorithm SHA256).Hash
        if ($current -ne $Script:EDR.SelfHash) {
            Write-EDRLog 'INTEGRITY VIOLATION: EDR script has been modified!' 'CRITICAL'
            return $false
        }
    }
    catch { }
    return $true
}

function Initialize-Whitelist {
    if (Test-Path $Script:EDR.WhitelistPath) {
        try {
            $wl = Get-Content $Script:EDR.WhitelistPath -Raw | ConvertFrom-Json
            $Script:Whitelist.Paths  = @($wl.Paths)
            $Script:Whitelist.Hashes = @($wl.Hashes)
        }
        catch { Write-EDRLog "Failed to load whitelist: $_" 'WARN' }
    }
    # Always whitelist own hash
    if ($Script:EDR.SelfHash) {
        $Script:Whitelist.Hashes += $Script:EDR.SelfHash
    }
}

function Initialize-HashRepDB {
    if (Test-Path $Script:EDR.HashDBPath) {
        try {
            $db = Get-Content $Script:EDR.HashDBPath -Raw | ConvertFrom-Json
            foreach ($entry in $db) {
                $Script:HashRepDB[$entry.Hash] = $entry.ThreatName
            }
            Write-EDRLog "Loaded $($Script:HashRepDB.Count) hash reputation entries" 'INFO'
        }
        catch { Write-EDRLog "Failed to load hash DB: $_" 'WARN' }
    }
}

function Get-HashReputation {
    param([string]$SHA256)
    $result = [PSCustomObject]@{ IsKnownMalicious = $false; ThreatName = ''; Score = 0 }
    if ($SHA256 -and $Script:HashRepDB.ContainsKey($SHA256)) {
        $result.IsKnownMalicious = $true
        $result.ThreatName = $Script:HashRepDB[$SHA256]
        $result.Score = 80
    }
    return $result
}

# ═══════════════════════════════════════════════════════════════
# SECTION 6b: ANTI-CIRCUMVENTION (ported from GEdr C# project)
# ═══════════════════════════════════════════════════════════════

# -- Process DACL hardening --
# Sets a restrictive ACL on our own process so non-admin users cannot taskkill us.
# Admins can still kill it (we don't want to brick the system).
function Protect-EDRProcess {
    try {
        if (-not ([System.Management.Automation.PSTypeName]'EDRProcessProtect').Type) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public class EDRProcessProtect {
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool SetKernelObjectSecurity(IntPtr handle, int secInfo, byte[] pSD);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string sddl, int revision, out IntPtr sd, out int sdLen);

    [DllImport("kernel32.dll")]
    static extern bool LocalFree(IntPtr hMem);

    public static bool Protect() {
        // DACL: only SYSTEM and Administrators get full control
        string sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";
        IntPtr sd; int sdLen;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out sd, out sdLen))
            return false;
        byte[] sdBytes = new byte[sdLen];
        Marshal.Copy(sd, sdBytes, 0, sdLen);
        LocalFree(sd);
        return SetKernelObjectSecurity(GetCurrentProcess(), 0x04, sdBytes);
    }
}
'@ -ErrorAction Stop
        }
        if ([EDRProcessProtect]::Protect()) {
            Write-EDRLog 'Process DACL hardened (non-admin terminate blocked)' 'INFO'
        }
        else {
            Write-EDRLog 'Failed to set process DACL' 'WARN'
        }
    }
    catch {
        Write-EDRLog "Process DACL protection failed: $_" 'WARN'
    }
}

# -- Whitelist tamper detection --
# Snapshot whitelist hash at startup. If it changes at runtime, freeze the whitelist
# so an attacker can't add their payload hash to bypass detection.
$Script:WhitelistHashAtLoad = $null

function Initialize-WhitelistTamperDetection {
    if (Test-Path $Script:EDR.WhitelistPath) {
        try {
            $Script:WhitelistHashAtLoad = (Get-FileHash $Script:EDR.WhitelistPath -Algorithm SHA256).Hash
        }
        catch { }
    }
}

function Test-WhitelistTamper {
    if (-not $Script:WhitelistHashAtLoad) { return }
    if (-not (Test-Path $Script:EDR.WhitelistPath)) { return }
    try {
        $current = (Get-FileHash $Script:EDR.WhitelistPath -Algorithm SHA256).Hash
        if ($current -ne $Script:WhitelistHashAtLoad) {
            Write-EDRLog 'WHITELIST TAMPERED: whitelist.json modified at runtime. Allowlists frozen to prevent bypass.' 'CRITICAL'
            # Don't reload — keep the original whitelist. Attacker adding their hash won't take effect.
            $Script:WhitelistHashAtLoad = $current
        }
    }
    catch { }
}

# -- Debugger detection --
function Test-DebuggerAttached {
    try {
        if (-not ([System.Management.Automation.PSTypeName]'EDRDebugCheck').Type) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class EDRDebugCheck {
    [DllImport("kernel32.dll")]
    public static extern bool IsDebuggerPresent();
}
'@ -ErrorAction Stop
        }
        if ([EDRDebugCheck]::IsDebuggerPresent()) {
            Write-EDRLog 'DEBUGGER DETECTED attached to EDR process!' 'CRITICAL'
        }
    }
    catch { }
}

# -- ETW tamper detection --
# Checks if ntdll!EtwEventWrite has been patched (common EDR bypass).
# Attackers patch the first bytes to RET (0xC3) so no ETW events are emitted.
function Test-EtwIntegrity {
    try {
        if (-not ([System.Management.Automation.PSTypeName]'EDREtwCheck').Type) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class EDREtwCheck {
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi)]
    static extern IntPtr GetModuleHandle(string moduleName);

    [DllImport("kernel32.dll", CharSet=CharSet.Ansi)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    public static byte[] GetEtwPrologue() {
        IntPtr hNtdll = GetModuleHandle("ntdll.dll");
        if (hNtdll == IntPtr.Zero) return null;
        IntPtr addr = GetProcAddress(hNtdll, "EtwEventWrite");
        if (addr == IntPtr.Zero) return null;
        byte[] prologue = new byte[4];
        Marshal.Copy(addr, prologue, 0, 4);
        return prologue;
    }
}
'@ -ErrorAction Stop
        }
        $prologue = [EDREtwCheck]::GetEtwPrologue()
        if ($null -eq $prologue) { return }

        # 0xC3 = RET — means EtwEventWrite was patched to immediately return
        if ($prologue[0] -eq 0xC3) {
            Write-EDRLog 'ETW TAMPERED: ntdll!EtwEventWrite patched with RET instruction! [T1562.001]' 'CRITICAL'
        }
        # 0x33 0xC0 0xC3 = xor eax,eax; ret — returns 0 (success) without doing anything
        elseif ($prologue[0] -eq 0x33 -and $prologue[1] -eq 0xC0 -and $prologue[2] -eq 0xC3) {
            Write-EDRLog 'ETW TAMPERED: ntdll!EtwEventWrite patched to return 0! [T1562.001]' 'CRITICAL'
        }
    }
    catch { }
}

# -- Renamed LOLBin detection --
# Checks OriginalFilename in PE version info to catch renamed system tools.
# e.g., powershell.exe copied to D:\update.exe still has OriginalFilename=PowerShell.EXE
$Script:LOLBinOriginalNames = @(
    'powershell.exe','pwsh.exe','cmd.exe','wscript.exe','cscript.exe',
    'mshta.exe','certutil.exe','bitsadmin.exe','wmic.exe','msiexec.exe',
    'regsvr32.exe','rundll32.exe','regasm.exe','regsvcs.exe','installutil.exe',
    'msbuild.exe','cmstp.exe','odbcconf.exe','sc.exe','net.exe','net1.exe',
    'netsh.exe','bcdedit.exe','schtasks.exe','reg.exe','taskkill.exe'
)

# Framework runtimes that legitimately rebrand (not suspicious)
$Script:FrameworkOriginalNames = @(
    'electron.exe','nw.exe','node.exe','java.exe','javaw.exe',
    'python.exe','pythonw.exe','dotnet.exe','php.exe','ruby.exe'
)

function Test-RenamedLOLBin {
    param([string]$FilePath, [string]$ProcessName)

    if (-not $FilePath -or -not (Test-Path $FilePath -ErrorAction SilentlyContinue)) { return $null }

    try {
        $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($FilePath)
        $origName = $versionInfo.OriginalFilename
        if (-not $origName) { return $null }

        $origLower = $origName.ToLower() -replace '\.mui$', ''
        $procLower = ($ProcessName ?? '').ToLower()

        # Same name? Not renamed.
        if ($origLower -eq $procLower) { return $null }
        if ($origLower -eq ($procLower -replace '\.exe$', '') + '.exe') { return $null }

        # Is it a framework rebrand? (not suspicious)
        foreach ($fw in $Script:FrameworkOriginalNames) {
            if ($origLower.Contains($fw)) { return $null }
        }

        # Is the original name a LOLBin? (suspicious!)
        foreach ($lol in $Script:LOLBinOriginalNames) {
            if ($origLower.Contains($lol)) {
                return [PSCustomObject]@{
                    OriginalName = $origName
                    CurrentName  = $ProcessName
                    FilePath     = $FilePath
                    Score        = 70
                }
            }
        }
    }
    catch { }

    return $null
}

# -- Command-line entropy detection --
# High-entropy command lines often contain base64 blobs or obfuscated payloads.
function Get-StringEntropy {
    param([string]$Text)
    if (-not $Text -or $Text.Length -eq 0) { return 0.0 }
    $freq = @{}
    foreach ($c in $Text.ToCharArray()) {
        $b = [int]$c
        if ($b -lt 256) {
            if ($freq.ContainsKey($b)) { $freq[$b]++ } else { $freq[$b] = 1 }
        }
    }
    $entropy = 0.0
    $len = $Text.Length
    foreach ($count in $freq.Values) {
        $p = $count / $len
        if ($p -gt 0) { $entropy -= $p * [Math]::Log($p, 2) }
    }
    return [Math]::Round($entropy, 2)
}

# ═══════════════════════════════════════════════════════════════
# SECTION 7: P/INVOKE FOR MEMORY SCANNING
# ═══════════════════════════════════════════════════════════════
function Initialize-PInvoke {
    if ($Script:PInvokeLoaded) { return }
    try {
        if (-not ([System.Management.Automation.PSTypeName]'EDRNative').Type) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public class EDRNative {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(IntPtr hProc, IntPtr baseAddr, byte[] buf, int size, out int read);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern int VirtualQueryEx(IntPtr hProc, IntPtr addr, out MEMORY_BASIC_INFORMATION buf, int len);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress, AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State, Protect, Type;
    }

    public const int PROCESS_VM_READ = 0x0010;
    public const int PROCESS_QUERY_LIMITED = 0x1000;
    public const uint MEM_COMMIT = 0x1000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_EXECUTE_READ = 0x20;
    public const uint PAGE_EXECUTE = 0x10;
    public const uint MEM_PRIVATE = 0x20000;
    public const uint MEM_IMAGE = 0x1000000;

    public static bool ContainsBytes(byte[] haystack, int len, byte[] needle) {
        if (needle.Length > len) return false;
        int limit = len - needle.Length;
        for (int i = 0; i <= limit; i++) {
            bool match = true;
            for (int j = 0; j < needle.Length; j++) {
                if (haystack[i + j] != needle[j]) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }
}
'@ -ErrorAction Stop
        }
        $Script:PInvokeLoaded = $true
    }
    catch {
        Write-EDRLog "P/Invoke init failed (memory scanning disabled): $_" 'WARN'
    }
}

# ═══════════════════════════════════════════════════════════════
# SECTION 8: AMSI INTEGRATION
# ═══════════════════════════════════════════════════════════════
function Initialize-AMSI {
    try {
        if (-not ([System.Management.Automation.PSTypeName]'AMSINative').Type) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class AMSINative {
    [DllImport("amsi.dll", CharSet=CharSet.Unicode)]
    public static extern int AmsiInitialize(string appName, out IntPtr ctx);
    [DllImport("amsi.dll", CharSet=CharSet.Unicode)]
    public static extern int AmsiScanBuffer(IntPtr ctx, byte[] buf, uint len, string name, IntPtr session, out int result);
    [DllImport("amsi.dll")]
    public static extern void AmsiUninitialize(IntPtr ctx);
}
'@ -ErrorAction Stop
        }
        $ctx = [IntPtr]::Zero
        $hr = [AMSINative]::AmsiInitialize('GorstaksEDR', [ref]$ctx)
        if ($hr -eq 0 -and $ctx -ne [IntPtr]::Zero) {
            $Script:AMSIContext = $ctx
            $Script:AMSIAvailable = $true
            Write-EDRLog 'AMSI initialized' 'INFO'
        }
    }
    catch {
        Write-EDRLog "AMSI init failed: $_" 'WARN'
    }
}

function Invoke-AMSIScan {
    param([string]$Content, [string]$ContentName)
    if (-not $Script:AMSIAvailable -or -not $Content) { return 0 }
    try {
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($Content)
        $amsiResult = 0
        $hr = [AMSINative]::AmsiScanBuffer($Script:AMSIContext, $bytes, [uint32]$bytes.Length, $ContentName, [IntPtr]::Zero, [ref]$amsiResult)
        if ($hr -ne 0) { return 0 }
        if ($amsiResult -ge 32768) { return 80 }  # AMSI_RESULT_DETECTED
        if ($amsiResult -ge 16384) { return 50 }  # Suspicious
    }
    catch { }
    return 0
}

function Invoke-AMSIFileScan {
    param([string]$FilePath)
    if (-not $Script:AMSIAvailable) { return 0 }
    if (-not (Test-Path $FilePath)) { return 0 }
    $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()
    if ($ext -notin @('.ps1','.vbs','.js','.wsf','.bat','.cmd','.hta')) { return 0 }
    try {
        $content = Get-Content $FilePath -Raw -ErrorAction Stop
        if ($content.Length -gt 1048576) { $content = $content.Substring(0, 1048576) }
        return Invoke-AMSIScan -Content $content -ContentName ([System.IO.Path]::GetFileName($FilePath))
    }
    catch { return 0 }
}

# ═══════════════════════════════════════════════════════════════
# SECTION 9: STATIC ANALYSIS
# ═══════════════════════════════════════════════════════════════
function Invoke-StaticAnalysis {
    param([string]$FilePath)

    $r = [PSCustomObject]@{
        FilePath = $FilePath; FileSize = 0; Hashes = @{}
        IsSigned = $false; SignerName = ''; Entropy = 0.0
        IsPacked = $false; Score = 0; Flags = [System.Collections.ArrayList]::new()
    }

    if (-not (Test-Path $FilePath)) { return $r }
    if (Test-IsExcludedPath $FilePath) { return $r }

    try {
        $item = Get-Item $FilePath -ErrorAction Stop
        $r.FileSize = $item.Length

        # Hashes
        $r.Hashes = @{
            SHA256 = (Get-FileHash $FilePath -Algorithm SHA256).Hash
        }

        if (Test-IsWhitelisted -FilePath $FilePath -SHA256 $r.Hashes.SHA256) { return $r }

        # Hash reputation
        $rep = Get-HashReputation -SHA256 $r.Hashes.SHA256
        if ($rep.IsKnownMalicious) {
            $r.Score += $rep.Score
            $r.Flags.Add("Known malicious: $($rep.ThreatName)") | Out-Null
        }

        # Signature check
        $sig = Get-AuthenticodeSignature $FilePath -ErrorAction SilentlyContinue
        if ($sig) {
            $r.IsSigned = ($sig.Status -eq 'Valid')
            if ($sig.SignerCertificate) { $r.SignerName = $sig.SignerCertificate.Subject }
        }
        if (-not $r.IsSigned) {
            $r.Score += 10
            $r.Flags.Add('Unsigned binary') | Out-Null
        }

        # Entropy (read first 64KB to keep it fast)
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        $sampleSize = [Math]::Min($bytes.Length, 65536)
        if ($sampleSize -gt 0) {
            $freq = @{}
            for ($i = 0; $i -lt $sampleSize; $i++) {
                $b = $bytes[$i]
                if ($freq.ContainsKey($b)) { $freq[$b]++ } else { $freq[$b] = 1 }
            }
            $ent = 0.0
            foreach ($c in $freq.Values) {
                $p = $c / $sampleSize
                if ($p -gt 0) { $ent -= $p * [Math]::Log($p, 2) }
            }
            $r.Entropy = [Math]::Round($ent, 2)
            if ($ent -gt 7.2) {
                $r.IsPacked = $true; $r.Score += 25
                $r.Flags.Add("High entropy ($($r.Entropy))") | Out-Null
            }
            elseif ($ent -gt 6.8) {
                $r.Score += 10
                $r.Flags.Add("Elevated entropy ($($r.Entropy))") | Out-Null
            }
        }

        # PE header checks (only for actual PE files)
        if ($bytes.Length -gt 64 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
            $ascii = [System.Text.Encoding]::ASCII.GetString($bytes, 0, [Math]::Min($bytes.Length, 262144))

            # Packer sections
            foreach ($sec in @('.upx','.aspack','.themida','.vmp','.enigma')) {
                if ($ascii.Contains($sec)) {
                    $r.Score += 20
                    $r.Flags.Add("Packer section: $sec") | Out-Null
                }
            }

            # Suspicious imports
            foreach ($imp in @('VirtualAllocEx','WriteProcessMemory','CreateRemoteThread','NtUnmapViewOfSection','IsDebuggerPresent')) {
                if ($ascii.Contains($imp)) {
                    $r.Score += 15
                    $r.Flags.Add("Suspicious import: $imp") | Out-Null
                }
            }
        }

        # Double extension
        if ($FilePath -match '\.\w+\.(exe|scr|bat|cmd|ps1|vbs|js)$') {
            $r.Score += 30
            $r.Flags.Add('Double extension') | Out-Null
        }

        # Tiny PE
        if ($r.FileSize -lt 10KB -and $FilePath -match '\.(exe|dll)$') {
            $r.Score += 15
            $r.Flags.Add("Tiny PE ($($r.FileSize) bytes)") | Out-Null
        }

        # AMSI scan for script files
        $amsiScore = Invoke-AMSIFileScan -FilePath $FilePath
        if ($amsiScore -gt 0) {
            $r.Score += $amsiScore
            $r.Flags.Add("AMSI detection (score $amsiScore)") | Out-Null
        }

        $Script:Stats.FilesScanned++
    }
    catch {
        Write-EDRLog "Static analysis error for $FilePath : $_" 'DEBUG'
    }

    return $r
}

# ═══════════════════════════════════════════════════════════════
# SECTION 10: BEHAVIOR ENGINE
# ═══════════════════════════════════════════════════════════════
function Invoke-BehaviorAnalysis {
    param([int]$ProcessId, [string]$CommandLine, [string]$FilePath)

    $r = [PSCustomObject]@{
        ProcessId = $ProcessId; ProcessName = ''; CommandLine = $CommandLine
        FilePath = $FilePath; Score = 0
        Flags = [System.Collections.ArrayList]::new()
        MitreTags = [System.Collections.ArrayList]::new()
    }

    if (Test-IsSelfProcess $ProcessId) { return $r }

    # Resolve process info if needed
    if ($ProcessId) {
        try {
            $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue
            if ($proc) {
                $r.ProcessName = $proc.Name
                if (-not $CommandLine) { $CommandLine = $proc.CommandLine; $r.CommandLine = $CommandLine }
                if (-not $FilePath) { $FilePath = $proc.ExecutablePath; $r.FilePath = $FilePath }
            }
        }
        catch { }
    }

    if (-not $CommandLine) { return $r }
    if (Test-IsExcludedPath $FilePath) { return $r }

    $cmdLow = $CommandLine.ToLower()
    $procLow = $r.ProcessName.ToLower()

    # LOLBin argument matching
    foreach ($bin in $Script:LOLBinArgs.Keys) {
        $binLow = $bin.ToLower()
        $binNoExt = [System.IO.Path]::GetFileNameWithoutExtension($bin).ToLower()
        if ($procLow -ne $binLow -and $procLow -ne $binNoExt) { continue }

        $hitCount = 0
        foreach ($arg in $Script:LOLBinArgs[$bin]) {
            if ($cmdLow.Contains($arg.ToLower())) { $hitCount++ }
        }
        if ($hitCount -gt 0) {
            $r.Score += 20 + ($hitCount * 10)
            $r.Flags.Add("LOLBin: $bin ($hitCount suspicious args)") | Out-Null
        }
        break
    }

    # Command-line pattern matching
    foreach ($p in $Script:CmdPatterns) {
        if ($cmdLow -match $p.Pat) {
            $r.Score += $p.Sc
            $r.Flags.Add($p.Desc) | Out-Null
            if ($p.M) { $r.MitreTags.Add($p.M) | Out-Null }
        }
    }

    # Suspicious execution paths
    $badPaths = @('\\appdata\\local\\temp\\','\\users\\public\\','\\windows\\temp\\')
    if ($FilePath) {
        foreach ($sp in $badPaths) {
            if ($FilePath.ToLower() -match [regex]::Escape($sp)) {
                if (-not (Test-IsExcludedPath $FilePath)) {
                    $r.Score += 15
                    $r.Flags.Add("Suspicious exec path") | Out-Null
                }
                break
            }
        }
    }

    # Long command line
    if ($CommandLine.Length -gt 1000) {
        $r.Score += 15
        $r.Flags.Add("Long command line ($($CommandLine.Length) chars)") | Out-Null
    }

    # Obfuscation scoring
    $specials = ([regex]::Matches($CommandLine, '[`^|&;${}()\[\]]')).Count
    if ($specials -gt 20) {
        $r.Score += 20
        $r.Flags.Add("High obfuscation ($specials special chars)") | Out-Null
        $r.MitreTags.Add('T1027') | Out-Null
    }

    # Command-line entropy (ported from GEdr — catches base64 blobs)
    if ($CommandLine.Length -gt 100) {
        $scriptHosts = @('powershell','cmd','wscript','cscript','mshta')
        $isScriptHost = $false
        foreach ($sh in $scriptHosts) {
            if ($procLow.Contains($sh)) { $isScriptHost = $true; break }
        }
        if ($isScriptHost) {
            $cmdEntropy = Get-StringEntropy -Text $CommandLine
            if ($cmdEntropy -gt 5.5) {
                $r.Score += 30
                $r.Flags.Add("High-entropy command line ($cmdEntropy) [T1027]") | Out-Null
                $r.MitreTags.Add('T1027') | Out-Null
            }
        }
    }

    # Renamed LOLBin detection (ported from GEdr — catches powershell.exe renamed to update.exe)
    if ($FilePath -and $r.ProcessName) {
        $renamedResult = Test-RenamedLOLBin -FilePath $FilePath -ProcessName $r.ProcessName
        if ($renamedResult) {
            $r.Score += $renamedResult.Score
            $r.Flags.Add("Renamed LOLBin: $($r.ProcessName) is actually $($renamedResult.OriginalName)") | Out-Null
        }
    }

    $Script:Stats.ProcessesAnalyzed++
    return $r
}

# ═══════════════════════════════════════════════════════════════
# SECTION 11: YARA-LIKE RULES
# ═══════════════════════════════════════════════════════════════
function Invoke-YaraRuleScan {
    param([string]$FilePath, [string]$CommandLine)

    $matches2 = [System.Collections.ArrayList]::new()
    $content = ''

    if ($FilePath -and (Test-Path $FilePath -ErrorAction SilentlyContinue)) {
        try {
            $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
            $readLen = [Math]::Min($fileBytes.Length, 262144)  # First 256KB
            $content = [System.Text.Encoding]::UTF8.GetString($fileBytes, 0, $readLen)
        }
        catch { }
    }
    if ($CommandLine) { $content += "`n$CommandLine" }
    if (-not $content) { return $matches2 }

    $cLow = $content.ToLower()
    foreach ($rule in $Script:YaraRules) {
        $hits = 0
        foreach ($pat in $rule.Patterns) {
            if ($cLow -match $pat) { $hits++ }
        }
        $fired = ($rule.Cond -eq 'any' -and $hits -gt 0) -or
                 ($rule.Cond -eq 'all' -and $hits -eq $rule.Patterns.Count)
        if ($fired) {
            $matches2.Add([PSCustomObject]@{
                RuleName    = $rule.Name
                Description = $rule.Desc
                Category    = $rule.Cat
                Severity    = $rule.Sev
                Score       = $rule.Score
                HitCount    = $hits
            }) | Out-Null
        }
    }
    return $matches2
}

# ═══════════════════════════════════════════════════════════════
# SECTION 12: MITRE MAPPING
# ═══════════════════════════════════════════════════════════════
function Get-MitreMapping {
    param($BehaviorResults, $StaticResults)

    $mappings = [System.Collections.ArrayList]::new()
    $seen = @{}

    if ($BehaviorResults -and $BehaviorResults.MitreTags) {
        foreach ($tag in $BehaviorResults.MitreTags) {
            if (-not $seen.ContainsKey($tag) -and $Script:MitreDB.ContainsKey($tag)) {
                $info = $Script:MitreDB[$tag]
                $mappings.Add([PSCustomObject]@{
                    TechniqueId   = $tag
                    TechniqueName = $info.Name
                    Tactic        = $info.Tactic
                    Confidence    = 'High'
                    Source        = 'Behavior'
                }) | Out-Null
                $seen[$tag] = $true
            }
        }
    }

    if ($StaticResults -and $StaticResults.Flags) {
        foreach ($f in $StaticResults.Flags) {
            if ($f -match 'injection|VirtualAllocEx|WriteProcessMemory|CreateRemoteThread' -and -not $seen.ContainsKey('T1055')) {
                $mappings.Add([PSCustomObject]@{
                    TechniqueId   = 'T1055'
                    TechniqueName = 'Process Injection'
                    Tactic        = 'DefenseEvasion'
                    Confidence    = 'Medium'
                    Source        = 'Static'
                }) | Out-Null
                $seen['T1055'] = $true
            }
        }
    }

    return $mappings
}

# ═══════════════════════════════════════════════════════════════
# SECTION 13: NETWORK ANALYSIS
# ═══════════════════════════════════════════════════════════════
function Invoke-NetworkAnalysis {
    param([int]$ProcessId)

    if (Test-IsSelfProcess $ProcessId) { return $null }

    $r = [PSCustomObject]@{
        ProcessId = $ProcessId
        SuspiciousConns = [System.Collections.ArrayList]::new()
        BeaconingDetected = $false
        Score = 0
    }

    try {
        $conns = Get-NetTCPConnection -OwningProcess $ProcessId -ErrorAction SilentlyContinue |
            Where-Object { $_.RemoteAddress -notin @('0.0.0.0','::','127.0.0.1','::1') }

        foreach ($conn in $conns) {
            if ($conn.RemotePort -in $Script:SuspiciousPorts) {
                $r.SuspiciousConns.Add([PSCustomObject]@{
                    RemoteAddress = $conn.RemoteAddress
                    RemotePort    = $conn.RemotePort
                    State         = $conn.State
                }) | Out-Null
                $r.Score += 25
            }

            # Beaconing tracker
            $key = "$($conn.RemoteAddress):$($conn.RemotePort)"
            if (-not $Script:BeaconTracker.ContainsKey($key)) {
                $Script:BeaconTracker[$key] = [System.Collections.ArrayList]::new()
            }
            $Script:BeaconTracker[$key].Add((Get-Date)) | Out-Null
        }

        # Beaconing detection via jitter analysis
        foreach ($key in @($Script:BeaconTracker.Keys)) {
            $stamps = $Script:BeaconTracker[$key]
            if ($stamps.Count -ge 5) {
                $intervals = @()
                for ($i = 1; $i -lt $stamps.Count; $i++) {
                    $intervals += ($stamps[$i] - $stamps[$i-1]).TotalSeconds
                }
                if ($intervals.Count -ge 4) {
                    $avg = ($intervals | Measure-Object -Average).Average
                    $variance = ($intervals | ForEach-Object { [Math]::Pow($_ - $avg, 2) } | Measure-Object -Average).Average
                    $sd = [Math]::Sqrt($variance)
                    if ($avg -gt 0 -and ($sd / $avg) -lt 0.3) {
                        $r.BeaconingDetected = $true
                        $r.Score += 40
                    }
                }
            }
        }
    }
    catch { }

    return $r
}

# ═══════════════════════════════════════════════════════════════
# SECTION 14: PROCESS CHAIN ANALYSIS
# ═══════════════════════════════════════════════════════════════
function Get-ProcessChain {
    param([int]$ProcessId)

    $chain = [System.Collections.ArrayList]::new()
    $cur = $ProcessId
    $visited = @{}

    while ($cur -and $cur -ne 0 -and -not $visited.ContainsKey($cur) -and $chain.Count -lt $Script:EDR.MaxChainDepth) {
        $visited[$cur] = $true

        if ($Script:ProcessTracker.ContainsKey($cur)) {
            $info = $Script:ProcessTracker[$cur]
            $chain.Add([PSCustomObject]@{
                PID = $cur; Name = $info.Name; CommandLine = $info.CommandLine
                ExePath = $info.ExePath; ParentPID = $info.ParentPID
            }) | Out-Null
            $cur = $info.ParentPID
        }
        else {
            try {
                $p = Get-CimInstance Win32_Process -Filter "ProcessId=$cur" -ErrorAction SilentlyContinue
                if ($p) {
                    $chain.Add([PSCustomObject]@{
                        PID = $cur; Name = $p.Name; CommandLine = $p.CommandLine
                        ExePath = $p.ExecutablePath; ParentPID = $p.ParentProcessId
                    }) | Out-Null
                    $cur = $p.ParentProcessId
                }
                else { break }
            }
            catch { break }
        }
    }

    $chain.Reverse()
    return $chain
}

function Invoke-ChainAnalysis {
    param([int]$ProcessId)

    if (Test-IsSelfProcess $ProcessId) { return $null }

    $chain = Get-ProcessChain -ProcessId $ProcessId
    $r = [PSCustomObject]@{
        ProcessId = $ProcessId; ChainDepth = $chain.Count; Score = 0
        ChainString = (($chain | ForEach-Object { $_.Name }) -join ' -> ')
        MitreTechniques = [System.Collections.ArrayList]::new()
    }

    if ($chain.Count -lt 2) { return $r }

    # Parent-child rule matching
    for ($i = 0; $i -lt ($chain.Count - 1); $i++) {
        $pN = ($chain[$i].Name ?? '').ToLower()
        $cN = ($chain[$i+1].Name ?? '').ToLower()
        foreach ($rule in $Script:SuspiciousChains) {
            if ($pN -eq $rule.Parent -and $cN -eq $rule.Child) {
                $r.Score += $rule.Score
            }
        }
    }

    # Deep chain bonus
    if ($chain.Count -ge 5) {
        $r.Score += ($chain.Count - 4) * 10
    }

    # LOLBin chain detection
    $lolbins = @($Script:LOLBinArgs.Keys | ForEach-Object { $_.ToLower() })
    $lolCount = 0
    foreach ($node in $chain) {
        if (($node.Name ?? '').ToLower() -in $lolbins) { $lolCount++ }
    }
    if ($lolCount -ge 3) {
        $r.Score += 40
        $r.MitreTechniques.Add('T1218') | Out-Null
    }
    elseif ($lolCount -ge 2) { $r.Score += 15 }

    # Non-interactive parent spawning interactive shell
    $nonInteractive = @('services.exe','svchost.exe','wmiprvse.exe','taskeng.exe','taskhostw.exe','w3wp.exe','sqlservr.exe')
    $interactive = @('cmd.exe','powershell.exe','pwsh.exe')
    if ($chain.Count -ge 2) {
        $parentName = ($chain[-2].Name ?? '').ToLower()
        $childName  = ($chain[-1].Name ?? '').ToLower()
        if ($parentName -in $nonInteractive -and $childName -in $interactive) {
            $r.Score += 30
        }
    }

    return $r
}

# ═══════════════════════════════════════════════════════════════
# SECTION 15: MEMORY SCANNER
# ═══════════════════════════════════════════════════════════════
$Script:ShellcodeSigs = @(
    @(0xFC,0x48,0x83,0xE4,0xF0),          # x64 CLD; SUB RSP
    @(0xFC,0xE8,0x82,0x00,0x00,0x00),     # Metasploit x86
    @(0x60,0x89,0xE5,0x31,0xC0),          # x86 PUSHAD
    @(0xE8,0x00,0x00,0x00,0x00,0x5B)      # CALL $+5; POP EBX
)

$Script:MemStringPatterns = @(
    'mimikatz','sekurlsa','kerberos::','lsadump::','Invoke-Mimikatz',
    'Invoke-Shellcode','ReflectivePEInjection','AmsiScanBuffer',
    'amsiInitFailed','cobaltstrike','beacon.dll','meterpreter'
)

$Script:SkipScanProcs = @(
    'System','Idle','smss','csrss','wininit','winlogon','services',
    'lsass','svchost','dwm','MsMpEng','conhost'
)

function Invoke-MemoryScan {
    param([int]$ProcessId)

    $r = [PSCustomObject]@{ ProcessId = $ProcessId; Score = 0; HasSuspicious = $false }

    if (-not $Script:PInvokeLoaded) { return $r }
    if ($ProcessId -le 4) { return $r }
    if (Test-IsSelfProcess $ProcessId) { return $r }

    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if (-not $proc -or $proc.ProcessName -in $Script:SkipScanProcs) { return $r }
    }
    catch { return $r }

    $hProc = [IntPtr]::Zero
    try {
        $hProc = [EDRNative]::OpenProcess(
            [EDRNative]::PROCESS_VM_READ -bor [EDRNative]::PROCESS_QUERY_LIMITED,
            $false, $ProcessId
        )
        if ($hProc -eq [IntPtr]::Zero) { return $r }

        $addr = [IntPtr]::Zero
        $rwxCount = 0
        $scanned = 0
        $mbi = New-Object EDRNative+MEMORY_BASIC_INFORMATION
        $mbiSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][EDRNative+MEMORY_BASIC_INFORMATION])

        while ($scanned -lt $Script:EDR.MaxMemRegions -and
               [EDRNative]::VirtualQueryEx($hProc, $addr, [ref]$mbi, $mbiSize) -gt 0) {

            $regionSize = $mbi.RegionSize.ToInt64()
            if ($regionSize -le 0) { break }

            if ($mbi.State -eq [EDRNative]::MEM_COMMIT) {
                $isRWX = ($mbi.Protect -band [EDRNative]::PAGE_EXECUTE_READWRITE) -ne 0
                $isExec = $isRWX -or
                          (($mbi.Protect -band [EDRNative]::PAGE_EXECUTE_READ) -ne 0) -or
                          (($mbi.Protect -band [EDRNative]::PAGE_EXECUTE) -ne 0)
                $isPrivate = ($mbi.Type -band [EDRNative]::MEM_PRIVATE) -ne 0
                $isImage = ($mbi.Type -band [EDRNative]::MEM_IMAGE) -ne 0

                if ($isRWX) { $rwxCount++ }

                if ($isExec -and $regionSize -gt 0 -and $regionSize -le $Script:EDR.MaxMemRegionBytes) {
                    try {
                        $buf = New-Object byte[] $regionSize
                        $bytesRead = 0
                        if ([EDRNative]::ReadProcessMemory($hProc, $mbi.BaseAddress, $buf, $buf.Length, [ref]$bytesRead) -and $bytesRead -gt 0) {

                            # Shellcode signatures
                            foreach ($sig in $Script:ShellcodeSigs) {
                                if ([EDRNative]::ContainsBytes($buf, $bytesRead, [byte[]]$sig)) {
                                    $r.Score += 60
                                    break
                                }
                            }

                            # In-memory string patterns
                            $text = [System.Text.Encoding]::ASCII.GetString($buf, 0, $bytesRead)
                            foreach ($pat in $Script:MemStringPatterns) {
                                if ($text.IndexOf($pat, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                                    $r.Score += 40
                                }
                            }

                            # Reflective PE in private memory
                            if ($isPrivate -and -not $isImage -and $bytesRead -ge 2 -and
                                $buf[0] -eq 0x4D -and $buf[1] -eq 0x5A) {
                                $r.Score += 80
                            }
                        }
                    }
                    catch { }
                }
            }

            $scanned++
            $next = $mbi.BaseAddress.ToInt64() + $regionSize
            if ($next -le $addr.ToInt64()) { break }
            $addr = [IntPtr]$next
        }

        if ($rwxCount -gt 0) {
            $r.Score += [Math]::Min($rwxCount * 20, 60)
            $r.HasSuspicious = $true
        }
    }
    catch { }
    finally {
        if ($hProc -ne [IntPtr]::Zero) { [EDRNative]::CloseHandle($hProc) | Out-Null }
    }

    return $r
}

# ═══════════════════════════════════════════════════════════════
# SECTION 16: RANSOMWARE DETECTOR
# ═══════════════════════════════════════════════════════════════
function Invoke-RansomwareCheck {
    param(
        [string]$EventType,
        [string]$OldPath,
        [string]$NewPath
    )

    $score = 0

    # Reset sliding window
    if (((Get-Date) - $Script:RansomWindowStart).TotalSeconds -gt 30) {
        $Script:RansomRenames = 0
        $Script:RansomExtChanges = @{}
        $Script:RansomWindowStart = Get-Date
    }

    if ($EventType -eq 'Renamed') {
        $Script:RansomRenames++
        $newExt = [System.IO.Path]::GetExtension($NewPath).ToLower()
        $oldExt = [System.IO.Path]::GetExtension($OldPath).ToLower()

        if ($newExt -ne $oldExt -and $newExt -in $Script:RansomwareExtensions) {
            if (-not $Script:RansomExtChanges.ContainsKey($newExt)) {
                $Script:RansomExtChanges[$newExt] = 0
            }
            $Script:RansomExtChanges[$newExt]++

            if ($Script:RansomExtChanges[$newExt] -ge 10) {
                Write-EDRLog "RANSOMWARE: Mass rename to $newExt ($($Script:RansomExtChanges[$newExt]) files)" 'CRITICAL'
                $score += 60
            }
        }

        if ($Script:RansomRenames -ge 50) {
            Write-EDRLog "RANSOMWARE: $($Script:RansomRenames) renames in 30s window!" 'CRITICAL'
            $score += 90
        }
    }

    if ($EventType -eq 'Created' -and $NewPath) {
        $name = [System.IO.Path]::GetFileName($NewPath).ToLower()
        foreach ($pat in $Script:RansomNotePatterns) {
            if ($name.Contains($pat)) {
                Write-EDRLog "RANSOMWARE: Ransom note detected: $NewPath" 'CRITICAL'
                $score += 70
                break
            }
        }
    }

    return $score
}

# ═══════════════════════════════════════════════════════════════
# SECTION 17: SCORING ENGINE
# ═══════════════════════════════════════════════════════════════
function Get-ThreatScore {
    param([Parameter(Mandatory)]$A)

    $bd = [PSCustomObject]@{
        StaticScore = 0; BehaviorScore = 0; YaraScore = 0; MitreScore = 0
        NetworkScore = 0; ChainScore = 0; MemoryScore = 0; HashRepScore = 0
        BonusPenalties = 0; TotalScore = 0; Verdict = 'Clean'; Confidence = 'Low'
    }

    if ($A.StaticResults)   { $bd.StaticScore   = [Math]::Min($A.StaticResults.Score, 100) }
    if ($A.BehaviorResults) { $bd.BehaviorScore  = [Math]::Min($A.BehaviorResults.Score, 150) }

    if ($A.YaraMatches -and $A.YaraMatches.Count -gt 0) {
        $yt = ($A.YaraMatches | Measure-Object -Property Score -Sum).Sum
        $bd.YaraScore = [Math]::Min($yt, 120)
        if ($A.YaraMatches | Where-Object { $_.Severity -eq 'Critical' }) {
            $bd.YaraScore = [Math]::Min([int]($bd.YaraScore * 1.3), 150)
        }
    }

    if ($A.MitreMapping -and $A.MitreMapping.Count -gt 0) {
        $mb = $A.MitreMapping.Count * 8 +
              @($A.MitreMapping | Where-Object { $_.Confidence -eq 'High' }).Count * 5
        $tactics = @($A.MitreMapping | Select-Object -ExpandProperty Tactic -Unique).Count
        if ($tactics -ge 3) { $mb = [int]($mb * 1.3) }
        $bd.MitreScore = [Math]::Min($mb, 80)
    }

    if ($A.NetworkResults) {
        $bd.NetworkScore = [Math]::Min($A.NetworkResults.Score, 80)
        if ($A.NetworkResults.BeaconingDetected) { $bd.NetworkScore += 30 }
        $bd.NetworkScore = [Math]::Min($bd.NetworkScore, 100)
    }

    if ($A.ChainResults)  { $bd.ChainScore  = [Math]::Min($A.ChainResults.Score, 120) }
    if ($A.MemoryResults) { $bd.MemoryScore  = [Math]::Min($A.MemoryResults.Score, 150) }

    if ($A.HashRepResults -and $A.HashRepResults.IsKnownMalicious) {
        $bd.HashRepScore = $A.HashRepResults.Score
    }

    # Adjustments
    $adj = 0
    if ($A.FilePath -and (Test-Path $A.FilePath -ErrorAction SilentlyContinue)) {
        try {
            $sig = Get-AuthenticodeSignature $A.FilePath -ErrorAction SilentlyContinue
            if ($sig -and $sig.Status -eq 'Valid') {
                $adj -= 20
                $trustedPublishers = @('Microsoft','Google','Mozilla','Adobe','Oracle','Apple','Intel','NVIDIA')
                foreach ($pub in $trustedPublishers) {
                    if ($sig.SignerCertificate.Subject -match $pub) { $adj -= 30; break }
                }
            }
        }
        catch { }
    }

    # Corroboration bonus
    $sources = 0
    if ($bd.StaticScore -gt 20)   { $sources++ }
    if ($bd.BehaviorScore -gt 20) { $sources++ }
    if ($bd.YaraScore -gt 0)      { $sources++ }
    if ($bd.NetworkScore -gt 10)  { $sources++ }
    if ($bd.ChainScore -gt 20)    { $sources++ }
    if ($bd.MemoryScore -gt 0)    { $sources++ }
    if ($sources -ge 4) { $adj += 35 }
    elseif ($sources -ge 3) { $adj += 25 }

    $bd.BonusPenalties = $adj

    # Weighted total
    $wt = ($bd.StaticScore   * $Script:ScoreWeights.Static) +
          ($bd.BehaviorScore * $Script:ScoreWeights.Behavior) +
          ($bd.YaraScore     * $Script:ScoreWeights.Yara) +
          ($bd.MitreScore    * $Script:ScoreWeights.Mitre) +
          ($bd.NetworkScore  * $Script:ScoreWeights.Network) +
          ($bd.ChainScore    * $Script:ScoreWeights.Chain) +
          ($bd.MemoryScore   * $Script:ScoreWeights.Memory) +
          ($bd.HashRepScore  * $Script:ScoreWeights.HashRep) +
          $adj

    $bd.TotalScore = [Math]::Max(0, [Math]::Round($wt))

    # Verdict
    if     ($bd.TotalScore -ge 120) { $bd.Verdict = 'Critical' }
    elseif ($bd.TotalScore -ge 80)  { $bd.Verdict = 'Malicious' }
    elseif ($bd.TotalScore -ge 50)  { $bd.Verdict = 'Suspicious' }
    elseif ($bd.TotalScore -ge 25)  { $bd.Verdict = 'Low' }

    # Confidence
    $activeEngines = 0
    @($bd.StaticScore, $bd.BehaviorScore, $bd.YaraScore, $bd.MitreScore,
      $bd.NetworkScore, $bd.ChainScore, $bd.MemoryScore) | ForEach-Object {
        if ($_ -gt 0) { $activeEngines++ }
    }
    if ($activeEngines -ge 4) { $bd.Confidence = 'High' }
    elseif ($activeEngines -ge 2) { $bd.Confidence = 'Medium' }

    return $bd
}

# ═══════════════════════════════════════════════════════════════
# SECTION 18: RESPONSE ENGINE
# ═══════════════════════════════════════════════════════════════
function Invoke-ThreatResponse {
    param($Analysis, [int]$Score, [string]$Verdict, [string]$Confidence)

    $actions = [System.Collections.ArrayList]::new()

    # Always generate alerts for suspicious+
    if ($Score -ge $Script:EDR.AlertThreshold) {
        $alertId = [guid]::NewGuid().ToString('N').Substring(0, 8)
        $target = if ($Analysis.FilePath) { $Analysis.FilePath } else { "PID:$($Analysis.ProcessId)" }

        $alert = [PSCustomObject]@{
            AlertId     = $alertId
            Timestamp   = Get-Date -Format 'o'
            Score       = $Score
            Verdict     = $Verdict
            Confidence  = $Confidence
            Target      = $target
            CommandLine = $Analysis.CommandLine
        }

        # Write alert file
        try {
            if (-not (Test-Path $Script:EDR.AlertPath)) {
                New-Item -ItemType Directory -Path $Script:EDR.AlertPath -Force | Out-Null
            }
            $alertFile = Join-Path $Script:EDR.AlertPath "${alertId}_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            $alert | ConvertTo-Json -Depth 5 | Set-Content $alertFile -Encoding UTF8
        }
        catch { }

        $Script:AlertHistory.Add($alert) | Out-Null
        if ($Script:AlertHistory.Count -gt $Script:EDR.MaxAlertHistory) {
            $Script:AlertHistory.RemoveAt(0)
        }

        $Script:Stats.AlertsGenerated++
        $actions.Add("Alert:$alertId") | Out-Null
        Write-EDRLog "ALERT [$alertId] Score=$Score Verdict=$Verdict Confidence=$Confidence Target=$target" 'ALERT'
    }

    # Auto-response only if explicitly enabled AND confidence is High
    if (-not $Script:EDR.AutoRespond) {
        if ($actions.Count -eq 0) { return 'None' }
        return ($actions -join '; ')
    }

    if ($Confidence -ne 'High') {
        # Don't auto-respond on low/medium confidence — too risky
        if ($actions.Count -eq 0) { return 'None' }
        return ($actions -join '; ')
    }

    # Kill process (Critical verdict only)
    if ($Score -ge $Script:EDR.KillThreshold -and $Analysis.ProcessId -and
        -not (Test-IsSelfProcess $Analysis.ProcessId)) {
        try {
            $proc = Get-Process -Id $Analysis.ProcessId -ErrorAction SilentlyContinue
            if ($proc) {
                $procName = $proc.ProcessName -replace '\.exe$', ''
                if ($procName -notin $Script:ProtectedProcesses) {
                    $proc | Stop-Process -Force -ErrorAction Stop
                    Write-EDRLog "KILLED: $($proc.ProcessName) (PID $($Analysis.ProcessId))" 'CRITICAL'
                    $actions.Add("Killed:$($proc.ProcessName)") | Out-Null
                    $Script:Stats.ThreatsBlocked++
                }
                else {
                    Write-EDRLog "SKIPPED KILL: $procName is protected" 'WARN'
                }
            }
        }
        catch {
            Write-EDRLog "Kill failed for PID $($Analysis.ProcessId): $_" 'WARN'
        }
    }

    # Quarantine file (Malicious+ verdict)
    if ($Score -ge $Script:EDR.QuarantineThreshold -and $Analysis.FilePath -and
        -not (Test-IsExcludedPath $Analysis.FilePath)) {
        try {
            if (Test-Path $Analysis.FilePath) {
                if (-not (Test-Path $Script:EDR.QuarantinePath)) {
                    New-Item -ItemType Directory -Path $Script:EDR.QuarantinePath -Force | Out-Null
                }
                $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
                $origName = [System.IO.Path]::GetFileName($Analysis.FilePath)
                $qPath = Join-Path $Script:EDR.QuarantinePath "${ts}_${origName}.quarantined"

                # Save metadata
                @{
                    OriginalPath  = $Analysis.FilePath
                    QuarantinedAt = (Get-Date -Format 'o')
                    Score         = $Score
                    Verdict       = $Verdict
                } | ConvertTo-Json -Depth 5 | Set-Content "${qPath}.meta.json" -Encoding UTF8

                Move-Item -Path $Analysis.FilePath -Destination $qPath -Force
                Write-EDRLog "QUARANTINED: $($Analysis.FilePath) -> $qPath" 'CRITICAL'
                $actions.Add("Quarantined:$origName") | Out-Null
                $Script:Stats.ThreatsBlocked++
            }
        }
        catch {
            Write-EDRLog "Quarantine failed for $($Analysis.FilePath): $_" 'WARN'
        }
    }

    # Block suspicious IPs via firewall
    if ($Score -ge $Script:EDR.QuarantineThreshold -and
        $Analysis.NetworkResults -and $Analysis.NetworkResults.SuspiciousConns.Count -gt 0) {
        foreach ($conn in $Analysis.NetworkResults.SuspiciousConns) {
            try {
                $ip = $conn.RemoteAddress
                $ruleName = "GorstaksEDR_Block_$ip"
                if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
                    New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block `
                        -RemoteAddress $ip -ErrorAction Stop | Out-Null
                    Write-EDRLog "BLOCKED IP: $ip (outbound)" 'CRITICAL'
                    $actions.Add("Blocked:$ip") | Out-Null
                }
            }
            catch { }
        }
    }

    if ($actions.Count -eq 0) { return 'None' }
    return ($actions -join '; ')
}

# ═══════════════════════════════════════════════════════════════
# SECTION 19: FULL ANALYSIS ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════
function Invoke-FullAnalysis {
    param(
        [string]$FilePath,
        [int]$ProcessId,
        [string]$CommandLine
    )

    if (Test-IsSelfProcess $ProcessId) { return $null }
    if (Test-IsExcludedPath $FilePath) { return $null }

    $result = [PSCustomObject]@{
        AnalysisId      = [guid]::NewGuid().ToString('N').Substring(0, 12)
        Timestamp       = Get-Date
        FilePath        = $FilePath
        ProcessId       = $ProcessId
        CommandLine     = $CommandLine
        StaticResults   = $null
        BehaviorResults = $null
        MitreMapping    = @()
        YaraMatches     = @()
        NetworkResults  = $null
        ChainResults    = $null
        MemoryResults   = $null
        HashRepResults  = $null
        TotalScore      = 0
        Verdict         = 'Clean'
        ResponseTaken   = 'None'
    }

    # Static analysis
    if ($FilePath -and (Test-Path $FilePath -ErrorAction SilentlyContinue)) {
        $result.StaticResults = Invoke-StaticAnalysis -FilePath $FilePath
    }

    # Hash reputation
    if ($result.StaticResults -and $result.StaticResults.Hashes.SHA256) {
        $result.HashRepResults = Get-HashReputation -SHA256 $result.StaticResults.Hashes.SHA256
        if (Test-IsWhitelisted -FilePath $FilePath -SHA256 $result.StaticResults.Hashes.SHA256) {
            return $null
        }
    }

    # Behavior analysis
    if ($ProcessId -or $CommandLine) {
        $result.BehaviorResults = Invoke-BehaviorAnalysis -ProcessId $ProcessId -CommandLine $CommandLine -FilePath $FilePath
    }

    # YARA rules
    if ($FilePath -and (Test-Path $FilePath -ErrorAction SilentlyContinue)) {
        $result.YaraMatches = Invoke-YaraRuleScan -FilePath $FilePath -CommandLine $CommandLine
    }
    elseif ($CommandLine) {
        $result.YaraMatches = Invoke-YaraRuleScan -CommandLine $CommandLine
    }

    # MITRE mapping
    $result.MitreMapping = Get-MitreMapping -BehaviorResults $result.BehaviorResults -StaticResults $result.StaticResults

    # Network analysis
    if ($ProcessId) {
        $result.NetworkResults = Invoke-NetworkAnalysis -ProcessId $ProcessId
    }

    # Process chain analysis
    if ($ProcessId) {
        $result.ChainResults = Invoke-ChainAnalysis -ProcessId $ProcessId
    }

    # Memory scan
    if ($ProcessId) {
        $result.MemoryResults = Invoke-MemoryScan -ProcessId $ProcessId
    }

    # Score
    $scoreResult = Get-ThreatScore -A $result
    $result.TotalScore = $scoreResult.TotalScore
    $result.Verdict = $scoreResult.Verdict

    # Response
    $result.ResponseTaken = Invoke-ThreatResponse -Analysis $result -Score $result.TotalScore `
        -Verdict $result.Verdict -Confidence $scoreResult.Confidence

    # Log non-clean results
    if ($result.TotalScore -gt 0) {
        $mitre = ($result.MitreMapping | ForEach-Object { $_.TechniqueId }) -join ','
        $logLevel = switch ($result.Verdict) {
            'Critical' { 'CRITICAL' }
            'Malicious' { 'ALERT' }
            'Suspicious' { 'WARN' }
            default { 'INFO' }
        }
        Write-EDRLog "[$($result.AnalysisId)] Score=$($result.TotalScore) Verdict=$($result.Verdict) MITRE=[$mitre] Response=$($result.ResponseTaken)" $logLevel
    }

    return $result
}

# ═══════════════════════════════════════════════════════════════
# SECTION 20: ONE-SHOT SCAN
# ═══════════════════════════════════════════════════════════════
function Invoke-EDRScan {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path $Path)) {
        Write-Host "Path not found: $Path" -ForegroundColor Red
        return
    }

    $files = @()
    if (Test-Path $Path -PathType Container) {
        $files = Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -match '\.(exe|dll|ps1|bat|cmd|vbs|js|wsf|hta|scr|msi|sys)$' }
        Write-Host "Scanning $($files.Count) files in $Path..." -ForegroundColor Cyan
    }
    else {
        $files = @(Get-Item $Path)
        Write-Host "Scanning: $Path" -ForegroundColor Cyan
    }

    $threats = 0
    foreach ($file in $files) {
        $result = Invoke-FullAnalysis -FilePath $file.FullName
        if ($result -and $result.TotalScore -ge $Script:EDR.AlertThreshold) {
            $threats++
            $color = switch ($result.Verdict) {
                'Critical'   { 'Red' }
                'Malicious'  { 'DarkRed' }
                'Suspicious' { 'Yellow' }
                default      { 'White' }
            }
            Write-Host "  [$($result.Verdict)] $($file.FullName) (Score: $($result.TotalScore))" -ForegroundColor $color

            if ($result.StaticResults -and $result.StaticResults.Flags.Count -gt 0) {
                foreach ($flag in $result.StaticResults.Flags) {
                    Write-Host "    - $flag" -ForegroundColor DarkGray
                }
            }
            if ($result.YaraMatches -and $result.YaraMatches.Count -gt 0) {
                foreach ($ym in $result.YaraMatches) {
                    Write-Host "    - YARA: $($ym.RuleName) ($($ym.Severity))" -ForegroundColor DarkGray
                }
            }
        }
    }

    Write-Host "`nScan complete: $($files.Count) files scanned, $threats threat(s) found." -ForegroundColor Cyan
}

# ═══════════════════════════════════════════════════════════════
# SECTION 21: REAL-TIME MONITORS
# ═══════════════════════════════════════════════════════════════
function Start-ProcessMonitor {
    $started = $false

    # Attempt 1: WMI event (real-time, preferred)
    try {
        $sub = Register-WmiEvent -Query 'SELECT * FROM Win32_ProcessStartTrace' `
            -SourceIdentifier 'EDR_ProcessStart' -ErrorAction Stop -Action {
            $ev = $Event.SourceEventArgs.NewEvent
            $pid2 = $ev.ProcessID
            $name2 = $ev.ProcessName
            if ($pid2 -eq $Script:EDR.SelfPID) { return }
            try {
                $wp = Get-CimInstance Win32_Process -Filter "ProcessId=$pid2" -ErrorAction SilentlyContinue
                $cl = if ($wp) { $wp.CommandLine } else { '' }
                $pp = if ($wp) { $wp.ParentProcessId } else { 0 }
                $ep = if ($wp) { $wp.ExecutablePath } else { '' }
                $Script:ProcessTracker[$pid2] = @{
                    Name = $name2; CommandLine = $cl; ParentPID = $pp
                    ExePath = $ep; StartTime = Get-Date
                }
                Invoke-FullAnalysis -FilePath $ep -ProcessId $pid2 -CommandLine $cl
            }
            catch { }
        }
        $Script:ActiveWatchers.Add($sub) | Out-Null
        $started = $true
        Write-EDRLog 'Process monitor started (WMI event)' 'INFO'
    }
    catch {
        Write-EDRLog "WMI event failed: $_ — trying polling" 'WARN'
    }

    # Attempt 2: Polling fallback
    if (-not $started) {
        try {
            $Script:_KnownPids = @{}
            Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
                ForEach-Object { $Script:_KnownPids[$_.ProcessId] = $true }

            $timer = New-Object Timers.Timer
            $timer.Interval = $Script:EDR.ScanIntervalSec * 1000
            $timer.AutoReset = $true

            Register-ObjectEvent $timer Elapsed -SourceIdentifier 'EDR_ProcessPoll' -Action {
                try {
                    $current = @{}
                    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
                    foreach ($p in $procs) {
                        $current[$p.ProcessId] = $true
                        if (-not $Script:_KnownPids.ContainsKey($p.ProcessId)) {
                            if ($p.ProcessId -eq $Script:EDR.SelfPID) { continue }
                            $Script:ProcessTracker[$p.ProcessId] = @{
                                Name = $p.Name; CommandLine = $p.CommandLine
                                ParentPID = $p.ParentProcessId; ExePath = $p.ExecutablePath
                                StartTime = Get-Date
                            }
                            Invoke-FullAnalysis -FilePath $p.ExecutablePath -ProcessId $p.ProcessId -CommandLine $p.CommandLine
                        }
                    }
                    $Script:_KnownPids = $current
                }
                catch { }
            } | Out-Null

            $timer.Start()
            $Script:ActiveWatchers.Add($timer) | Out-Null
            $started = $true
            Write-EDRLog "Process monitor started (polling, ${Script:EDR.ScanIntervalSec}s)" 'INFO'
        }
        catch {
            Write-EDRLog "Polling fallback failed: $_" 'WARN'
        }
    }

    if (-not $started) {
        Write-EDRLog 'Process monitoring UNAVAILABLE' 'CRITICAL'
    }
}

function Start-FileMonitor {
    # Watch common user-writable paths (recursive, instant detection)
    $watchPaths = @(
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        "$env:TEMP",
        "$env:APPDATA",
        'C:\Users\Public'
    )

    foreach ($wp in $watchPaths) {
        if (-not (Test-Path $wp)) { continue }
        try {
            $w = [System.IO.FileSystemWatcher]::new($wp)
            $w.IncludeSubdirectories = $true
            $w.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite
            $w.EnableRaisingEvents = $true

            $created = Register-ObjectEvent $w Created -Action {
                $path2 = $Event.SourceEventArgs.FullPath
                if (Test-IsExcludedPath $path2) { return }
                $ext = [System.IO.Path]::GetExtension($path2).ToLower()
                if ($ext -in @('.exe','.dll','.ps1','.bat','.cmd','.vbs','.js','.wsf','.hta','.scr','.msi')) {
                    Start-Sleep -Milliseconds 500  # Let file finish writing
                    Invoke-FullAnalysis -FilePath $path2
                }
                Invoke-RansomwareCheck -EventType 'Created' -NewPath $path2
            }

            $renamed = Register-ObjectEvent $w Renamed -Action {
                Invoke-RansomwareCheck -EventType 'Renamed' `
                    -OldPath $Event.SourceEventArgs.OldFullPath `
                    -NewPath $Event.SourceEventArgs.FullPath
            }

            $Script:ActiveWatchers.Add($created) | Out-Null
            $Script:ActiveWatchers.Add($renamed) | Out-Null
        }
        catch {
            Write-EDRLog "FileMonitor failed for $wp : $_" 'WARN'
        }
    }

    # Watch all drive roots (non-recursive — catches files dropped at root level like D:\mimikatz.exe)
    $driveRoots = @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
        Where-Object { $_.Used -ne $null } |
        ForEach-Object { $_.Root })

    foreach ($root in $driveRoots) {
        if (-not (Test-Path $root)) { continue }
        try {
            $w = [System.IO.FileSystemWatcher]::new($root)
            $w.IncludeSubdirectories = $false  # Root level only — lightweight
            $w.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite
            $w.EnableRaisingEvents = $true

            $created = Register-ObjectEvent $w Created -Action {
                $path2 = $Event.SourceEventArgs.FullPath
                if (Test-IsExcludedPath $path2) { return }
                $ext = [System.IO.Path]::GetExtension($path2).ToLower()
                if ($ext -in @('.exe','.dll','.ps1','.bat','.cmd','.vbs','.js','.wsf','.hta','.scr','.msi')) {
                    Start-Sleep -Milliseconds 500
                    Invoke-FullAnalysis -FilePath $path2
                }
            }

            $Script:ActiveWatchers.Add($created) | Out-Null
        }
        catch {
            Write-EDRLog "DriveRoot watcher failed for $root : $_" 'WARN'
        }
    }

    Write-EDRLog "File monitor started ($($watchPaths.Count) deep paths + $($driveRoots.Count) drive roots)" 'INFO'
}

# Periodic sweep of all drives for new executables (catches files dropped anywhere)
function Start-DriveSweep {
    $Script:_SweepKnownFiles = @{}

    $timer = New-Object Timers.Timer
    $timer.Interval = $Script:EDR.DriveSweepSec * 1000
    $timer.AutoReset = $true

    Register-ObjectEvent $timer Elapsed -SourceIdentifier 'EDR_DriveSweep' -Action {
        try {
            $scanExts = @('*.exe','*.dll','*.scr','*.ps1','*.bat','*.cmd','*.vbs','*.js','*.hta','*.msi')
            $drives = @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
                Where-Object { $_.Used -ne $null } |
                ForEach-Object { $_.Root })

            foreach ($drive in $drives) {
                # Scan root level of every drive
                foreach ($ext in $scanExts) {
                    $files = Get-ChildItem -Path $drive -Filter $ext -File -ErrorAction SilentlyContinue
                    foreach ($file in $files) {
                        if (Test-IsExcludedPath $file.FullName) { continue }
                        $key = $file.FullName.ToLower()
                        $mtime = $file.LastWriteTimeUtc.Ticks
                        if ($Script:_SweepKnownFiles.ContainsKey($key) -and
                            $Script:_SweepKnownFiles[$key] -eq $mtime) { continue }
                        $Script:_SweepKnownFiles[$key] = $mtime
                        Invoke-FullAnalysis -FilePath $file.FullName
                    }
                }

                # Also scan common drop locations on each drive
                $dropPaths = @(
                    (Join-Path $drive 'Temp'),
                    (Join-Path $drive 'tmp'),
                    (Join-Path $drive 'Tools'),
                    (Join-Path $drive 'Users\Public')
                )
                foreach ($dp in $dropPaths) {
                    if (-not (Test-Path $dp)) { continue }
                    foreach ($ext in $scanExts) {
                        $files = Get-ChildItem -Path $dp -Filter $ext -File -Recurse -Depth 2 -ErrorAction SilentlyContinue
                        foreach ($file in $files) {
                            if (Test-IsExcludedPath $file.FullName) { continue }
                            $key = $file.FullName.ToLower()
                            $mtime = $file.LastWriteTimeUtc.Ticks
                            if ($Script:_SweepKnownFiles.ContainsKey($key) -and
                                $Script:_SweepKnownFiles[$key] -eq $mtime) { continue }
                            $Script:_SweepKnownFiles[$key] = $mtime
                            Invoke-FullAnalysis -FilePath $file.FullName
                        }
                    }
                }
            }
        }
        catch {
            Write-EDRLog "Drive sweep error: $_" 'WARN'
        }
    } | Out-Null

    $timer.Start()
    $Script:ActiveWatchers.Add($timer) | Out-Null
    Write-EDRLog "Drive sweep started (every $($Script:EDR.DriveSweepSec)s)" 'INFO'
}

function Start-ChainCleanup {
    $timer = New-Object Timers.Timer
    $timer.Interval = 60000
    $timer.AutoReset = $true

    Register-ObjectEvent $timer Elapsed -SourceIdentifier 'EDR_ChainCleanup' -Action {
        $cutoff = (Get-Date).AddSeconds(-$Script:EDR.ChainTTLSec)
        $stale = @($Script:ProcessTracker.Keys | Where-Object {
            $Script:ProcessTracker[$_].StartTime -lt $cutoff
        })
        foreach ($key in $stale) { $Script:ProcessTracker.Remove($key) }

        # Also trim beacon tracker
        $beaconCutoff = (Get-Date).AddMinutes(-10)
        foreach ($key in @($Script:BeaconTracker.Keys)) {
            $Script:BeaconTracker[$key] = [System.Collections.ArrayList]@(
                $Script:BeaconTracker[$key] | Where-Object { $_ -gt $beaconCutoff }
            )
            if ($Script:BeaconTracker[$key].Count -eq 0) {
                $Script:BeaconTracker.Remove($key)
            }
        }
    } | Out-Null

    $timer.Start()
    $Script:ActiveWatchers.Add($timer) | Out-Null
}

function Start-IntegrityWatchdog {
    $timer = New-Object Timers.Timer
    $timer.Interval = $Script:EDR.IntegrityCheckSec * 1000
    $timer.AutoReset = $true

    Register-ObjectEvent $timer Elapsed -SourceIdentifier 'EDR_Integrity' -Action {
        Test-SelfIntegrity
    } | Out-Null

    $timer.Start()
    $Script:ActiveWatchers.Add($timer) | Out-Null
}

# ═══════════════════════════════════════════════════════════════
# SECTION 22: DASHBOARD
# ═══════════════════════════════════════════════════════════════
function Show-EDRDashboard {
    $uptime = (Get-Date) - $Script:Stats.StartTime
    $mode = if ($Script:EDR.AutoRespond) { 'AUTO-RESPOND' } else { 'MONITOR-ONLY' }

    Write-Host ''
    Write-Host '  ╔══════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '  ║         GorstaksEDR v2.0 Dashboard          ║' -ForegroundColor Cyan
    Write-Host '  ╚══════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''
    Write-Host "  Mode:               $mode" -ForegroundColor $(if ($Script:EDR.AutoRespond) { 'Red' } else { 'Green' })
    Write-Host "  Uptime:             $([int]$uptime.TotalHours)h $($uptime.Minutes)m"
    Write-Host "  Processes analyzed: $($Script:Stats.ProcessesAnalyzed)"
    Write-Host "  Files scanned:     $($Script:Stats.FilesScanned)"
    Write-Host "  Alerts generated:  $($Script:Stats.AlertsGenerated)"
    Write-Host "  Threats blocked:   $($Script:Stats.ThreatsBlocked)"
    Write-Host "  Active watchers:   $($Script:ActiveWatchers.Count)"
    Write-Host "  Process tracker:   $($Script:ProcessTracker.Count) entries"
    Write-Host ''

    if ($Script:AlertHistory.Count -gt 0) {
        Write-Host '  Recent Alerts:' -ForegroundColor Yellow
        $recent = $Script:AlertHistory | Select-Object -Last 5
        foreach ($a in $recent) {
            $color = switch ($a.Verdict) {
                'Critical'   { 'Red' }
                'Malicious'  { 'DarkRed' }
                'Suspicious' { 'Yellow' }
                default      { 'White' }
            }
            Write-Host "    [$($a.Verdict)] Score=$($a.Score) $($a.Target)" -ForegroundColor $color
        }
        Write-Host ''
    }
}

# ═══════════════════════════════════════════════════════════════
# SECTION 23: EXPORTED FUNCTIONS
# ═══════════════════════════════════════════════════════════════
function Start-EDR {
    # Ensure directories
    foreach ($dir in @($Script:EDR.LogPath, $Script:EDR.QuarantinePath, $Script:EDR.AlertPath)) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }

    # Initialize engines
    Initialize-SelfIntegrity
    Initialize-PInvoke
    Initialize-AMSI
    Initialize-Whitelist
    Initialize-WhitelistTamperDetection
    Initialize-HashRepDB

    # Anti-circumvention (ported from GEdr)
    Protect-EDRProcess
    Test-EtwIntegrity

    # Start monitors
    Start-ProcessMonitor
    Start-FileMonitor
    Start-DriveSweep
    Start-ChainCleanup
    Start-IntegrityWatchdog

    $mode = if ($Script:EDR.AutoRespond) { 'AUTO-RESPOND (kill/quarantine/block enabled)' } else { 'MONITOR-ONLY (alerts only)' }
    Write-EDRLog "=== GorstaksEDR v$($Script:EDR.Version) Started ===" 'INFO'
    Write-EDRLog "Mode: $mode" 'INFO'
    Write-EDRLog "PID: $PID" 'INFO'
    Write-Host ''
    Write-Host "  GorstaksEDR v$($Script:EDR.Version) running [$mode]" -ForegroundColor Green
    Write-Host "  PID: $PID | Log: $($Script:EDR.LogPath)" -ForegroundColor DarkGray
    Write-Host "  Press Ctrl+C to stop." -ForegroundColor DarkGray
    Write-Host ''
}

function Stop-EDR {
    Write-EDRLog 'Shutting down GorstaksEDR...' 'INFO'

    foreach ($w in $Script:ActiveWatchers) {
        try {
            if ($w -is [System.Timers.Timer]) { $w.Stop(); $w.Dispose() }
            elseif ($w.Name) { Unregister-Event -SourceIdentifier $w.Name -ErrorAction SilentlyContinue }
        }
        catch { }
    }
    $Script:ActiveWatchers.Clear()

    # Clean up AMSI
    if ($Script:AMSIAvailable -and $Script:AMSIContext -ne [IntPtr]::Zero) {
        try { [AMSINative]::AmsiUninitialize($Script:AMSIContext) } catch { }
    }

    Write-EDRLog '=== GorstaksEDR Stopped ===' 'INFO'
    Write-Host '  GorstaksEDR stopped.' -ForegroundColor Yellow
}

# ═══════════════════════════════════════════════════════════════
# SECTION 24: MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════
if ($Install) {
    Install-EDR
    return
}

if ($Uninstall) {
    Uninstall-EDR
    return
}

if ($ScanPath) {
    # Initialize engines for one-shot scan
    Initialize-SelfIntegrity
    Initialize-PInvoke
    Initialize-AMSI
    Initialize-Whitelist
    Initialize-HashRepDB
    Invoke-EDRScan -Path $ScanPath
    return
}

# Default: start real-time monitoring
Start-EDR

try {
    while ($true) {
        Test-SelfIntegrity
        Test-WhitelistTamper
        Test-DebuggerAttached
        Test-EtwIntegrity
        Start-Sleep -Seconds $Script:EDR.MainLoopSec
    }
}
finally {
    Stop-EDR
}
