#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Local VirusTotal-like EDR - Core Engine
.DESCRIPTION
    Main orchestrator that ties together all detection modules:
    Static Analysis, Behavior Engine, MITRE Mapping, YARA Rules,
    Network Monitor, Scoring Engine, and Response Engine.
#>

# ── Configuration ──────────────────────────────────────────────
$Script:EDRConfig = @{
    LogPath          = "$PSScriptRoot\Logs"
    QuarantinePath   = "$PSScriptRoot\Quarantine"
    RulesPath        = "$PSScriptRoot\Rules"
    WatchPaths       = @("C:\Users", "C:\Temp", "C:\Windows\Temp")
    ScanIntervalSec  = 5
    ScoreThresholds  = @{
        Clean      = 0
        Low        = 25
        Suspicious = 50
        Malicious  = 80
        Critical   = 100
    }
    MaxLogSizeMB     = 50
    EnableRealTime   = $true
    EnableNetwork    = $true
    EnablePseudoSandbox = $true
    SandboxTimeoutSec   = 30
}

# ── Global State ───────────────────────────────────────────────
$Script:ProcessTracker   = @{}   # PID -> tracking info
$Script:AlertHistory     = [System.Collections.ArrayList]::new()
$Script:ActiveWatchers   = [System.Collections.ArrayList]::new()
$Script:MitreFindings    = [System.Collections.ArrayList]::new()

# ── Import Modules ─────────────────────────────────────────────
. "$PSScriptRoot\StaticAnalysis.ps1"
. "$PSScriptRoot\BehaviorEngine.ps1"
. "$PSScriptRoot\MitreMapper.ps1"
. "$PSScriptRoot\YaraEngine.ps1"
. "$PSScriptRoot\NetworkMonitor.ps1"
. "$PSScriptRoot\ScoringEngine.ps1"
. "$PSScriptRoot\ResponseEngine.ps1"
. "$PSScriptRoot\PseudoSandbox.ps1"

# ── Logging ────────────────────────────────────────────────────
function Write-EDRLog {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ALERT","CRITICAL","DEBUG")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $entry = "[$timestamp] [$Level] $Message"

    if (-not (Test-Path $Script:EDRConfig.LogPath)) {
        New-Item -ItemType Directory -Path $Script:EDRConfig.LogPath -Force | Out-Null
    }

    $logFile = Join-Path $Script:EDRConfig.LogPath "edr_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $entry

    switch ($Level) {
        "CRITICAL" { Write-Host $entry -ForegroundColor Red }
        "ALERT"    { Write-Host $entry -ForegroundColor Yellow }
        "WARN"     { Write-Host $entry -ForegroundColor DarkYellow }
        "DEBUG"    { Write-Host $entry -ForegroundColor Gray }
        default    { Write-Host $entry -ForegroundColor Cyan }
    }
}

# ── Core Analysis Pipeline ─────────────────────────────────────
function Invoke-FullAnalysis {
    <#
    .SYNOPSIS
        Run the complete analysis pipeline on a file or process,
        similar to how VirusTotal processes a submission.
    #>
    param(
        [string]$FilePath,
        [int]$ProcessId,
        [string]$CommandLine
    )

    $analysisId = [guid]::NewGuid().ToString("N").Substring(0, 12)
    $result = [PSCustomObject]@{
        AnalysisId     = $analysisId
        Timestamp      = Get-Date
        FilePath       = $FilePath
        ProcessId      = $ProcessId
        CommandLine    = $CommandLine
        StaticResults  = $null
        BehaviorResults = $null
        MitreMapping   = @()
        YaraMatches    = @()
        NetworkResults = $null
        TotalScore     = 0
        Verdict        = "Clean"
        ResponseTaken  = "None"
    }

    Write-EDRLog "Starting analysis [$analysisId] File=$FilePath PID=$ProcessId" "INFO"

    # ── Stage 1: Static Analysis ───────────────────────────────
    if ($FilePath -and (Test-Path $FilePath)) {
        Write-EDRLog "[$analysisId] Stage 1: Static Analysis" "INFO"
        $result.StaticResults = Invoke-StaticAnalysis -FilePath $FilePath
    }

    # ── Stage 2: Behavior Analysis ─────────────────────────────
    if ($ProcessId -or $CommandLine) {
        Write-EDRLog "[$analysisId] Stage 2: Behavior Analysis" "INFO"
        $result.BehaviorResults = Invoke-BehaviorAnalysis `
            -ProcessId $ProcessId `
            -CommandLine $CommandLine `
            -FilePath $FilePath
    }

    # ── Stage 3: YARA Rule Matching ────────────────────────────
    if ($FilePath -and (Test-Path $FilePath)) {
        Write-EDRLog "[$analysisId] Stage 3: YARA Rule Matching" "INFO"
        $result.YaraMatches = Invoke-YaraRuleScan -FilePath $FilePath -CommandLine $CommandLine
    } elseif ($CommandLine) {
        $result.YaraMatches = Invoke-YaraRuleScan -CommandLine $CommandLine
    }

    # ── Stage 4: MITRE Mapping ─────────────────────────────────
    Write-EDRLog "[$analysisId] Stage 4: MITRE ATT&CK Mapping" "INFO"
    $result.MitreMapping = Get-MitreMapping `
        -BehaviorResults $result.BehaviorResults `
        -StaticResults $result.StaticResults `
        -CommandLine $CommandLine

    # ── Stage 5: Network Analysis ──────────────────────────────
    if ($Script:EDRConfig.EnableNetwork -and $ProcessId) {
        Write-EDRLog "[$analysisId] Stage 5: Network Analysis" "INFO"
        $result.NetworkResults = Invoke-NetworkAnalysis -ProcessId $ProcessId
    }

    # ── Stage 6: Scoring ───────────────────────────────────────
    Write-EDRLog "[$analysisId] Stage 6: Scoring" "INFO"
    $scoreResult = Get-ThreatScore -AnalysisResult $result
    $result.TotalScore = $scoreResult.TotalScore
    $result.Verdict    = $scoreResult.Verdict

    # ── Stage 7: Response ──────────────────────────────────────
    Write-EDRLog "[$analysisId] Stage 7: Response (Score=$($result.TotalScore) Verdict=$($result.Verdict))" "INFO"
    $result.ResponseTaken = Invoke-ThreatResponse `
        -AnalysisResult $result `
        -Score $result.TotalScore `
        -Verdict $result.Verdict

    # ── Log final result ───────────────────────────────────────
    $logLevel = switch ($result.Verdict) {
        "Critical"   { "CRITICAL" }
        "Malicious"  { "ALERT" }
        "Suspicious" { "WARN" }
        default      { "INFO" }
    }
    Write-EDRLog ("[$analysisId] COMPLETE: Score={0} Verdict={1} MITRE=[{2}] Response={3}" -f `
        $result.TotalScore, $result.Verdict, `
        (($result.MitreMapping | ForEach-Object { $_.TechniqueId }) -join ","), `
        $result.ResponseTaken) $logLevel

    $Script:AlertHistory.Add($result) | Out-Null
    return $result
}

# ── Real-Time Process Monitor ──────────────────────────────────
function Start-ProcessMonitor {
    <#
    .SYNOPSIS
        Watch for new process creation events and analyze them in real time.
    #>
    Write-EDRLog "Starting real-time process monitor" "INFO"

    $query = "SELECT * FROM Win32_ProcessStartTrace"
    $action = {
        $proc = $Event.SourceEventArgs.NewEvent
        $pid  = $proc.ProcessID
        $name = $proc.ProcessName

        try {
            $wmiProc = Get-CimInstance Win32_Process -Filter "ProcessId=$pid" -ErrorAction SilentlyContinue
            $cmdLine = if ($wmiProc) { $wmiProc.CommandLine } else { "" }
            $parentPid = if ($wmiProc) { $wmiProc.ParentProcessId } else { 0 }
            $exePath = if ($wmiProc) { $wmiProc.ExecutablePath } else { "" }

            # Track the process
            $Script:ProcessTracker[$pid] = @{
                Name        = $name
                CommandLine = $cmdLine
                ParentPID   = $parentPid
                ExePath     = $exePath
                StartTime   = Get-Date
                Children    = @()
            }

            # Track parent-child relationship
            if ($Script:ProcessTracker.ContainsKey($parentPid)) {
                $Script:ProcessTracker[$parentPid].Children += $pid
            }

            # Run analysis pipeline
            Invoke-FullAnalysis -FilePath $exePath -ProcessId $pid -CommandLine $cmdLine

        } catch {
            Write-EDRLog "Error analyzing PID $pid : $_" "WARN"
        }
    }

    $sub = Register-WmiEvent -Query $query -Action $action -SourceIdentifier "EDR_ProcessMonitor"
    $Script:ActiveWatchers.Add($sub) | Out-Null
    Write-EDRLog "Process monitor registered" "INFO"
}

# ── File System Monitor ────────────────────────────────────────
function Start-FileMonitor {
    <#
    .SYNOPSIS
        Watch configured directories for new or modified files.
    #>
    foreach ($watchPath in $Script:EDRConfig.WatchPaths) {
        if (-not (Test-Path $watchPath)) { continue }

        $watcher = [System.IO.FileSystemWatcher]::new($watchPath)
        $watcher.IncludeSubdirectories = $true
        $watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor
                                [System.IO.NotifyFilters]::LastWrite
        $watcher.EnableRaisingEvents = $true

        $createdAction = Register-ObjectEvent $watcher Created -Action {
            $path = $Event.SourceEventArgs.FullPath
            $ext  = [System.IO.Path]::GetExtension($path).ToLower()

            # Only analyze executable-like files
            $riskyExtensions = @('.exe','.dll','.ps1','.bat','.cmd','.vbs',
                                 '.js','.wsf','.hta','.scr','.pif','.msi')
            if ($ext -in $riskyExtensions) {
                Write-EDRLog "New file detected: $path" "WARN"
                Start-Sleep -Milliseconds 500  # Let file finish writing
                Invoke-FullAnalysis -FilePath $path
            }
        }

        $Script:ActiveWatchers.Add($createdAction) | Out-Null
        Write-EDRLog "File monitor started for: $watchPath" "INFO"
    }
}

# ── Manual Scan ────────────────────────────────────────────────
function Invoke-EDRScan {
    <#
    .SYNOPSIS
        Manually scan a file or directory (like uploading to VirusTotal).
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (Test-Path $Path -PathType Container) {
        Write-EDRLog "Scanning directory: $Path" "INFO"
        $files = Get-ChildItem -Path $Path -Recurse -File
        $results = foreach ($file in $files) {
            Invoke-FullAnalysis -FilePath $file.FullName
        }
        return $results
    }
    elseif (Test-Path $Path -PathType Leaf) {
        Write-EDRLog "Scanning file: $Path" "INFO"
        return Invoke-FullAnalysis -FilePath $Path
    }
    else {
        Write-EDRLog "Path not found: $Path" "WARN"
    }
}

# ── Dashboard ──────────────────────────────────────────────────
function Show-EDRDashboard {
    <#
    .SYNOPSIS
        Display a summary of current EDR state and recent alerts.
    #>
    $header = @"

╔══════════════════════════════════════════════════════════════╗
║                   LOCAL EDR DASHBOARD                       ║
║              VirusTotal-Style Threat Analysis                ║
╚══════════════════════════════════════════════════════════════╝
"@
    Write-Host $header -ForegroundColor Cyan

    Write-Host "`n── Active Monitors ──" -ForegroundColor Green
    Write-Host "  Watchers active : $($Script:ActiveWatchers.Count)"
    Write-Host "  Processes tracked: $($Script:ProcessTracker.Count)"
    Write-Host "  Total alerts     : $($Script:AlertHistory.Count)"

    $recent = $Script:AlertHistory |
        Sort-Object Timestamp -Descending |
        Select-Object -First 10

    if ($recent) {
        Write-Host "`n── Recent Alerts (last 10) ──" -ForegroundColor Yellow
        foreach ($alert in $recent) {
            $color = switch ($alert.Verdict) {
                "Critical"   { "Red" }
                "Malicious"  { "DarkRed" }
                "Suspicious" { "Yellow" }
                default      { "Gray" }
            }
            $mitre = ($alert.MitreMapping | ForEach-Object { $_.TechniqueId }) -join ","
            Write-Host ("  [{0}] Score={1,-3} Verdict={2,-11} MITRE=[{3}] {4}" -f `
                $alert.Timestamp.ToString("HH:mm:ss"),
                $alert.TotalScore,
                $alert.Verdict,
                $mitre,
                ($alert.FilePath ?? $alert.CommandLine ?? "PID:$($alert.ProcessId)")
            ) -ForegroundColor $color
        }
    }

    # MITRE technique summary
    $allMitre = $Script:AlertHistory |
        ForEach-Object { $_.MitreMapping } |
        Where-Object { $_ } |
        Group-Object TechniqueId |
        Sort-Object Count -Descending |
        Select-Object -First 10

    if ($allMitre) {
        Write-Host "`n── Top MITRE Techniques Observed ──" -ForegroundColor Magenta
        foreach ($t in $allMitre) {
            $name = ($Script:AlertHistory |
                ForEach-Object { $_.MitreMapping } |
                Where-Object { $_.TechniqueId -eq $t.Name } |
                Select-Object -First 1).TechniqueName
            Write-Host "  $($t.Name) ($name) - $($t.Count) hits"
        }
    }
}

# ── Start / Stop ───────────────────────────────────────────────
function Start-EDR {
    <#
    .SYNOPSIS
        Initialize and start all EDR monitoring components.
    #>
    Write-Host @"

    ██╗      ██████╗  ██████╗ █████╗ ██╗         ███████╗██████╗ ██████╗
    ██║     ██╔═══██╗██╔════╝██╔══██╗██║         ██╔════╝██╔══██╗██╔══██╗
    ██║     ██║   ██║██║     ███████║██║         █████╗  ██║  ██║██████╔╝
    ██║     ██║   ██║██║     ██╔══██║██║         ██╔══╝  ██║  ██║██╔══██╗
    ███████╗╚██████╔╝╚██████╗██║  ██║███████╗    ███████╗██████╔╝██║  ██║
    ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝    ╚══════╝╚═════╝ ╚═╝  ╚═╝

"@ -ForegroundColor Red

    Write-EDRLog "═══ EDR Engine Starting ═══" "INFO"

    # Ensure directories exist
    foreach ($dir in @($Script:EDRConfig.LogPath, $Script:EDRConfig.QuarantinePath, $Script:EDRConfig.RulesPath)) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }

    # Load YARA rules
    Initialize-YaraEngine

    if ($Script:EDRConfig.EnableRealTime) {
        Start-ProcessMonitor
        Start-FileMonitor
    }

    if ($Script:EDRConfig.EnableNetwork) {
        Start-NetworkMonitor
    }

    Write-EDRLog "═══ EDR Engine Ready ═══" "INFO"
    Show-EDRDashboard
}

function Stop-EDR {
    <#
    .SYNOPSIS
        Gracefully shut down all EDR monitoring components.
    #>
    Write-EDRLog "═══ EDR Engine Stopping ═══" "INFO"

    # Unregister all event subscriptions
    Get-EventSubscriber | Where-Object { $_.SourceIdentifier -like "EDR_*" } |
        Unregister-Event

    $Script:ActiveWatchers.Clear()
    $Script:ProcessTracker.Clear()

    Write-EDRLog "═══ EDR Engine Stopped ═══" "INFO"
}

# ── Exports ────────────────────────────────────────────────────
Export-ModuleMember -Function @(
    'Start-EDR',
    'Stop-EDR',
    'Invoke-EDRScan',
    'Invoke-FullAnalysis',
    'Show-EDRDashboard',
    'Write-EDRLog'
) -ErrorAction SilentlyContinue
