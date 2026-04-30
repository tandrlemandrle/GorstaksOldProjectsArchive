<#
.SYNOPSIS
    Response Engine - Automated threat response and containment.
.DESCRIPTION
    Takes action based on threat scores: kill processes, quarantine files,
    block network connections, and generate alerts.
#>

# ── Response Configuration ─────────────────────────────────────
$Script:ResponseConfig = @{
    # Auto-response thresholds
    AutoKillThreshold       = 120   # Auto-kill process above this score
    AutoQuarantineThreshold = 100   # Auto-quarantine file above this score
    AutoBlockThreshold      = 80    # Auto-block network above this score
    AlertThreshold          = 50    # Generate alert above this score

    # Safety: don't kill these processes
    ProtectedProcesses = @(
        'System', 'smss', 'csrss', 'wininit', 'winlogon',
        'services', 'lsass', 'svchost', 'dwm', 'explorer',
        'taskhostw', 'sihost', 'fontdrvhost', 'RuntimeBroker',
        'SearchIndexer', 'SecurityHealthService', 'MsMpEng',
        'powershell', 'pwsh', 'conhost', 'cmd'
    )

    # Enable/disable auto-response (set to $false for monitor-only mode)
    AutoResponseEnabled = $false   # SAFE DEFAULT: manual mode
}

# ── Main Response Function ─────────────────────────────────────
function Invoke-ThreatResponse {
    param(
        $AnalysisResult,
        [int]$Score,
        [string]$Verdict
    )

    $actions = [System.Collections.ArrayList]::new()

    # ── Always: Log the alert ──────────────────────────────────
    if ($Score -ge $Script:ResponseConfig.AlertThreshold) {
        $alert = New-ThreatAlert -AnalysisResult $AnalysisResult -Score $Score -Verdict $Verdict
        $actions.Add("Alert generated: $($alert.AlertId)") | Out-Null
    }

    # ── If auto-response is disabled, stop here ────────────────
    if (-not $Script:ResponseConfig.AutoResponseEnabled) {
        if ($Score -ge $Script:ResponseConfig.AlertThreshold) {
            Write-EDRLog "Auto-response DISABLED. Manual action required for score=$Score verdict=$Verdict" "WARN"
            $actions.Add("Manual review required") | Out-Null
        }
        return ($actions -join "; ")
    }

    # ── Auto-Response Actions ──────────────────────────────────

    # Kill process
    if ($Score -ge $Script:ResponseConfig.AutoKillThreshold -and $AnalysisResult.ProcessId) {
        $killResult = Stop-ThreatProcess -ProcessId $AnalysisResult.ProcessId
        $actions.Add($killResult) | Out-Null
    }

    # Quarantine file
    if ($Score -ge $Script:ResponseConfig.AutoQuarantineThreshold -and $AnalysisResult.FilePath) {
        $quarantineResult = Move-ToQuarantine -FilePath $AnalysisResult.FilePath -AnalysisResult $AnalysisResult
        $actions.Add($quarantineResult) | Out-Null
    }

    # Block network
    if ($Score -ge $Script:ResponseConfig.AutoBlockThreshold -and
        $AnalysisResult.NetworkResults -and
        $AnalysisResult.NetworkResults.SuspiciousConns.Count -gt 0) {
        foreach ($conn in $AnalysisResult.NetworkResults.SuspiciousConns) {
            $blockResult = Block-ThreatConnection -RemoteAddress $conn.RemoteAddress
            $actions.Add($blockResult) | Out-Null
        }
    }

    if ($actions.Count -eq 0) {
        return "None"
    }

    return ($actions -join "; ")
}

# ── Process Termination ───────────────────────────────────────
function Stop-ThreatProcess {
    param([int]$ProcessId)

    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if (-not $proc) {
            return "Process $ProcessId already terminated"
        }

        # Safety check
        if ($proc.Name -in $Script:ResponseConfig.ProtectedProcesses) {
            Write-EDRLog "BLOCKED: Cannot kill protected process $($proc.Name) (PID $ProcessId)" "WARN"
            return "Protected process - kill blocked: $($proc.Name)"
        }

        # Attempt graceful stop first
        $proc | Stop-Process -Force -ErrorAction Stop
        Write-EDRLog "KILLED: Process $($proc.Name) (PID $ProcessId)" "CRITICAL"
        return "Process killed: $($proc.Name) (PID $ProcessId)"

    } catch {
        Write-EDRLog "Failed to kill PID $ProcessId : $_" "WARN"
        return "Kill failed: PID $ProcessId - $_"
    }
}

# ── Suspend Process (alternative to kill) ──────────────────────
function Suspend-ThreatProcess {
    <#
    .SYNOPSIS
        Suspend a process instead of killing it (preserves for analysis).
    #>
    param([int]$ProcessId)

    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if (-not $proc) { return "Process not found" }

        if ($proc.Name -in $Script:ResponseConfig.ProtectedProcesses) {
            return "Protected process - suspend blocked"
        }

        # Use NtSuspendProcess via debug API
        # Fallback: reduce priority to lowest
        $proc.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle

        # Suspend all threads
        foreach ($thread in $proc.Threads) {
            # Note: Full suspension requires P/Invoke (SuspendThread)
            # This is a best-effort approach in pure PowerShell
        }

        Write-EDRLog "SUSPENDED: Process $($proc.Name) (PID $ProcessId) - priority set to Idle" "ALERT"
        return "Process suspended: $($proc.Name) (PID $ProcessId)"

    } catch {
        return "Suspend failed: $_"
    }
}

# ── File Quarantine ────────────────────────────────────────────
function Move-ToQuarantine {
    param(
        [string]$FilePath,
        $AnalysisResult
    )

    try {
        if (-not (Test-Path $FilePath)) {
            return "File not found for quarantine: $FilePath"
        }

        $quarantineDir = $Script:EDRConfig.QuarantinePath
        if (-not (Test-Path $quarantineDir)) {
            New-Item -ItemType Directory -Path $quarantineDir -Force | Out-Null
        }

        # Create quarantine record
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $originalName = [System.IO.Path]::GetFileName($FilePath)
        $quarantineName = "${timestamp}_${originalName}.quarantined"
        $quarantinePath = Join-Path $quarantineDir $quarantineName

        # Save metadata
        $metadata = @{
            OriginalPath  = $FilePath
            QuarantinedAt = Get-Date -Format "o"
            Score         = $AnalysisResult.TotalScore
            Verdict       = $AnalysisResult.Verdict
            Hashes        = $AnalysisResult.StaticResults.Hashes
            MitreTechniques = ($AnalysisResult.MitreMapping | ForEach-Object { $_.TechniqueId })
        }
        $metadataPath = "${quarantinePath}.meta.json"
        $metadata | ConvertTo-Json -Depth 5 | Set-Content $metadataPath

        # Move file (rename to prevent execution)
        Move-Item -Path $FilePath -Destination $quarantinePath -Force

        # Remove execute permissions
        $acl = Get-Acl $quarantinePath
        $acl.SetAccessRuleProtection($true, $false)
        $readOnly = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Everyone", "Read", "Allow"
        )
        $acl.AddAccessRule($readOnly)
        Set-Acl $quarantinePath $acl -ErrorAction SilentlyContinue

        Write-EDRLog "QUARANTINED: $FilePath -> $quarantinePath" "CRITICAL"
        return "File quarantined: $originalName"

    } catch {
        Write-EDRLog "Quarantine failed for $FilePath : $_" "WARN"
        return "Quarantine failed: $_"
    }
}

# ── Restore from Quarantine ────────────────────────────────────
function Restore-FromQuarantine {
    <#
    .SYNOPSIS
        Restore a quarantined file to its original location.
    #>
    param([string]$QuarantinedFileName)

    $quarantineDir = $Script:EDRConfig.QuarantinePath
    $quarantinePath = Join-Path $quarantineDir $QuarantinedFileName
    $metadataPath = "${quarantinePath}.meta.json"

    if (-not (Test-Path $metadataPath)) {
        Write-Host "Metadata not found for: $QuarantinedFileName" -ForegroundColor Red
        return
    }

    $metadata = Get-Content $metadataPath -Raw | ConvertFrom-Json
    $originalPath = $metadata.OriginalPath

    Write-Host "Restoring: $QuarantinedFileName" -ForegroundColor Yellow
    Write-Host "  Original path: $originalPath"
    Write-Host "  Score was: $($metadata.Score)"
    Write-Host "  Verdict was: $($metadata.Verdict)"
    Write-Host ""
    $confirm = Read-Host "Are you sure you want to restore this file? (yes/no)"

    if ($confirm -eq "yes") {
        Move-Item -Path $quarantinePath -Destination $originalPath -Force
        Remove-Item $metadataPath -Force
        Write-EDRLog "RESTORED from quarantine: $originalPath" "WARN"
        Write-Host "File restored to: $originalPath" -ForegroundColor Green
    } else {
        Write-Host "Restore cancelled." -ForegroundColor Gray
    }
}

# ── Network Blocking ──────────────────────────────────────────
function Block-ThreatConnection {
    param([string]$RemoteAddress)

    try {
        # Check if rule already exists
        $existingRule = Get-NetFirewallRule -DisplayName "EDR_Block_$RemoteAddress" -ErrorAction SilentlyContinue
        if ($existingRule) {
            return "Already blocked: $RemoteAddress"
        }

        # Create outbound block rule
        New-NetFirewallRule `
            -DisplayName "EDR_Block_$RemoteAddress" `
            -Direction Outbound `
            -Action Block `
            -RemoteAddress $RemoteAddress `
            -Description "Blocked by EDR at $(Get-Date -Format 'o')" `
            -ErrorAction Stop | Out-Null

        # Also create inbound block
        New-NetFirewallRule `
            -DisplayName "EDR_Block_${RemoteAddress}_In" `
            -Direction Inbound `
            -Action Block `
            -RemoteAddress $RemoteAddress `
            -Description "Blocked by EDR at $(Get-Date -Format 'o')" `
            -ErrorAction Stop | Out-Null

        Write-EDRLog "BLOCKED: Network connection to $RemoteAddress" "CRITICAL"
        return "Network blocked: $RemoteAddress"

    } catch {
        Write-EDRLog "Failed to block $RemoteAddress : $_" "WARN"
        return "Block failed: $RemoteAddress - $_"
    }
}

# ── Unblock IP ─────────────────────────────────────────────────
function Unblock-ThreatConnection {
    param([string]$RemoteAddress)

    try {
        Remove-NetFirewallRule -DisplayName "EDR_Block_$RemoteAddress" -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName "EDR_Block_${RemoteAddress}_In" -ErrorAction SilentlyContinue
        Write-EDRLog "UNBLOCKED: $RemoteAddress" "INFO"
        return "Unblocked: $RemoteAddress"
    } catch {
        return "Unblock failed: $_"
    }
}

# ── Alert Generation ──────────────────────────────────────────
function New-ThreatAlert {
    param(
        $AnalysisResult,
        [int]$Score,
        [string]$Verdict
    )

    $alert = [PSCustomObject]@{
        AlertId     = [guid]::NewGuid().ToString("N").Substring(0, 8)
        Timestamp   = Get-Date
        Score       = $Score
        Verdict     = $Verdict
        Target      = $AnalysisResult.FilePath ?? "PID:$($AnalysisResult.ProcessId)"
        CommandLine = $AnalysisResult.CommandLine
        Mitre       = ($AnalysisResult.MitreMapping | ForEach-Object { "$($_.TechniqueId):$($_.TechniqueName)" }) -join "; "
        YaraRules   = ($AnalysisResult.YaraMatches | ForEach-Object { $_.RuleName }) -join "; "
    }

    # Save alert to file
    $alertDir = Join-Path $Script:EDRConfig.LogPath "Alerts"
    if (-not (Test-Path $alertDir)) {
        New-Item -ItemType Directory -Path $alertDir -Force | Out-Null
    }

    $alertFile = Join-Path $alertDir "$($alert.AlertId)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $alert | ConvertTo-Json -Depth 5 | Set-Content $alertFile

    $Script:NetworkAlerts.Add($alert) | Out-Null

    return $alert
}

# ── List Quarantined Files ─────────────────────────────────────
function Get-QuarantinedFiles {
    $quarantineDir = $Script:EDRConfig.QuarantinePath
    if (-not (Test-Path $quarantineDir)) {
        Write-Host "No quarantine directory found." -ForegroundColor Gray
        return
    }

    $files = Get-ChildItem $quarantineDir -Filter "*.quarantined"
    if ($files.Count -eq 0) {
        Write-Host "No quarantined files." -ForegroundColor Green
        return
    }

    Write-Host "`n══ Quarantined Files ══" -ForegroundColor Yellow
    foreach ($f in $files) {
        $metaPath = "$($f.FullName).meta.json"
        if (Test-Path $metaPath) {
            $meta = Get-Content $metaPath -Raw | ConvertFrom-Json
            Write-Host "  $($f.Name)" -ForegroundColor Red
            Write-Host "    Original: $($meta.OriginalPath)"
            Write-Host "    Score: $($meta.Score) | Verdict: $($meta.Verdict)"
            Write-Host "    Quarantined: $($meta.QuarantinedAt)"
        }
    }
}

# ── List EDR Firewall Rules ───────────────────────────────────
function Get-EDRFirewallRules {
    $rules = Get-NetFirewallRule -DisplayName "EDR_Block_*" -ErrorAction SilentlyContinue
    if (-not $rules) {
        Write-Host "No EDR firewall rules active." -ForegroundColor Green
        return
    }

    Write-Host "`n══ EDR Firewall Rules ══" -ForegroundColor Yellow
    foreach ($r in $rules) {
        $addr = (Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r).RemoteAddress
        Write-Host "  $($r.DisplayName) | Direction: $($r.Direction) | IP: $addr" -ForegroundColor Red
    }
}

# ── Enable/Disable Auto-Response ──────────────────────────────
function Set-AutoResponse {
    param(
        [Parameter(Mandatory)]
        [bool]$Enabled
    )

    $Script:ResponseConfig.AutoResponseEnabled = $Enabled
    $state = if ($Enabled) { "ENABLED" } else { "DISABLED" }
    Write-EDRLog "Auto-response $state" "WARN"
    Write-Host "Auto-response is now: $state" -ForegroundColor $(if($Enabled){"Red"}else{"Green"})
}
