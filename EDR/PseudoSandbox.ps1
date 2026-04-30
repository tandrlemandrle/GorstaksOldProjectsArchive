<#
.SYNOPSIS
    Pseudo-Sandbox - Lightweight behavioral sandbox for suspicious files.
.DESCRIPTION
    Executes a suspicious file in a monitored environment, tracking:
    - Child process creation
    - File system changes
    - Registry modifications
    - Network connections
    Then scores the observed behavior.
#>

function Invoke-PseudoSandbox {
    <#
    .SYNOPSIS
        Run a file in a monitored pseudo-sandbox and observe its behavior.
    .PARAMETER FilePath
        Path to the file to analyze.
    .PARAMETER TimeoutSeconds
        How long to observe behavior (default: 30 seconds).
    .PARAMETER DryRun
        If true, only simulate - don't actually execute the file.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        [int]$TimeoutSeconds = 30,
        [switch]$DryRun
    )

    if (-not (Test-Path $FilePath)) {
        Write-EDRLog "Sandbox: File not found: $FilePath" "WARN"
        return $null
    }

    $result = [PSCustomObject]@{
        FilePath          = $FilePath
        StartTime         = Get-Date
        EndTime           = $null
        Duration          = 0
        DryRun            = $DryRun.IsPresent
        ProcessesCreated  = [System.Collections.ArrayList]::new()
        FilesCreated      = [System.Collections.ArrayList]::new()
        FilesModified     = [System.Collections.ArrayList]::new()
        FilesDeleted      = [System.Collections.ArrayList]::new()
        RegistryChanges   = [System.Collections.ArrayList]::new()
        NetworkConnections = [System.Collections.ArrayList]::new()
        BehaviorScore     = 0
        BehaviorFlags     = [System.Collections.ArrayList]::new()
        MitreTechniques   = [System.Collections.ArrayList]::new()
    }

    Write-EDRLog "Sandbox: Starting analysis of $FilePath (timeout=${TimeoutSeconds}s, dryrun=$($DryRun.IsPresent))" "INFO"

    # ── Set up monitors ────────────────────────────────────────

    # Process monitor
    $procMonitor = Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" `
        -SourceIdentifier "Sandbox_ProcMon" -Action {
            $proc = $Event.SourceEventArgs.NewEvent
            $result.ProcessesCreated.Add([PSCustomObject]@{
                PID         = $proc.ProcessID
                Name        = $proc.ProcessName
                ParentPID   = $proc.ParentProcessID
                Timestamp   = Get-Date
                CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.ProcessID)" -ErrorAction SilentlyContinue).CommandLine
            }) | Out-Null
        }

    # File system monitor (temp directories)
    $tempWatcher = [System.IO.FileSystemWatcher]::new($env:TEMP)
    $tempWatcher.IncludeSubdirectories = $true
    $tempWatcher.EnableRaisingEvents = $true

    $fsCreated = Register-ObjectEvent $tempWatcher Created -SourceIdentifier "Sandbox_FSCreated" -Action {
        $result.FilesCreated.Add([PSCustomObject]@{
            Path      = $Event.SourceEventArgs.FullPath
            Timestamp = Get-Date
        }) | Out-Null
    }

    $fsChanged = Register-ObjectEvent $tempWatcher Changed -SourceIdentifier "Sandbox_FSChanged" -Action {
        $result.FilesModified.Add([PSCustomObject]@{
            Path      = $Event.SourceEventArgs.FullPath
            Timestamp = Get-Date
        }) | Out-Null
    }

    $fsDeleted = Register-ObjectEvent $tempWatcher Deleted -SourceIdentifier "Sandbox_FSDeleted" -Action {
        $result.FilesDeleted.Add([PSCustomObject]@{
            Path      = $Event.SourceEventArgs.FullPath
            Timestamp = Get-Date
        }) | Out-Null
    }

    # Snapshot network connections before
    $netBefore = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::' }

    # Snapshot registry keys of interest
    $regPaths = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    $regBefore = @{}
    foreach ($rp in $regPaths) {
        if (Test-Path $rp) {
            $regBefore[$rp] = Get-ItemProperty $rp -ErrorAction SilentlyContinue
        }
    }

    # ── Execute the file (if not dry run) ──────────────────────
    $targetPID = $null
    if (-not $DryRun.IsPresent) {
        try {
            $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()

            switch ($ext) {
                '.exe' {
                    $process = Start-Process -FilePath $FilePath -PassThru -WindowStyle Hidden -ErrorAction Stop
                    $targetPID = $process.Id
                }
                '.ps1' {
                    $process = Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$FilePath`"" `
                        -PassThru -WindowStyle Hidden -ErrorAction Stop
                    $targetPID = $process.Id
                }
                '.bat' {
                    $process = Start-Process cmd.exe -ArgumentList "/c `"$FilePath`"" `
                        -PassThru -WindowStyle Hidden -ErrorAction Stop
                    $targetPID = $process.Id
                }
                '.vbs' {
                    $process = Start-Process cscript.exe -ArgumentList "//nologo `"$FilePath`"" `
                        -PassThru -WindowStyle Hidden -ErrorAction Stop
                    $targetPID = $process.Id
                }
                '.js' {
                    $process = Start-Process cscript.exe -ArgumentList "//nologo `"$FilePath`"" `
                        -PassThru -WindowStyle Hidden -ErrorAction Stop
                    $targetPID = $process.Id
                }
                default {
                    Write-EDRLog "Sandbox: Unsupported file type: $ext" "WARN"
                }
            }

            if ($targetPID) {
                Write-EDRLog "Sandbox: Launched PID $targetPID" "INFO"
            }
        } catch {
            Write-EDRLog "Sandbox: Failed to launch: $_" "WARN"
        }
    }

    # ── Wait and observe ───────────────────────────────────────
    Write-EDRLog "Sandbox: Observing for $TimeoutSeconds seconds..." "INFO"
    Start-Sleep -Seconds $TimeoutSeconds

    # ── Collect results ────────────────────────────────────────

    # Kill the target process if still running
    if ($targetPID) {
        $targetProc = Get-Process -Id $targetPID -ErrorAction SilentlyContinue
        if ($targetProc) {
            $targetProc | Stop-Process -Force -ErrorAction SilentlyContinue
            Write-EDRLog "Sandbox: Terminated PID $targetPID" "INFO"
        }
    }

    # Check for new network connections
    $netAfter = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::' }

    $newConns = $netAfter | Where-Object {
        $conn = $_
        -not ($netBefore | Where-Object {
            $_.RemoteAddress -eq $conn.RemoteAddress -and
            $_.RemotePort -eq $conn.RemotePort -and
            $_.OwningProcess -eq $conn.OwningProcess
        })
    }

    foreach ($nc in $newConns) {
        $result.NetworkConnections.Add([PSCustomObject]@{
            RemoteAddress = $nc.RemoteAddress
            RemotePort    = $nc.RemotePort
            OwningProcess = $nc.OwningProcess
            State         = $nc.State
        }) | Out-Null
    }

    # Check for registry changes
    foreach ($rp in $regPaths) {
        if (Test-Path $rp) {
            $regAfter = Get-ItemProperty $rp -ErrorAction SilentlyContinue
            $regBeforeProps = if ($regBefore.ContainsKey($rp)) { $regBefore[$rp] } else { $null }

            if ($regAfter -and $regBeforeProps) {
                $afterProps = $regAfter.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }
                $beforeProps = $regBeforeProps.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }

                foreach ($prop in $afterProps) {
                    $beforeProp = $beforeProps | Where-Object { $_.Name -eq $prop.Name }
                    if (-not $beforeProp -or $beforeProp.Value -ne $prop.Value) {
                        $result.RegistryChanges.Add([PSCustomObject]@{
                            Path      = $rp
                            Name      = $prop.Name
                            Value     = $prop.Value
                            Type      = "Added/Modified"
                        }) | Out-Null
                    }
                }
            }
        }
    }

    # ── Clean up monitors ──────────────────────────────────────
    Unregister-Event -SourceIdentifier "Sandbox_ProcMon" -ErrorAction SilentlyContinue
    Unregister-Event -SourceIdentifier "Sandbox_FSCreated" -ErrorAction SilentlyContinue
    Unregister-Event -SourceIdentifier "Sandbox_FSChanged" -ErrorAction SilentlyContinue
    Unregister-Event -SourceIdentifier "Sandbox_FSDeleted" -ErrorAction SilentlyContinue
    $tempWatcher.Dispose()

    # ── Score the behavior ─────────────────────────────────────
    $result.EndTime  = Get-Date
    $result.Duration = ($result.EndTime - $result.StartTime).TotalSeconds

    # Process creation scoring
    if ($result.ProcessesCreated.Count -gt 0) {
        $result.BehaviorScore += $result.ProcessesCreated.Count * 10
        $result.BehaviorFlags.Add("Spawned $($result.ProcessesCreated.Count) child process(es)") | Out-Null

        # Check for suspicious child processes
        foreach ($child in $result.ProcessesCreated) {
            $childName = $child.Name.ToLower()
            if ($childName -in @('powershell.exe','cmd.exe','mshta.exe','wscript.exe','cscript.exe')) {
                $result.BehaviorScore += 30
                $result.BehaviorFlags.Add("Spawned suspicious child: $childName") | Out-Null
            }
        }
    }

    # File activity scoring
    if ($result.FilesCreated.Count -gt 0) {
        $result.BehaviorScore += $result.FilesCreated.Count * 5
        $result.BehaviorFlags.Add("Created $($result.FilesCreated.Count) file(s)") | Out-Null

        # Check for executable drops
        $exeDrops = $result.FilesCreated | Where-Object {
            $_.Path -match '\.(exe|dll|ps1|bat|cmd|vbs|js|scr)$'
        }
        if ($exeDrops) {
            $result.BehaviorScore += $exeDrops.Count * 25
            $result.BehaviorFlags.Add("Dropped $($exeDrops.Count) executable file(s)") | Out-Null
        }
    }

    if ($result.FilesDeleted.Count -gt 5) {
        $result.BehaviorScore += 20
        $result.BehaviorFlags.Add("Deleted $($result.FilesDeleted.Count) file(s)") | Out-Null
    }

    # Registry scoring
    if ($result.RegistryChanges.Count -gt 0) {
        $result.BehaviorScore += $result.RegistryChanges.Count * 20
        $result.BehaviorFlags.Add("Modified $($result.RegistryChanges.Count) registry value(s)") | Out-Null

        foreach ($reg in $result.RegistryChanges) {
            if ($reg.Path -match 'Run') {
                $result.BehaviorScore += 30
                $result.BehaviorFlags.Add("Added persistence via registry Run key") | Out-Null
                $result.MitreTechniques.Add("T1547.001") | Out-Null
            }
        }
    }

    # Network scoring
    if ($result.NetworkConnections.Count -gt 0) {
        $result.BehaviorScore += $result.NetworkConnections.Count * 15
        $result.BehaviorFlags.Add("Made $($result.NetworkConnections.Count) network connection(s)") | Out-Null
    }

    Write-EDRLog "Sandbox: Analysis complete. Score=$($result.BehaviorScore) Flags=$($result.BehaviorFlags.Count)" "INFO"

    return $result
}

# ── Sandbox Report ─────────────────────────────────────────────
function Show-SandboxReport {
    param($SandboxResult)

    if (-not $SandboxResult) {
        Write-Host "No sandbox results to display." -ForegroundColor Gray
        return
    }

    $color = if ($SandboxResult.BehaviorScore -gt 80) { "Red" }
             elseif ($SandboxResult.BehaviorScore -gt 40) { "Yellow" }
             else { "Green" }

    Write-Host "`n╔══════════════════════════════════════════╗" -ForegroundColor $color
    Write-Host "║        PSEUDO-SANDBOX REPORT             ║" -ForegroundColor $color
    Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor $color

    Write-Host "`n  File: $($SandboxResult.FilePath)"
    Write-Host "  Duration: $([math]::Round($SandboxResult.Duration, 1))s"
    Write-Host "  Behavior Score: $($SandboxResult.BehaviorScore)" -ForegroundColor $color
    Write-Host "  Dry Run: $($SandboxResult.DryRun)"

    Write-Host "`n  ── Activity Summary ──" -ForegroundColor Cyan
    Write-Host "    Processes spawned : $($SandboxResult.ProcessesCreated.Count)"
    Write-Host "    Files created     : $($SandboxResult.FilesCreated.Count)"
    Write-Host "    Files modified    : $($SandboxResult.FilesModified.Count)"
    Write-Host "    Files deleted     : $($SandboxResult.FilesDeleted.Count)"
    Write-Host "    Registry changes  : $($SandboxResult.RegistryChanges.Count)"
    Write-Host "    Network conns     : $($SandboxResult.NetworkConnections.Count)"

    if ($SandboxResult.BehaviorFlags.Count -gt 0) {
        Write-Host "`n  ── Behavior Flags ──" -ForegroundColor Yellow
        foreach ($flag in $SandboxResult.BehaviorFlags) {
            Write-Host "    ⚠ $flag" -ForegroundColor Yellow
        }
    }

    if ($SandboxResult.ProcessesCreated.Count -gt 0) {
        Write-Host "`n  ── Child Processes ──" -ForegroundColor Magenta
        foreach ($p in $SandboxResult.ProcessesCreated) {
            Write-Host "    PID $($p.PID): $($p.Name)"
            if ($p.CommandLine) {
                $truncCmd = if ($p.CommandLine.Length -gt 100) { $p.CommandLine.Substring(0,100) + "..." } else { $p.CommandLine }
                Write-Host "      CMD: $truncCmd" -ForegroundColor Gray
            }
        }
    }

    if ($SandboxResult.RegistryChanges.Count -gt 0) {
        Write-Host "`n  ── Registry Changes ──" -ForegroundColor Red
        foreach ($r in $SandboxResult.RegistryChanges) {
            Write-Host "    $($r.Path)\$($r.Name) = $($r.Value)" -ForegroundColor Red
        }
    }

    if ($SandboxResult.NetworkConnections.Count -gt 0) {
        Write-Host "`n  ── Network Connections ──" -ForegroundColor Red
        foreach ($n in $SandboxResult.NetworkConnections) {
            Write-Host "    -> $($n.RemoteAddress):$($n.RemotePort) (PID $($n.OwningProcess))" -ForegroundColor Red
        }
    }

    if ($SandboxResult.MitreTechniques.Count -gt 0) {
        Write-Host "`n  ── MITRE Techniques ──" -ForegroundColor Magenta
        foreach ($t in ($SandboxResult.MitreTechniques | Select-Object -Unique)) {
            Write-Host "    $t"
        }
    }
}
