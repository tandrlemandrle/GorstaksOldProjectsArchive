<#
.SYNOPSIS
    Scoring Engine - Aggregates all detection signals into a threat score.
.DESCRIPTION
    Combines scores from static analysis, behavior engine, YARA rules,
    MITRE mappings, and network analysis into a weighted final verdict.
    Inspired by VirusTotal's multi-engine consensus approach.
#>

# ── Score Weights ──────────────────────────────────────────────
$Script:ScoreWeights = @{
    Static    = 1.0    # Static analysis weight
    Behavior  = 1.5    # Behavior is king - weighted higher
    Yara      = 1.3    # Rule matches are strong signals
    Mitre     = 0.8    # MITRE mapping adds context
    Network   = 1.2    # Network activity is important
}

# ── Verdict Thresholds ─────────────────────────────────────────
$Script:VerdictThresholds = @{
    Clean      = @{ Min = 0;   Max = 24  }
    Low        = @{ Min = 25;  Max = 49  }
    Suspicious = @{ Min = 50;  Max = 79  }
    Malicious  = @{ Min = 80;  Max = 119 }
    Critical   = @{ Min = 120; Max = 9999 }
}

# ── Main Scoring Function ─────────────────────────────────────
function Get-ThreatScore {
    param(
        [Parameter(Mandatory)]
        $AnalysisResult
    )

    $breakdown = [PSCustomObject]@{
        StaticScore    = 0
        BehaviorScore  = 0
        YaraScore      = 0
        MitreScore     = 0
        NetworkScore   = 0
        BonusPenalties = 0
        RawTotal       = 0
        WeightedTotal  = 0
        TotalScore     = 0
        Verdict        = "Clean"
        Confidence     = "Low"
        Details        = @()
    }

    # ── Static Analysis Score ──────────────────────────────────
    if ($AnalysisResult.StaticResults) {
        $breakdown.StaticScore = [math]::Min($AnalysisResult.StaticResults.Score, 100)
        if ($breakdown.StaticScore -gt 0) {
            $breakdown.Details += "Static: $($breakdown.StaticScore) pts"
        }
    }

    # ── Behavior Score ─────────────────────────────────────────
    if ($AnalysisResult.BehaviorResults) {
        $breakdown.BehaviorScore = [math]::Min($AnalysisResult.BehaviorResults.Score, 150)
        if ($breakdown.BehaviorScore -gt 0) {
            $breakdown.Details += "Behavior: $($breakdown.BehaviorScore) pts"
        }
    }

    # ── YARA Score ─────────────────────────────────────────────
    if ($AnalysisResult.YaraMatches -and $AnalysisResult.YaraMatches.Count -gt 0) {
        $yaraTotal = ($AnalysisResult.YaraMatches | Measure-Object -Property Score -Sum).Sum
        $breakdown.YaraScore = [math]::Min($yaraTotal, 120)

        # Severity multiplier
        $hasCritical = $AnalysisResult.YaraMatches | Where-Object { $_.Severity -eq "Critical" }
        if ($hasCritical) {
            $breakdown.YaraScore = [math]::Min($breakdown.YaraScore * 1.3, 150)
        }

        $breakdown.Details += "YARA: $([math]::Round($breakdown.YaraScore)) pts ($($AnalysisResult.YaraMatches.Count) rules)"
    }

    # ── MITRE Score ────────────────────────────────────────────
    if ($AnalysisResult.MitreMapping -and $AnalysisResult.MitreMapping.Count -gt 0) {
        $mitreBase = $AnalysisResult.MitreMapping.Count * 8

        # High-confidence mappings worth more
        $highConf = ($AnalysisResult.MitreMapping | Where-Object { $_.Confidence -eq "High" }).Count
        $mitreBase += $highConf * 5

        # Multiple tactics = more concerning
        $uniqueTactics = ($AnalysisResult.MitreMapping | Select-Object -ExpandProperty Tactic -Unique).Count
        if ($uniqueTactics -ge 3) {
            $mitreBase *= 1.3  # Multi-tactic bonus
        }

        $breakdown.MitreScore = [math]::Min($mitreBase, 80)
        $breakdown.Details += "MITRE: $([math]::Round($breakdown.MitreScore)) pts ($($AnalysisResult.MitreMapping.Count) techniques, $uniqueTactics tactics)"
    }

    # ── Network Score ──────────────────────────────────────────
    if ($AnalysisResult.NetworkResults) {
        $breakdown.NetworkScore = [math]::Min($AnalysisResult.NetworkResults.Score, 80)

        if ($AnalysisResult.NetworkResults.BeaconingDetected) {
            $breakdown.NetworkScore += 30
        }

        $breakdown.NetworkScore = [math]::Min($breakdown.NetworkScore, 100)

        if ($breakdown.NetworkScore -gt 0) {
            $breakdown.Details += "Network: $($breakdown.NetworkScore) pts"
        }
    }

    # ── Bonus / Penalty Adjustments ────────────────────────────
    $breakdown.BonusPenalties = Get-BonusPenalties -AnalysisResult $AnalysisResult
    if ($breakdown.BonusPenalties -ne 0) {
        $breakdown.Details += "Adjustments: $($breakdown.BonusPenalties) pts"
    }

    # ── Calculate Weighted Total ───────────────────────────────
    $breakdown.RawTotal = $breakdown.StaticScore +
                          $breakdown.BehaviorScore +
                          $breakdown.YaraScore +
                          $breakdown.MitreScore +
                          $breakdown.NetworkScore +
                          $breakdown.BonusPenalties

    $breakdown.WeightedTotal = (
        ($breakdown.StaticScore   * $Script:ScoreWeights.Static) +
        ($breakdown.BehaviorScore * $Script:ScoreWeights.Behavior) +
        ($breakdown.YaraScore     * $Script:ScoreWeights.Yara) +
        ($breakdown.MitreScore    * $Script:ScoreWeights.Mitre) +
        ($breakdown.NetworkScore  * $Script:ScoreWeights.Network) +
        $breakdown.BonusPenalties
    )

    # Normalize to a 0-200 scale
    $breakdown.TotalScore = [math]::Max(0, [math]::Round($breakdown.WeightedTotal))

    # ── Determine Verdict ──────────────────────────────────────
    $breakdown.Verdict = Get-Verdict -Score $breakdown.TotalScore

    # ── Determine Confidence ───────────────────────────────────
    $signalCount = @(
        ($breakdown.StaticScore -gt 0),
        ($breakdown.BehaviorScore -gt 0),
        ($breakdown.YaraScore -gt 0),
        ($breakdown.MitreScore -gt 0),
        ($breakdown.NetworkScore -gt 0)
    ) | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count

    $breakdown.Confidence = switch ($signalCount) {
        { $_ -ge 4 } { "High" }
        { $_ -ge 2 } { "Medium" }
        default       { "Low" }
    }

    return $breakdown
}

# ── Verdict Determination ──────────────────────────────────────
function Get-Verdict {
    param([int]$Score)

    foreach ($level in @("Critical","Malicious","Suspicious","Low","Clean")) {
        $threshold = $Script:VerdictThresholds[$level]
        if ($Score -ge $threshold.Min -and $Score -le $threshold.Max) {
            return $level
        }
    }
    return "Clean"
}

# ── Bonus/Penalty Calculations ─────────────────────────────────
function Get-BonusPenalties {
    param($AnalysisResult)

    $adjustment = 0

    # ── Signed binary bonus (reduce score) ─────────────────────
    if ($AnalysisResult.FilePath -and (Test-Path $AnalysisResult.FilePath -ErrorAction SilentlyContinue)) {
        try {
            $sig = Get-AuthenticodeSignature $AnalysisResult.FilePath -ErrorAction SilentlyContinue
            if ($sig -and $sig.Status -eq 'Valid') {
                $adjustment -= 20
                # Known trusted publishers get bigger bonus
                $trustedPublishers = @(
                    'Microsoft',
                    'Google',
                    'Mozilla',
                    'Adobe',
                    'Oracle',
                    'Apple'
                )
                $signerName = $sig.SignerCertificate.Subject
                foreach ($pub in $trustedPublishers) {
                    if ($signerName -match $pub) {
                        $adjustment -= 30
                        break
                    }
                }
            }
        } catch { }
    }

    # ── Known system process bonus ─────────────────────────────
    $knownSystemProcs = @(
        'svchost.exe', 'csrss.exe', 'lsass.exe', 'services.exe',
        'smss.exe', 'wininit.exe', 'winlogon.exe', 'dwm.exe',
        'explorer.exe', 'taskhostw.exe', 'sihost.exe'
    )
    $procName = ""
    if ($AnalysisResult.BehaviorResults) {
        $procName = $AnalysisResult.BehaviorResults.ProcessName.ToLower()
    }
    if ($procName -in $knownSystemProcs) {
        # Only reduce if running from expected path
        if ($AnalysisResult.FilePath -match 'C:\\Windows\\System32') {
            $adjustment -= 15
        }
    }

    # ── Multiple detection sources penalty (corroboration) ─────
    $sources = 0
    if ($AnalysisResult.StaticResults -and $AnalysisResult.StaticResults.Score -gt 20) { $sources++ }
    if ($AnalysisResult.BehaviorResults -and $AnalysisResult.BehaviorResults.Score -gt 20) { $sources++ }
    if ($AnalysisResult.YaraMatches -and $AnalysisResult.YaraMatches.Count -gt 0) { $sources++ }
    if ($AnalysisResult.NetworkResults -and $AnalysisResult.NetworkResults.Score -gt 10) { $sources++ }

    if ($sources -ge 3) {
        $adjustment += 25  # Multiple independent signals = more suspicious
    }

    return $adjustment
}

# ── Score Report ───────────────────────────────────────────────
function Show-ScoreReport {
    <#
    .SYNOPSIS
        Display a detailed scoring breakdown for an analysis result.
    #>
    param($AnalysisResult)

    $score = Get-ThreatScore -AnalysisResult $AnalysisResult

    $verdictColor = switch ($score.Verdict) {
        "Critical"   { "Red" }
        "Malicious"  { "DarkRed" }
        "Suspicious" { "Yellow" }
        "Low"        { "DarkYellow" }
        default      { "Green" }
    }

    Write-Host "`n╔══════════════════════════════════════════╗" -ForegroundColor $verdictColor
    Write-Host "║         THREAT SCORE REPORT              ║" -ForegroundColor $verdictColor
    Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor $verdictColor

    Write-Host "`n  Target: $($AnalysisResult.FilePath ?? $AnalysisResult.CommandLine ?? "PID:$($AnalysisResult.ProcessId)")"
    Write-Host "  Score : $($score.TotalScore)" -ForegroundColor $verdictColor
    Write-Host "  Verdict: $($score.Verdict)" -ForegroundColor $verdictColor
    Write-Host "  Confidence: $($score.Confidence)"

    Write-Host "`n  ── Score Breakdown ──" -ForegroundColor Cyan
    Write-Host "    Static Analysis : $($score.StaticScore)"
    Write-Host "    Behavior Engine : $($score.BehaviorScore)"
    Write-Host "    YARA Rules      : $([math]::Round($score.YaraScore))"
    Write-Host "    MITRE Mapping   : $([math]::Round($score.MitreScore))"
    Write-Host "    Network         : $($score.NetworkScore)"
    Write-Host "    Adjustments     : $($score.BonusPenalties)"
    Write-Host "    ─────────────────"
    Write-Host "    Weighted Total  : $($score.TotalScore)" -ForegroundColor $verdictColor

    if ($score.Details.Count -gt 0) {
        Write-Host "`n  ── Details ──" -ForegroundColor Gray
        foreach ($d in $score.Details) {
            Write-Host "    $d"
        }
    }
}
