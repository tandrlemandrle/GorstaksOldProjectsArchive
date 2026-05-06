rule AMSI_Bypass
{
    meta:
        description = "AMSI bypass techniques"
        severity = "critical"
        score = 80
        mitre = "T1562.001"
    strings:
        $s1 = "AmsiScanBuffer" ascii nocase
        $s2 = "amsiInitFailed" ascii nocase
        $s3 = "amsi.dll" ascii nocase
        $s4 = "AmsiUtils" ascii nocase
        $s5 = "amsiContext" ascii nocase
        $s6 = "PatchAmsi" ascii nocase
        $s7 = "DisableAmsi" ascii nocase
        $s8 = "Invoke-AmsiBypass" ascii nocase
        $s9 = "Remove-Amsi" ascii nocase
        $s10 = /\[Ref\]\.Assembly\.GetType.*AmsiUtils/i
        $s11 = "AMSI_RESULT_CLEAN" ascii nocase
        $s12 = "AmsiOpenSession" ascii nocase
    condition:
        any of them
}

rule Defender_Tampering
{
    meta:
        description = "Windows Defender tampering / disabling"
        severity = "critical"
        score = 75
        mitre = "T1562.001"
    strings:
        $s1 = "Set-MpPreference" ascii nocase
        $s2 = "-DisableRealtimeMonitoring" ascii nocase
        $s3 = "-DisableBehaviorMonitoring" ascii nocase
        $s4 = "-DisableIOAVProtection" ascii nocase
        $s5 = "Add-MpPreference" ascii nocase
        $s6 = "-ExclusionPath" ascii nocase
        $s7 = "-ExclusionProcess" ascii nocase
        $s8 = "DisableAntiSpyware" ascii nocase
    condition:
        ($s1 or $s5) and any of ($s2, $s3, $s4, $s6, $s7, $s8)
}

rule Event_Log_Clearing
{
    meta:
        description = "Event log clearing / tampering"
        severity = "high"
        score = 70
        mitre = "T1070.001"
    strings:
        $s1 = "Clear-EventLog" ascii nocase
        $s2 = "wevtutil cl" ascii nocase
        $s3 = "wevtutil clear-log" ascii nocase
        $s4 = /Remove-EventLog.*-Source/i
    condition:
        any of them
}
