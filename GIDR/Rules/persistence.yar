rule Registry_Run_Key_Persistence
{
    meta:
        description = "Registry Run key persistence techniques"
        severity = "high"
        score = 60
        mitre = "T1547.001"
    strings:
        $s1 = /reg\s+add.*CurrentVersion\\Run/i
        $s2 = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
        $s3 = "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
        $s4 = /schtasks.*\/create/i
        $s5 = "New-ScheduledTask" ascii nocase
        $s6 = "Register-ScheduledTask" ascii nocase
        $s7 = /sc\.exe.*create/i
        $s8 = "New-Service" ascii nocase
    condition:
        any of them
}

rule WMI_Persistence
{
    meta:
        description = "WMI event subscription persistence"
        severity = "high"
        score = 65
        mitre = "T1546.003"
    strings:
        $s1 = "__EventFilter" ascii nocase
        $s2 = "CommandLineEventConsumer" ascii nocase
        $s3 = "__FilterToConsumerBinding" ascii nocase
        $s4 = "ActiveScriptEventConsumer" ascii nocase
        $s5 = "root\\subscription" ascii nocase
    condition:
        2 of them
}

rule Startup_Folder_Persistence
{
    meta:
        description = "Startup folder persistence"
        severity = "medium"
        score = 50
        mitre = "T1547.001"
    strings:
        $s1 = "\\Start Menu\\Programs\\Startup\\" ascii nocase
        $s2 = "shell:startup" ascii nocase
        $s3 = "shell:common startup" ascii nocase
    condition:
        any of them
}

rule Lateral_Movement
{
    meta:
        description = "Lateral movement techniques"
        severity = "high"
        score = 70
        mitre = "T1021"
    strings:
        $s1 = "Enter-PSSession" ascii nocase
        $s2 = /Invoke-Command.*-ComputerName/i
        $s3 = "New-PSSession" ascii nocase
        $s4 = /wmic.*\/node:/i
        $s5 = "psexec" ascii nocase
        $s6 = "winrm" ascii nocase
        $s7 = "paexec" ascii nocase
        $s8 = /schtasks.*\/create.*\/s\s/i
    condition:
        any of them
}
