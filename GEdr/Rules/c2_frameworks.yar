rule CobaltStrike_Beacon
{
    meta:
        description = "Cobalt Strike beacon indicators"
        severity = "critical"
        score = 90
        mitre = "T1071"
    strings:
        $s1 = "beacon.dll" ascii nocase
        $s2 = "cobaltstrike" ascii nocase
        $s3 = "sleeptime" ascii nocase
        $s4 = "%COMSPEC%" ascii
        $s5 = /IEX.*downloadstring.*http/i
        $s6 = "ReflectiveLoader" ascii
        $s7 = {4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF}
        $s8 = "beacon_keys" ascii
        $s9 = ".http-get." ascii
        $s10 = ".http-post." ascii
    condition:
        any of them
}

rule PowerSploit_Framework
{
    meta:
        description = "PowerSploit offensive framework"
        severity = "high"
        score = 75
        mitre = "T1059.001"
    strings:
        $s1 = "Invoke-Shellcode" ascii nocase
        $s2 = "Invoke-ReflectivePEInjection" ascii nocase
        $s3 = "Invoke-DllInjection" ascii nocase
        $s4 = "Invoke-TokenManipulation" ascii nocase
        $s5 = "Get-GPPPassword" ascii nocase
        $s6 = "Invoke-Kerberoast" ascii nocase
        $s7 = "Invoke-Mimikatz" ascii nocase
        $s8 = "PowerView" ascii nocase
    condition:
        any of them
}

rule SharpTools_Offensive
{
    meta:
        description = "C# offensive tools (SharpHound, Rubeus, etc.)"
        severity = "high"
        score = 70
        mitre = "T1059"
    strings:
        $s1 = "SharpHound" ascii nocase
        $s2 = "Rubeus" ascii nocase
        $s3 = "Seatbelt" ascii nocase
        $s4 = "SharpUp" ascii nocase
        $s5 = "Certify" ascii nocase
        $s6 = "Whisker" ascii nocase
        $s7 = "SharpDPAPI" ascii nocase
        $s8 = "SharpChrome" ascii nocase
    condition:
        any of them
}

rule Metasploit_Indicators
{
    meta:
        description = "Metasploit framework indicators"
        severity = "critical"
        score = 85
        mitre = "T1059"
    strings:
        $s1 = "meterpreter" ascii nocase
        $s2 = "metasploit" ascii nocase
        $s3 = "msfvenom" ascii nocase
        $s4 = "msfconsole" ascii nocase
        $s5 = "reverse_tcp" ascii nocase
        $s6 = "reverse_https" ascii nocase
        $s7 = "windows/meterpreter" ascii nocase
        $s8 = "payload/windows" ascii nocase
        $hex_meterpreter = {6D 65 74 65 72 70 72 65 74 65 72}
    condition:
        any of them
}

rule Empire_Framework
{
    meta:
        description = "Empire/Covenant C2 framework"
        severity = "high"
        score = 75
        mitre = "T1059.001"
    strings:
        $s1 = "Invoke-Empire" ascii nocase
        $s2 = "covenant" ascii nocase
        $s3 = "Invoke-Obfuscation" ascii nocase
        $s4 = "stager" ascii nocase
        $s5 = "GruntHTTP" ascii nocase
        $s6 = "GruntSMB" ascii nocase
    condition:
        2 of them
}
