rule Mimikatz
{
    meta:
        description = "Mimikatz credential dumping tool"
        severity = "critical"
        score = 95
        mitre = "T1003"
    strings:
        $s1 = "mimikatz" ascii nocase
        $s2 = "sekurlsa" ascii nocase
        $s3 = "kerberos::" ascii nocase
        $s4 = "lsadump::" ascii nocase
        $s5 = "privilege::debug" ascii nocase
        $s6 = "token::elevate" ascii nocase
        $s7 = "dpapi::" ascii nocase
        $s8 = "crypto::" ascii nocase
        $s9 = "gentilkiwi" ascii nocase
        $s10 = "Benjamin DELPY" ascii nocase
        $hex1 = {6D 69 6D 69 6B 61 74 7A}
    condition:
        any of them
}

rule Credential_Dumper_Generic
{
    meta:
        description = "Generic credential dumping tool indicators"
        severity = "high"
        score = 70
        mitre = "T1003"
    strings:
        $s1 = "pwdump" ascii nocase
        $s2 = "gsecdump" ascii nocase
        $s3 = "wce.exe" ascii nocase
        $s4 = "dumpert" ascii nocase
        $s5 = "nanodump" ascii nocase
        $s6 = "lsassy" ascii nocase
        $s7 = "cachedump" ascii nocase
        $s8 = "fgdump" ascii nocase
        $s9 = "pypykatz" ascii nocase
        $s10 = "secretsdump" ascii nocase
    condition:
        any of them
}

rule LSASS_Access_Indicators
{
    meta:
        description = "LSASS memory access patterns"
        severity = "critical"
        score = 80
        mitre = "T1003.001"
    strings:
        $s1 = "lsass.dmp" ascii nocase
        $s2 = "lsass.exe" ascii nocase
        $s3 = "MiniDumpWriteDump" ascii nocase
        $s4 = "comsvcs.dll" ascii nocase
        $s5 = /procdump.*lsass/i
        $s6 = /reg.*save.*sam/i
        $s7 = /reg.*save.*security/i
        $s8 = /reg.*save.*system/i
        $s9 = "CreateDump" ascii nocase
    condition:
        2 of them
}

rule Password_Cracker
{
    meta:
        description = "Password cracking tools"
        severity = "high"
        score = 65
        mitre = "T1110"
    strings:
        $s1 = "hashcat" ascii nocase
        $s2 = "john the ripper" ascii nocase
        $s3 = "hydra" ascii nocase
        $s4 = "brute force" ascii nocase
        $s5 = "wordlist" ascii nocase
        $s6 = "password crack" ascii nocase
        $s7 = "ophcrack" ascii nocase
        $s8 = "l0phtcrack" ascii nocase
    condition:
        2 of them
}
