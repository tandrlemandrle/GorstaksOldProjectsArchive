rule Process_Injection_APIs
{
    meta:
        description = "Process injection API usage patterns"
        severity = "critical"
        score = 85
        mitre = "T1055"
    strings:
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "NtMapViewOfSection" ascii
        $api5 = "QueueUserAPC" ascii
        $api6 = "RtlCreateUserThread" ascii
        $api7 = "NtCreateThreadEx" ascii
        $api8 = "SetThreadContext" ascii
        $api9 = "NtUnmapViewOfSection" ascii
        $api10 = "NtWriteVirtualMemory" ascii
    condition:
        3 of them
}

rule Reflective_DLL_Injection
{
    meta:
        description = "Reflective DLL injection indicators"
        severity = "critical"
        score = 80
        mitre = "T1620"
    strings:
        $s1 = "ReflectiveLoader" ascii
        $s2 = "Invoke-ReflectivePEInjection" ascii nocase
        $s3 = "reflection.assembly" ascii nocase
        $s4 = "[System.Reflection.Assembly]::Load" ascii nocase
        $s5 = "Assembly.Load" ascii
        $s6 = "FromBase64String" ascii
    condition:
        2 of them
}

rule Shellcode_Indicators
{
    meta:
        description = "Shellcode patterns and loaders"
        severity = "critical"
        score = 85
        mitre = "T1055"
    strings:
        $s1 = "shellcode" ascii nocase
        $s2 = "Invoke-Shellcode" ascii nocase
        $s3 = "VirtualAlloc" ascii
        $s4 = "VirtualProtect" ascii
        $s5 = "PAGE_EXECUTE_READWRITE" ascii
        $hex_nopsled = {90 90 90 90 90 90 90 90}
        $hex_winexec = {FF 15 ?? ?? ?? ?? 6A 00 FF 15}
    condition:
        ($s1 or $s2) and ($s3 or $s4 or $s5) or $hex_nopsled or $hex_winexec
}

rule Process_Hollowing
{
    meta:
        description = "Process hollowing technique indicators"
        severity = "critical"
        score = 85
        mitre = "T1055.012"
    strings:
        $s1 = "NtUnmapViewOfSection" ascii
        $s2 = "ZwUnmapViewOfSection" ascii
        $s3 = "CREATE_SUSPENDED" ascii
        $s4 = "ResumeThread" ascii
        $s5 = "SetThreadContext" ascii
        $s6 = "GetThreadContext" ascii
        $s7 = "Wow64SetThreadContext" ascii
    condition:
        ($s1 or $s2) and $s4 and ($s5 or $s6 or $s7)
}
