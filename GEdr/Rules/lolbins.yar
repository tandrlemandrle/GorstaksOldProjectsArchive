rule LOLBin_Certutil_Abuse
{
    meta:
        description = "Certutil abuse for download or decode"
        severity = "high"
        score = 70
        mitre = "T1218"
    strings:
        $s1 = /certutil.*-urlcache/i
        $s2 = /certutil.*-decode/i
        $s3 = /certutil.*-encode/i
        $s4 = /certutil.*-verifyctl/i
        $s5 = /certutil.*-split/i
    condition:
        any of them
}

rule LOLBin_Bitsadmin_Download
{
    meta:
        description = "Bitsadmin abuse for file download"
        severity = "high"
        score = 65
        mitre = "T1218"
    strings:
        $s1 = /bitsadmin.*\/transfer/i
        $s2 = /bitsadmin.*\/addfile/i
        $s3 = /bitsadmin.*\/download/i
        $s4 = "Start-BitsTransfer" ascii nocase
    condition:
        any of them
}

rule LOLBin_MSHTA_Execution
{
    meta:
        description = "MSHTA remote code execution"
        severity = "critical"
        score = 80
        mitre = "T1218.005"
    strings:
        $s1 = /mshta.*javascript:/i
        $s2 = /mshta.*vbscript:/i
        $s3 = /mshta.*http:\/\//i
        $s4 = /mshta.*https:\/\//i
    condition:
        any of them
}

rule LOLBin_Regsvr32_Squiblydoo
{
    meta:
        description = "Regsvr32 squiblydoo / proxy execution"
        severity = "high"
        score = 70
        mitre = "T1218.010"
    strings:
        $s1 = /regsvr32.*scrobj\.dll/i
        $s2 = /regsvr32.*\/s.*\/i:http/i
        $s3 = /regsvr32.*\/u.*http/i
    condition:
        any of them
}

rule LOLBin_WMIC_Abuse
{
    meta:
        description = "WMIC process creation or XSL abuse"
        severity = "high"
        score = 70
        mitre = "T1047"
    strings:
        $s1 = /wmic.*process\s+call\s+create/i
        $s2 = /wmic.*/node:/i
        $s3 = /wmic.*shadowcopy\s+delete/i
        $s4 = /wmic.*format:.*http/i
        $s5 = /wmic.*os\s+get/i
    condition:
        any of them
}

rule LOLBin_PowerShell_Obfuscation
{
    meta:
        description = "PowerShell obfuscation and evasion techniques"
        severity = "high"
        score = 65
        mitre = "T1059.001"
    strings:
        $s1 = /powershell.*-enc\s/i
        $s2 = /powershell.*-encodedcommand\s/i
        $s3 = /powershell.*-nop.*-w\s+hidden/i
        $s4 = /powershell.*-ep\s+bypass/i
        $s5 = "Invoke-Expression" ascii nocase
        $s6 = /iex\s*\(/i
        $s7 = /\|\s*iex/i
        $s8 = /downloadstring\s*\(.*http/i
        $s9 = "FromBase64String" ascii nocase
        $s10 = "DownloadFile" ascii nocase
        $s11 = "Net.WebClient" ascii nocase
        $s12 = "Invoke-WebRequest" ascii nocase
    condition:
        2 of them
}

rule LOLBin_Download_Cradle
{
    meta:
        description = "Generic download cradle patterns"
        severity = "high"
        score = 65
        mitre = "T1059.001"
    strings:
        $s1 = "DownloadString(" ascii nocase
        $s2 = "DownloadFile(" ascii nocase
        $s3 = "Net.WebClient" ascii nocase
        $s4 = "Invoke-WebRequest" ascii nocase
        $s5 = "Start-BitsTransfer" ascii nocase
        $s6 = "wget " ascii nocase
        $s7 = "curl " ascii nocase
    condition:
        any of them
}
