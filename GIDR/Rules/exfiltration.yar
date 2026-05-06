rule Data_Exfiltration
{
    meta:
        description = "Data exfiltration techniques"
        severity = "high"
        score = 60
        mitre = "T1048"
    strings:
        $s1 = "Compress-Archive" ascii nocase
        $s2 = /tar.*-czf/i
        $s3 = /7z.*a\s/i
        $s4 = "ToBase64String" ascii nocase
        $s5 = /nslookup.*txt/i
        $s6 = "dns tunnel" ascii nocase
        $s7 = "Invoke-DNSExfiltration" ascii nocase
    condition:
        2 of them
}

rule DNS_Tunneling_Indicators
{
    meta:
        description = "DNS tunneling tool indicators"
        severity = "high"
        score = 70
        mitre = "T1048.003"
    strings:
        $s1 = "iodine" ascii nocase
        $s2 = "dns2tcp" ascii nocase
        $s3 = "dnscat2" ascii nocase
        $s4 = "heyoka" ascii nocase
        $s5 = "DNSExfiltrator" ascii nocase
    condition:
        any of them
}

rule Network_Scanner
{
    meta:
        description = "Network scanning / reconnaissance tools"
        severity = "medium"
        score = 50
        mitre = "T1046"
    strings:
        $s1 = "nmap" ascii nocase
        $s2 = "masscan" ascii nocase
        $s3 = "port scan" ascii nocase
        $s4 = "network scan" ascii nocase
        $s5 = "Invoke-Portscan" ascii nocase
        $s6 = "Test-NetConnection" ascii nocase
    condition:
        2 of them
}

rule Cryptominer
{
    meta:
        description = "Cryptocurrency miner indicators"
        severity = "high"
        score = 65
        mitre = "T1496"
    strings:
        $s1 = "xmrig" ascii nocase
        $s2 = "ccminer" ascii nocase
        $s3 = "stratum+tcp://" ascii nocase
        $s4 = "stratum+ssl://" ascii nocase
        $s5 = "monero" ascii nocase
        $s6 = "cryptonight" ascii nocase
        $s7 = "hashrate" ascii nocase
        $s8 = "mining pool" ascii nocase
    condition:
        2 of them
}
