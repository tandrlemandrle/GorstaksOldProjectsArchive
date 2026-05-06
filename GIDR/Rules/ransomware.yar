rule Ransomware_Indicators
{
    meta:
        description = "Generic ransomware behavioral indicators"
        severity = "critical"
        score = 80
        mitre = "T1486"
    strings:
        $cmd1 = "vssadmin delete shadows" ascii nocase
        $cmd2 = "wbadmin delete catalog" ascii nocase
        $cmd3 = "bcdedit /set {default} recoveryenabled no" ascii nocase
        $cmd4 = "wmic shadowcopy delete" ascii nocase
        $cmd5 = "vssadmin resize shadowstorage" ascii nocase
        $note1 = "your files have been encrypted" ascii nocase
        $note2 = "pay the ransom" ascii nocase
        $note3 = "bitcoin" ascii nocase
        $note4 = "decrypt your files" ascii nocase
        $note5 = "payment required" ascii nocase
        $note6 = "all your files" ascii nocase
        $note7 = "recover your files" ascii nocase
        $crypto1 = "CryptoLocker" ascii nocase
        $crypto2 = "WannaCry" ascii nocase
        $crypto3 = "Petya" ascii nocase
        $crypto4 = "Locky" ascii nocase
        $crypto5 = "Cerber" ascii nocase
    condition:
        2 of ($cmd*) or (1 of ($cmd*) and 1 of ($note*)) or 2 of ($note*) or any of ($crypto*)
}

rule Ransomware_CryptoAPI_Abuse
{
    meta:
        description = "Ransomware-style crypto API usage with file operations"
        severity = "high"
        score = 60
        mitre = "T1486"
    strings:
        $api1 = "CryptEncrypt" ascii
        $api2 = "CryptGenKey" ascii
        $api3 = "CryptImportKey" ascii
        $api4 = "CryptAcquireContext" ascii
        $api5 = "BCryptEncrypt" ascii
        $api6 = "BCryptGenerateSymmetricKey" ascii
        $file1 = "FindFirstFile" ascii
        $file2 = "FindNextFile" ascii
        $file3 = "MoveFileEx" ascii
        $file4 = "DeleteFile" ascii
    condition:
        2 of ($api*) and 2 of ($file*)
}

rule Shadow_Copy_Deletion
{
    meta:
        description = "Shadow copy / backup deletion commands"
        severity = "critical"
        score = 90
        mitre = "T1490"
    strings:
        $s1 = /vssadmin.*delete\s+shadows/i
        $s2 = /wbadmin\s+delete/i
        $s3 = /bcdedit.*recoveryenabled.*no/i
        $s4 = /wmic\s+shadowcopy\s+delete/i
    condition:
        any of them
}
