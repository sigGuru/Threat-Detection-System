rule EICAR_Test_File
{
    meta:
        description = "Detects EICAR test file"
        author = "Guru"
        severity = "low"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PE_Name
{
    meta:
        description = "Flags PE files with suspicious names"
        author = "Guru"
        severity = "medium"
    strings:
        $mal = "malware"
        $drop = "dropper"
    condition:
        any of ($mal, $drop)
}
