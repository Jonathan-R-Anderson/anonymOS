rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file"
        author = "prx-sd"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
        date = "2026-03-16"
        severity = "test"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar at 0
}

rule EICAR_Test_File_Anywhere
{
    meta:
        description = "EICAR test string found anywhere in file"
        author = "prx-sd"
        severity = "test"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}
