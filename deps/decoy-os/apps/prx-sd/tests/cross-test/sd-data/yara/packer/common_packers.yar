rule ASPack_Packed
{
    meta:
        description = "Detects ASPack packed executables"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "info"

    strings:
        $aspack1 = ".aspack" nocase
        $aspack2 = ".adata" nocase
        $stub = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD }

    condition:
        uint16(0) == 0x5A4D and
        ($aspack1 or $aspack2 or $stub)
}

rule Themida_Packed
{
    meta:
        description = "Detects Themida/WinLicense protected executables"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "medium"

    strings:
        $section1 = ".themida"
        $section2 = ".winlice"
        $section3 = "WinLicen"
        $vmp = ".vmp0"

    condition:
        uint16(0) == 0x5A4D and
        (1 of them)
}

rule VMProtect_Packed
{
    meta:
        description = "Detects VMProtect packed executables"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "medium"

    strings:
        $vmp0 = ".vmp0"
        $vmp1 = ".vmp1"
        $vmp2 = ".vmp2"
        $vmprotect = "VMProtect" nocase

    condition:
        uint16(0) == 0x5A4D and
        (2 of them)
}

rule PECompact_Packed
{
    meta:
        description = "Detects PECompact packed executables"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "info"

    strings:
        $pec = "PEC2"
        $pec2 = "pec"
        $section = ".petite"

    condition:
        uint16(0) == 0x5A4D and
        (1 of them)
}

rule MPRESS_Packed
{
    meta:
        description = "Detects MPRESS packed executables"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "info"

    strings:
        $mpress1 = ".MPRESS1"
        $mpress2 = ".MPRESS2"

    condition:
        uint16(0) == 0x5A4D and
        (1 of them)
}

rule Enigma_Protector
{
    meta:
        description = "Detects Enigma Protector packed executables"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "medium"

    strings:
        $enigma1 = ".enigma1"
        $enigma2 = ".enigma2"
        $ep = "The Enigma Protector"

    condition:
        uint16(0) == 0x5A4D and
        (1 of them)
}
