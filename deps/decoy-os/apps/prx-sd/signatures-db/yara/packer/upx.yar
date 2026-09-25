rule UPX_Packed
{
    meta:
        description = "Detects UPX packed executables"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "info"

    strings:
        $upx_magic = "UPX!"
        $upx_section0 = "UPX0"
        $upx_section1 = "UPX1"
        $upx_section2 = "UPX2"
        $upx_header = { 55 50 58 21 0D 0A }  // "UPX!\r\n"

    condition:
        uint16(0) == 0x5A4D and  // MZ header
        ($upx_magic or ($upx_section0 and $upx_section1) or $upx_header)
}

rule UPX_Modified
{
    meta:
        description = "Detects modified UPX (header stripped/altered)"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "medium"

    strings:
        $upx_stub = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 }  // UPX decompression stub
        $upx_stub64 = { 53 56 57 55 48 8D 35 }  // UPX 64-bit stub

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($upx_stub*)) and
        not for any of them : ( $ at 0 )
}
