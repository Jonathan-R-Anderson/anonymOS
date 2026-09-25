rule Worm_Network_Propagation
{
    meta:
        description = "Detects network worm propagation patterns"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "critical"

    strings:
        $net1 = "NetShareEnum"
        $net2 = "NetUseAdd"
        $net3 = "WNetAddConnection"
        $net4 = "WNetEnumResource"
        $copy1 = "CopyFileA"
        $copy2 = "CopyFileW"
        $copy3 = "CopyFileExW"
        $scan1 = "connect"
        $scan2 = "gethostbyname"
        $scan3 = "inet_addr"
        $port1 = { 01 BB }  // port 443
        $port2 = { 00 8B }  // port 139
        $port3 = { 01 BD }  // port 445

    condition:
        (2 of ($net*)) and (1 of ($copy*)) or
        (1 of ($scan*) and 1 of ($port*) and 1 of ($copy*))
}

rule Worm_USB_Propagation
{
    meta:
        description = "Detects USB worm propagation via autorun"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "high"

    strings:
        $auto1 = "autorun.inf" nocase
        $auto2 = "[autorun]" nocase
        $auto3 = "open=" nocase
        $drive1 = "GetDriveTypeA"
        $drive2 = "GetDriveTypeW"
        $drive3 = "GetLogicalDrives"
        $copy1 = "CopyFileA"
        $copy2 = "CopyFileW"
        $removable = "DRIVE_REMOVABLE"

    condition:
        (1 of ($auto*)) and (1 of ($drive*)) and (1 of ($copy*))
}

rule Worm_Email_Spreader
{
    meta:
        description = "Detects email worm spreading patterns"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "high"

    strings:
        $mapi1 = "MAPISendMail"
        $smtp1 = "MAIL FROM:" nocase
        $smtp2 = "RCPT TO:" nocase
        $smtp3 = "DATA\r\n" nocase
        $addr1 = "GetAddressBook"
        $addr2 = ".wab" nocase
        $addr3 = "Contacts" nocase
        $attach1 = "Content-Disposition: attachment" nocase

    condition:
        ($mapi1 or (2 of ($smtp*))) and
        (1 of ($addr*) or 1 of ($attach*))
}
