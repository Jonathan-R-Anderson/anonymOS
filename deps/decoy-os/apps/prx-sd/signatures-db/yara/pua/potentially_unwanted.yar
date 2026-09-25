rule PUA_Cryptocurrency_Miner
{
    meta:
        description = "Detects cryptocurrency mining software"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "medium"

    strings:
        $pool1 = "stratum+tcp://" nocase
        $pool2 = "stratum+ssl://" nocase
        $pool3 = "pool.minergate" nocase
        $pool4 = "xmrpool" nocase
        $pool5 = "nicehash" nocase
        $algo1 = "cryptonight" nocase
        $algo2 = "randomx" nocase
        $algo3 = "ethash" nocase
        $algo4 = "hashrate" nocase
        $miner1 = "xmrig" nocase
        $miner2 = "cpuminer" nocase
        $miner3 = "cgminer" nocase
        $miner4 = "bfgminer" nocase

    condition:
        (1 of ($pool*) and 1 of ($algo*)) or
        (2 of ($miner*)) or
        (1 of ($pool*) and 1 of ($miner*))
}

rule PUA_HackTool_Mimikatz
{
    meta:
        description = "Detects Mimikatz credential dumping tool"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "high"

    strings:
        $str1 = "mimikatz" nocase
        $str2 = "sekurlsa" nocase
        $str3 = "kerberos::golden" nocase
        $str4 = "lsadump::sam" nocase
        $str5 = "privilege::debug" nocase
        $str6 = "gentilkiwi" nocase
        $str7 = "wdigest" nocase
        $api1 = "LsaEnumerateLogonSessions"
        $api2 = "SamEnumerateUsersInDomain"
        $api3 = "SamQueryInformationUser"

    condition:
        3 of ($str*) or
        (1 of ($str*) and 2 of ($api*))
}

rule PUA_Remote_Admin_Tool
{
    meta:
        description = "Detects potentially unwanted remote administration tools"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "low"

    strings:
        $rat1 = "VNC" nocase
        $rat2 = "TeamViewer" nocase
        $rat3 = "AnyDesk" nocase
        $rat4 = "RealVNC" nocase
        $hidden1 = "hidden" nocase
        $hidden2 = "stealth" nocase
        $hidden3 = "silent" nocase
        $svc1 = "CreateService"
        $svc2 = "StartService"

    condition:
        (1 of ($rat*)) and (1 of ($hidden*)) and (1 of ($svc*))
}

rule PUA_Adware_Generic
{
    meta:
        description = "Detects generic adware patterns"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "low"

    strings:
        $ad1 = "advertising" nocase
        $ad2 = "sponsored" nocase
        $ad3 = "ad_click" nocase
        $ad4 = "track_install" nocase
        $browser1 = "BrowserHelper"
        $browser2 = "toolbar" nocase
        $browser3 = "extension" nocase
        $inject1 = "inject" nocase
        $inject2 = "hook" nocase
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" nocase

    condition:
        (2 of ($ad*) and 1 of ($browser*)) or
        ($reg1 and 1 of ($inject*))
}
