// Cryptocurrency Miner Detection
rule CryptoMiner_XMRig_Generic : cryptominer xmrig malware {
    meta:
        description = "Generic XMRig cryptocurrency miner detection"
        author = "Orin Security"
        severity = "medium"
        attack = "T1496"
    strings:
        $s1 = "XMRig" ascii
        $s2 = "xmrig" ascii
        $s3 = "Donate level:" ascii
        $s4 = "stratum+tcp://" ascii
        $s5 = "pool." ascii nocase
    condition:
        2 of them
}

rule CryptoMiner_Stratum_Protocol : cryptominer stratum suspicious {
    meta:
        description = "Detects Stratum mining protocol strings"
        author = "Orin Security"
        severity = "medium"
        attack = "T1496"
    strings:
        $stratum1 = "{\"id\":1,\"method\":\"mining.subscribe\"" ascii
        $stratum2 = "{\"method\":\"mining.notify\"" ascii
        $stratum3 = "mining.submit" ascii
    condition:
        $stratum1 or $stratum2 or $stratum3
}