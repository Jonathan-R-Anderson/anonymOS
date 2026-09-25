// Rootkit Detection Signatures
rule Rootkit_Diamorphine_Signature : rootkit linux kernel diamorphine {
    meta:
        description = "Diamorphine kernel rootkit detection"
        author = "Orin Security"
        severity = "critical"
        attack = "T1014"
    strings:
        $mod1 = "module_init(diamorphine_init)" ascii
        $mod2 = "hiding_module" ascii
        $mod3 = "orig_getdents64" ascii
        $mod4 = "orig_getdents" ascii
        $kill_signal = "63" ascii
        $clean_signal = "64" ascii
    condition:
        2 of them
}

rule Rootkit_Reptile_Signature : rootkit linux kernel reptile {
    meta:
        description = "Reptile kernel rootkit detection"
        author = "Orin Security"
        severity = "critical"
        attack = "T1014"
    strings:
        $rep1 = "reptile_net" ascii
        $rep2 = "reptile.h" ascii
        $rep3 = "reptile.c" ascii
        $magic = "CAFEBABE" ascii
    condition:
        2 of them
}