rule SuspiciousShellScript {
    meta:
        description = "Detects common suspicious commands used in shell scripts"
        author = "Spectre"
    strings:
        $s1 = "/bin/sh -i"
        $s2 = "/bin/bash -i"
        $s3 = "nc -e"
        $s4 = "eval("
        $s5 = "base64 -d"
        $s6 = "curl -sL"
        $s7 = "wget -qO"
    condition:
        any of ($s*)
}
