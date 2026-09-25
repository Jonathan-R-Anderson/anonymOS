// Web Shell Detection
rule WebShell_PHP_Generic : webshell php backdoor {
    meta:
        description = "Generic PHP webshell detection"
        author = "Orin Security"
        severity = "critical"
        attack = "T1505.003"
    strings:
        $php1 = "<?php" ascii
        $php2 = "eval(" ascii
        $php3 = "base64_decode(" ascii
        $php4 = "gzinflate(" ascii
        $shell1 = "system(" ascii
        $shell2 = "exec(" ascii
        $shell3 = "passthru(" ascii
        $shell4 = "shell_exec(" ascii
    condition:
        $php1 and ($php2 or $php3 or $php4) and ($shell1 or $shell2 or $shell3 or $shell4)
}

rule WebShell_PHP_C99_Variant : webshell php c99 backdoor {
    meta:
        description = "C99-style PHP webshell detection"
        author = "Orin Security"
        severity = "critical"
        attack = "T1505.003"
    strings:
        $c99_1 = "$safe_mode = false;" ascii
        $c99_2 = "function ex($c){" ascii
        $c99_3 = "ini_set(\"max_execution_time\",0);" ascii
        $c99_4 = "@set_time_limit(0);" ascii
        $c99_5 = "Security mode is" ascii
    condition:
        2 of them
}