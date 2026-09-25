// Suspicious Command Execution Patterns
rule Suspicious_Python_Reverse_Shell : reverse_shell python suspicious {
    meta:
        description = "Detects Python reverse shell one-liners"
        author = "Orin Security"
        severity = "high"
        attack = "T1059.006"
    strings:
        $py1 = "socket.socket(socket.AF_INET,socket.SOCK_STREAM)" ascii
        $py2 = "subprocess.call(['/bin/sh','-i'])" ascii
        $py3 = "os.dup2(s.fileno(),0)" ascii
        $py4 = "os.dup2(s.fileno(),1)" ascii
        $py5 = "os.dup2(s.fileno(),2)" ascii
    condition:
        2 of them
}

rule Suspicious_Bash_Reverse_Shell : reverse_shell bash suspicious {
    meta:
        description = "Detects Bash reverse shell patterns"
        author = "Orin Security"
        severity = "high"
        attack = "T1059.004"
    strings:
        $bash1 = "/bin/bash -i >& /dev/tcp/" ascii
        $bash2 = "0<&196;exec 196<>/dev/tcp/" ascii
        $bash3 = "bash -c 'bash -i'" ascii
    condition:
        any of them
}

rule Suspicious_Curl_Download_Execute : download execute suspicious {
    meta:
        description = "Detects curl/wget download and execute patterns"
        author = "Orin Security"
        severity = "medium"
        attack = "T1105"
    strings:
        $curl1 = "curl" ascii
        $curl2 = "wget" ascii
        $exec1 = "| sh" ascii
        $exec2 = "| bash" ascii
    condition:
        ($curl1 or $curl2) and ($exec1 or $exec2)
}