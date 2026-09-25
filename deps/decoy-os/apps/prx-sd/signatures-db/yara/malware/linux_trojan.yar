rule Linux_Trojan_Meterpreter
{
    meta:
        description = "Detects Metasploit Meterpreter reverse shell payload on Linux"
        author = "prx-sd"
        date = "2026-03-17"
        severity = "critical"
        platform = "linux"
        reference = "https://github.com/rapid7/metasploit-framework"

    strings:
        $core1 = "core_channel_open"
        $core2 = "core_channel_write"
        $core3 = "core_channel_read"
        $core4 = "core_channel_close"
        $stdapi1 = "stdapi_sys_process_execute"
        $stdapi2 = "stdapi_fs_ls"
        $stdapi3 = "stdapi_fs_file_upload"
        $stdapi4 = "stdapi_sys_config_getuid"
        $stdapi5 = "stdapi_net_socket_tcp_shutdown"
        $met1 = "metsrv"
        $met2 = "met_api"
        $met3 = "process_execute"
        $met4 = "ext_server_stdapi"
        $stager1 = { 6A 29 58 99 6A 02 5F 6A 01 5E 0F 05 }
        $stager2 = { 48 B8 02 00 }

    condition:
        uint32(0) == 0x464C457F and
        (
            (2 of ($core*) and 1 of ($stdapi*)) or
            (1 of ($met*) and 1 of ($stdapi*)) or
            ($stager1 and $stager2) or
            (3 of ($stdapi*)) or
            ($met1 and 1 of ($core*))
        )
}

rule Linux_Trojan_Cobalt_Strike_Beacon
{
    meta:
        description = "Detects Cobalt Strike beacon implant on Linux systems"
        author = "prx-sd"
        date = "2026-03-17"
        severity = "critical"
        platform = "linux"

    strings:
        $beacon1 = "beacon.dll" fullword
        $beacon2 = "beacon.x64.dll"
        $beacon3 = "ReflectiveLoader"
        $config1 = "%s.%d.%s"
        $config2 = "BeaconDataParse"
        $config3 = "BeaconDataPtr"
        $config4 = "BeaconDataInt"
        $func1 = "sleep_mask" fullword
        $func2 = "pipe_name" fullword
        $func3 = "spawnto_x64"
        $func4 = "spawnto_x86"
        $net1 = "/submit.php"
        $net2 = "/beacon"
        $net3 = "Content-Type: application/octet-stream"
        $xor_cfg = { 69 68 69 68 69 6B }
        $named_pipe = "\\\\.\\pipe\\"
        $watermark = { 01 00 01 00 02 00 }
        $proxy = "PROXY_CONFIG"

    condition:
        (
            (2 of ($beacon*)) or
            (2 of ($config*) and 1 of ($func*)) or
            (1 of ($beacon*) and 1 of ($net*) and 1 of ($func*)) or
            ($xor_cfg and 1 of ($config*)) or
            ($named_pipe and 1 of ($beacon*) and 1 of ($config*))
        )
}

rule Linux_Trojan_BPFDoor
{
    meta:
        description = "Detects BPFDoor backdoor - uses BPF packet filters to hide C2, attributed to state-sponsored actors"
        author = "prx-sd"
        date = "2026-03-17"
        severity = "critical"
        platform = "linux"
        reference = "https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/bpfdoor.html"

    strings:
        $bpf1 = "BPF_LD"
        $bpf2 = "BPF_JMP"
        $bpf3 = "BPF_RET"
        $pcap1 = "pcap_open_live"
        $pcap2 = "pcap_setfilter"
        $pcap3 = "pcap_compile"
        $pcap4 = "pcap_loop"
        $magic1 = "magic_packet"
        $magic2 = { 21 07 15 21 }
        $magic3 = { 7F EE 01 02 }
        $persist1 = "/var/run/haldrund"
        $persist2 = "/dev/shm/kdmtmpflush"
        $persist3 = "/var/run/kdevrund"
        $shell1 = "/bin/sh"
        $shell2 = "dup2"
        $iptables = "iptables"
        $env_clean = "unsetenv"

    condition:
        uint32(0) == 0x464C457F and
        (
            (2 of ($bpf*) and 1 of ($pcap*) and 1 of ($shell*)) or
            (1 of ($magic*) and 1 of ($pcap*) and 1 of ($persist*)) or
            (1 of ($persist*) and 1 of ($pcap*) and $iptables) or
            (2 of ($pcap*) and 1 of ($magic*) and $env_clean)
        )
}

rule Linux_Trojan_Symbiote
{
    meta:
        description = "Detects Symbiote malware - LD_PRELOAD-based rootkit/trojan that hooks libc functions"
        author = "prx-sd"
        date = "2026-03-17"
        severity = "critical"
        platform = "linux"
        reference = "https://blogs.blackberry.com/en/2022/06/symbiote-a-new-nearly-impossible-to-detect-linux-threat"

    strings:
        $preload1 = "LD_PRELOAD"
        $preload2 = "/etc/ld.so.preload"
        $lib1 = "libsystem.so"
        $lib2 = "libnetfilter.so"
        $hook1 = "hook_connect"
        $hook2 = "hook_accept"
        $hook3 = "hook_read"
        $hook4 = "hook_write"
        $hide1 = "hide_tcp"
        $hide2 = "hide_tcp6"
        $hide3 = "hide_udp"
        $hide4 = "hide_process"
        $dlsym1 = "dlsym"
        $dlsym2 = "RTLD_NEXT"
        $libc1 = "readdir"
        $libc2 = "getdents"
        $libc3 = "fopen"
        $proc = "/proc/net/tcp"

    condition:
        (
            (1 of ($preload*) and 2 of ($hook*) and 1 of ($hide*)) or
            (1 of ($lib*) and 2 of ($hide*)) or
            ($dlsym1 and $dlsym2 and 2 of ($hook*)) or
            (1 of ($preload*) and 2 of ($libc*) and 1 of ($hide*)) or
            (1 of ($lib*) and $proc and 1 of ($hook*))
        )
}

rule Linux_Trojan_RotaJakiro
{
    meta:
        description = "Detects RotaJakiro backdoor - double-headed dragon with rotating encryption and C2"
        author = "prx-sd"
        date = "2026-03-17"
        severity = "critical"
        platform = "linux"
        reference = "https://blog.netlab.360.com/stealth_backdoor_rotajakiro_en/"

    strings:
        $path1 = "/tmp/.X11-unix/"
        $path2 = "/tmp/.X1M-unix"
        $path3 = "/bin/systemd-daemon"
        $path4 = "$HOME/.gvfsd"
        $path5 = "$HOME/.dbus/sessions/"
        $func1 = "compress_data"
        $func2 = "rotate_key"
        $func3 = "jakiro" nocase
        $func4 = "encrypt_payload"
        $crypto1 = "AES_encrypt"
        $crypto2 = "rotate"
        $crypto3 = "XOR"
        $persist1 = "/.config/autostart/"
        $persist2 = "/etc/init/"
        $watchdog = "watchdog"
        $shmem = "shmget"
        $proc1 = "/proc/self/exe"

    condition:
        uint32(0) == 0x464C457F and
        (
            (2 of ($path*) and 1 of ($func*)) or
            ($func3 and 1 of ($crypto*)) or
            (1 of ($path*) and 1 of ($func*) and 1 of ($crypto*)) or
            (1 of ($path*) and 1 of ($persist*) and ($watchdog or $shmem))
        )
}

rule Linux_Trojan_Doki
{
    meta:
        description = "Detects Doki trojan - Docker container escape backdoor using dogecoin blockchain for C2"
        author = "prx-sd"
        date = "2026-03-17"
        severity = "critical"
        platform = "linux"
        reference = "https://www.intezer.com/blog/research/watch-your-containers-doki-infecting-docker-servers/"

    strings:
        $docker1 = "docker.sock"
        $docker2 = "/var/run/docker.sock"
        $docker3 = "docker exec"
        $docker4 = "docker run"
        $escape1 = "container_escape"
        $escape2 = "--privileged"
        $escape3 = "nsenter"
        $escape4 = "chroot /host"
        $escape5 = "/proc/1/root"
        $doge1 = "dogechain.info"
        $doge2 = "blockchain"
        $doge3 = "doge"
        $curl = "curl"
        $pivot1 = "pivot"
        $pivot2 = "lateral"
        $cron1 = "crontab"
        $cron2 = "/etc/cron.d"
        $ngrok = "ngrok"

    condition:
        uint32(0) == 0x464C457F and
        (
            (1 of ($docker*) and 1 of ($escape*) and 1 of ($doge*)) or
            (2 of ($docker*) and 2 of ($escape*)) or
            (1 of ($docker*) and 1 of ($escape*) and 1 of ($cron*)) or
            (1 of ($doge*) and $curl and 1 of ($escape*))
        )
}

rule Linux_Trojan_Kinsing
{
    meta:
        description = "Detects Kinsing cryptominer trojan - exploits misconfigured Docker/Redis/WebLogic"
        author = "prx-sd"
        date = "2026-03-17"
        severity = "high"
        platform = "linux"
        reference = "https://blog.aquasec.com/threat-alert-kinsing-malware"

    strings:
        $name1 = "kinsing" nocase fullword
        $name2 = "kdevtmpfsi" fullword
        $name3 = "/tmp/kdevtmpfsi"
        $name4 = "/tmp/kinsing"
        $scan1 = "masscan"
        $scan2 = "redis-cli"
        $scan3 = "zgrab"
        $spread1 = "/.ssh/known_hosts"
        $spread2 = "/.ssh/id_rsa"
        $spread3 = "ssh -o StrictHostKeyChecking=no"
        $mine1 = "stratum+tcp"
        $mine2 = "xmrig"
        $mine3 = "randomx"
        $kill1 = "pkill"
        $kill2 = "kill -9"
        $kill3 = "kthreaddi"
        $cron = "crontab"
        $dl1 = "curl"
        $dl2 = "wget"
        $persist = "/etc/ld.so.preload"

    condition:
        (
            (1 of ($name*) and 1 of ($mine*)) or
            (1 of ($name*) and 1 of ($scan*)) or
            (2 of ($name*)) or
            (1 of ($scan*) and 1 of ($mine*) and 1 of ($spread*)) or
            (1 of ($name*) and 1 of ($spread*) and 1 of ($dl*))
        )
}
