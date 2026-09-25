rule XPlat_Cobalt_Strike_Payload
{
    meta:
        description = "Detects Cobalt Strike shellcode and stager patterns across platforms"
        author = "prx-sd"
        date = "2026-03-17"
        severity = "critical"
        platform = "any"

    strings:
        $beacon_magic = { 2E 2F 2E 2F 2E 2C }
        $pipe1 = "\\\\.\\pipe\\msagent_"
        $pipe2 = "\\\\.\\pipe\\MSSE-"
        $pipe3 = "\\\\.\\pipe\\status_"
        $pipe4 = "\\\\.\\pipe\\postex_"
        $config_xor = { 69 68 69 68 69 6B 69 68 }
        $reflective = "ReflectiveLoader"
        $submit = "/submit.php?id="
        $stager_x86 = { FC E8 89 00 00 00 60 89 E5 }
        $stager_x64 = { FC 48 83 E4 F0 E8 C8 00 00 00 }
        $sleeptime = "sleeptime"
        $jitter = "jitter"
        $spawn1 = "spawnto"
        $cs_ua = "Mozilla/5.0 (compatible; MSIE"
        $post_ex = "post-ex"
        $malleable = "Content-Type: application/octet-stream"

    condition:
        (
            ($stager_x86 or $stager_x64) or
            ($beacon_magic) or
            ($config_xor) or
            ($reflective and 1 of ($pipe*)) or
            ($submit and ($sleeptime or $jitter)) or
            (2 of ($pipe*)) or
            ($reflective and ($sleeptime or $jitter) and 1 of ($spawn1, $post_ex))
        )
}

rule XPlat_Metasploit_Shellcode
{
    meta:
        description = "Detects Metasploit framework shellcode patterns for multiple architectures"
        author = "prx-sd"
        date = "2026-03-17"
        severity = "critical"
        platform = "any"

    strings:
        $linux_x86_exec = { 31 C0 50 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 53 89 E1 B0 0B CD 80 }
        $linux_x64_exec = { 48 31 D2 52 48 B8 2F 62 69 6E 2F 2F 73 68 50 48 89 E7 52 57 48 89 E6 48 31 C0 B0 3B 0F 05 }
        $linux_x86_rev = { 6A 66 58 6A 01 5B 99 52 53 6A 02 89 E1 CD 80 }
        $linux_x64_rev = { 6A 29 58 99 6A 02 5F 6A 01 5E 0F 05 48 97 }
        $osx_x64_rev = { 41 B0 02 49 C1 E0 18 49 83 C8 61 }
        $shikata = { D9 74 24 F4 5? [4-8] 31 }
        $xor_decoder = { 31 C9 B1 ?? 83 ?? 04 31 }
        $msfvenom1 = "msfvenom" fullword
        $msfvenom2 = "metasploit" nocase fullword
        $msfpayload = "windows/meterpreter"
        $stage1 = "stage0"
        $stage2 = "stager"

    condition:
        (
            (1 of ($linux_x86_exec, $linux_x64_exec)) or
            (1 of ($linux_x86_rev, $linux_x64_rev, $osx_x64_rev)) or
            ($shikata) or
            ($xor_decoder) or
            ($msfvenom1 and 1 of ($stage*)) or
            ($msfpayload)
        )
}

rule XPlat_Webshell_Generic
{
    meta:
        description = "Detects generic webshells - PHP, JSP, and ASP variants"
        author = "prx-sd"
        date = "2026-03-17"
        severity = "critical"
        platform = "any"

    strings:
        $php_eval1 = "eval($_POST" nocase
        $php_eval2 = "eval($_GET" nocase
        $php_eval3 = "eval($_REQUEST" nocase
        $php_exec1 = "system($_" nocase
        $php_exec2 = "passthru($_" nocase
        $php_exec3 = "shell_exec($_" nocase
        $php_exec4 = "exec($_" nocase
        $php_exec5 = "popen($_" nocase
        $php_obf1 = "eval(base64_decode" nocase
        $php_obf2 = "assert(base64_decode" nocase
        $php_obf3 = "preg_replace(\"/.*/" nocase
        $jsp1 = "Runtime.getRuntime().exec("
        $jsp2 = "ProcessBuilder"
        $jsp3 = "request.getParameter"
        $jsp_cmd = { 52 75 6E 74 69 6D 65 2E 67 65 74 52 75 6E 74 69 6D 65 }
        $asp1 = "eval(Request" nocase
        $asp2 = "Execute(Request" nocase
        $asp3 = "CreateObject(\"WScript.Shell\")" nocase
        $asp4 = "Response.Write" nocase
        $chopper = { 40 65 76 61 6C 28 }

    condition:
        (
            (1 of ($php_eval*)) or
            (1 of ($php_exec*)) or
            (1 of ($php_obf*)) or
            ($jsp1 and $jsp3) or
            ($jsp2 and $jsp3) or
            (1 of ($asp1, $asp2) and ($asp3 or $asp4)) or
            ($chopper and filesize < 5KB)
        )
}

rule XPlat_Base64_Payload
{
    meta:
        description = "Detects heavily base64-encoded payload with execution - common obfuscation technique"
        author = "prx-sd"
        date = "2026-03-17"
        severity = "high"
        platform = "any"

    strings:
        $b64_exec1 = "base64_decode" nocase
        $b64_exec2 = "atob(" nocase
        $b64_exec3 = "base64 -d"
        $b64_exec4 = "base64 --decode"
        $b64_exec5 = "b64decode" nocase
        $b64_exec6 = "Base64.decode" nocase
        $b64_exec7 = "Buffer.from(" nocase
        $eval1 = "eval(" nocase
        $eval2 = "exec(" nocase
        $eval3 = "system(" nocase
        $eval4 = "os.system(" nocase
        $eval5 = "subprocess.Popen(" nocase
        $eval6 = "child_process" nocase
        $eval7 = "Function(" nocase
        $long_b64 = /[A-Za-z0-9+\/=]{200,}/
        $pipe_bash = "| bash"
        $pipe_sh = "| sh"
        $pipe_python = "| python"

    condition:
        (
            (1 of ($b64_exec*) and 1 of ($eval*)) or
            ($long_b64 and 1 of ($b64_exec*) and 1 of ($eval*)) or
            (1 of ($b64_exec3, $b64_exec4) and 1 of ($pipe_bash, $pipe_sh, $pipe_python)) or
            ($long_b64 and 1 of ($pipe_bash, $pipe_sh) and 1 of ($b64_exec*))
        )
}

rule XPlat_Credential_Harvester
{
    meta:
        description = "Detects credential harvesting targeting Linux and macOS credential stores"
        author = "prx-sd"
        date = "2026-03-17"
        severity = "critical"
        platform = "any"

    strings:
        $linux_shadow = "/etc/shadow"
        $linux_passwd = "/etc/passwd"
        $ssh_key1 = ".ssh/id_rsa"
        $ssh_key2 = ".ssh/id_ed25519"
        $ssh_key3 = ".ssh/id_ecdsa"
        $ssh_known = ".ssh/known_hosts"
        $ssh_auth = ".ssh/authorized_keys"
        $chrome1 = "Chrome/Default/Login Data"
        $chrome2 = "chrome/Default/Cookies"
        $chrome3 = "chromium/Default/Login Data"
        $firefox1 = "Firefox/Profiles"
        $firefox2 = "logins.json"
        $firefox3 = "key4.db"
        $firefox4 = "cert9.db"
        $macos_kc = "login.keychain"
        $macos_sec = "security find-generic-password"
        $gnome_kr = "gnome-keyring"
        $kwallet = "kwallet"
        $aws1 = ".aws/credentials"
        $aws2 = ".aws/config"
        $kube = ".kube/config"
        $docker_cfg = ".docker/config.json"
        $gpg = ".gnupg/secring"
        $env_file = ".env"

    condition:
        (
            ($linux_shadow and ($linux_passwd or 1 of ($ssh_key*))) or
            (3 of ($ssh_key*, $ssh_known, $ssh_auth)) or
            (2 of ($chrome*) or 2 of ($firefox*)) or
            ($macos_kc or $macos_sec) and (1 of ($chrome*, $firefox*, $ssh_key*)) or
            (1 of ($aws*) and 1 of ($ssh_key*)) or
            (3 of ($aws*, $kube, $docker_cfg, $gpg, $env_file))
        )
}

rule XPlat_Data_Exfiltration
{
    meta:
        description = "Detects data exfiltration patterns via HTTP, DNS, or raw sockets"
        author = "prx-sd"
        date = "2026-03-17"
        severity = "high"
        platform = "any"

    strings:
        $curl_post = "curl -X POST"
        $curl_data = "curl -d"
        $curl_file = "curl -F"
        $curl_silent = "curl -s"
        $wget_post = "wget --post-data"
        $wget_post2 = "wget --post-file"
        $nc1 = "nc -w"
        $nc2 = "ncat "
        $tcp1 = "/dev/tcp/"
        $tcp2 = "/dev/udp/"
        $tar_pipe = "tar czf -"
        $zip_pipe = "zip -r -"
        $archive1 = "tar czf"
        $archive2 = "zip -r"
        $exfil1 = "base64"
        $exfil2 = "xxd"
        $exfil3 = "openssl"
        $dns_exfil1 = "dig @"
        $dns_exfil2 = "nslookup"
        $dns_exfil3 = ".ns."
        $sensitive1 = "/etc/shadow"
        $sensitive2 = ".ssh/"
        $sensitive3 = "credentials"
        $sensitive4 = ".aws/"

    condition:
        (
            (1 of ($curl_post, $curl_data, $curl_file) and 1 of ($sensitive*)) or
            (1 of ($wget_post*) and 1 of ($sensitive*)) or
            (1 of ($nc*, $tcp*) and 1 of ($archive*, $tar_pipe, $zip_pipe)) or
            (1 of ($dns_exfil*) and 1 of ($exfil*)) or
            (1 of ($curl_post, $curl_data) and 1 of ($exfil*) and 1 of ($archive*)) or
            (1 of ($tar_pipe, $zip_pipe) and 1 of ($nc*, $tcp*, $curl_post))
        )
}

rule XPlat_Container_Escape
{
    meta:
        description = "Detects container escape attempts from Docker, Kubernetes, and other runtimes"
        author = "prx-sd"
        date = "2026-03-17"
        severity = "critical"
        platform = "any"

    strings:
        $proc_root = "/proc/1/root"
        $proc_cgroup = "/proc/1/cgroup"
        $proc_status = "/proc/self/status"
        $nsenter1 = "nsenter -t 1"
        $nsenter2 = "nsenter --mount"
        $nsenter3 = "nsenter --target"
        $docker_sock1 = "/var/run/docker.sock"
        $docker_sock2 = "docker.sock"
        $docker_sock3 = "/run/containerd/containerd.sock"
        $cgroup1 = "cgroup"
        $cgroup2 = "release_agent"
        $cgroup3 = "notify_on_release"
        $cap1 = "cap_sys_admin" nocase
        $cap2 = "cap_sys_ptrace" nocase
        $cap3 = "cap_net_admin" nocase
        $priv1 = "--privileged"
        $priv2 = "securityContext"
        $chroot = "chroot /host"
        $mount_host = "mount /dev/"
        $kubelet1 = "kubelet"
        $kubelet2 = "serviceaccount/token"
        $kubelet3 = "kubernetes.io/serviceaccount"
        $metadata = "169.254.169.254"

    condition:
        (
            ($proc_root and 1 of ($nsenter*)) or
            (1 of ($docker_sock*) and 1 of ($priv*)) or
            ($cgroup2 and $cgroup3) or
            (1 of ($cap*) and 1 of ($nsenter*)) or
            ($chroot and 1 of ($docker_sock*)) or
            ($mount_host and 1 of ($docker_sock*)) or
            (2 of ($kubelet*) and $metadata) or
            (1 of ($docker_sock*) and 1 of ($nsenter*) and $proc_root)
        )
}
