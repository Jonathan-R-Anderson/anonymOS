#compdef argus argus-server
# zsh completion for argus(8) and argus-server(8)
# Install:
#   sudo cp argus-completion.zsh /usr/local/share/zsh/site-functions/_argus
#   autoload -Uz compinit && compinit

_argus() {
    local context state state_descr line
    typeset -A opt_args

    _arguments -C \
        '--config[Load JSON config file]:config file:_files' \
        '--config-check[Print active config and exit]' \
        '--pid[Trace only this PID]:pid:' \
        '--follow[Trace PID and all children]:pid:' \
        '--comm[Trace processes with this comm]:comm:' \
        '--path[Filter events by filename substring]:path:' \
        '--exclude[Exclude path prefix (repeatable)]:prefix:_files -/' \
        '--events[Comma-separated event types]:events:->events' \
        '--ringbuf[Ring buffer size in KB]:kb:(64 128 256 512 1024 4096)' \
        '--summary[Summary interval in seconds]:secs:' \
        '--rate-limit[Events/sec limit per comm]:n:' \
        '--output[Append events to file]:file:_files' \
        '--output-fmt[Output format]:fmt:(text json cef syslog)' \
        '--json[Shorthand for --output-fmt json]' \
        '--syslog[Shorthand for --output-fmt syslog]' \
        '--pid-file[Write PID to file]:file:_files' \
        '--no-drop-privs[Stay root after BPF attach]' \
        '--rules[Alert rules JSON file]:file:_files' \
        '--forward[Forward events to host:port]:host\:port:' \
        '--forward-tls[Enable TLS for --forward]' \
        '--forward-tls-noverify[TLS without cert verification]' \
        '--baseline[Baseline profile file]:file:_files' \
        '--baseline-learn[Learn baseline for N seconds]:secs:' \
        '--baseline-out[Write learned baseline to file]:file:_files' \
        '--threat-intel[Threat intel blocklist file]:file:_files' \
        '--metrics-port[Prometheus metrics port]:port:' \
        '--yara-rules-dir[YARA rules directory]:dir:_files -/' \
        '--lsm-deny[Block matching execs via LSM hook]' \
        '--mitre-tags[Annotate alerts with MITRE ATT&CK IDs]' \
        '--webhook[POST alerts to this URL]:url:' \
        '--exec-hash[SHA-256 hash executed binaries]' \
        '--vt-api-key[VirusTotal API key]:key:' \
        '--otx-api-key[AlienVault OTX API key]:key:' \
        '--response-isolate[iptables-isolate THREAT_INTEL sources]' \
        '--store-path[SQLite event store path]:file:_files' \
        '--store-query-port[HTTP query API port for event store]:port:' \
        '--container-enrich[Enrich events with Docker metadata]' \
        '--compliance[Compliance framework]:framework:(cis pci-dss nist soc2)' \
        '--compliance-report[HTML report output path]:file:_files' \
        '--syscall-anom[Syscall anomaly detection interval]:secs:' \
        '--tls-data[Capture decrypted TLS payloads via uprobe]' \
        '--mem-forensics[Inspect anonymous exec mappings]' \
        '--version[Print version and exit]' \
        '--help[Show usage and exit]'

    case $state in
        events)
            local -a event_types
            event_types=(
                'EXEC:Process execve/execveat'
                'OPEN:File openat'
                'EXIT:Process exit'
                'CONNECT:Outbound connect'
                'UNLINK:File deletion'
                'RENAME:File rename'
                'CHMOD:Permission change'
                'BIND:Socket bind'
                'PTRACE:ptrace call'
                'DNS:DNS query (sendto port 53)'
                'SEND:sendto payload capture'
                'WRITE_CLOSE:close on write-mode fd'
                'PRIVESC:Privilege escalation'
                'MEMEXEC:Anonymous executable mmap'
                'KMOD_LOAD:Kernel module load'
                'THREAT_INTEL:Threat intel blocklist match'
                'PROC_SCRAPE:/proc/<pid>/mem read'
                'NS_ESCAPE:Namespace escape attempt'
            )
            _describe 'event type' event_types
            ;;
    esac
}

_argus_server() {
    _arguments \
        '--port[Listen port]:port:(9000)' \
        '--output[Write merged stream to file]:file:_files' \
        '--stats-interval[Print stats every N seconds]:secs:' \
        '--correlate-window[Fleet correlation time window]:secs:' \
        '--correlate-threshold[Distinct hosts to trigger fleet alert]:n:' \
        '--mgmt-port[Management API port]:port:' \
        '--hb-timeout[Close agents silent for N seconds]:secs:' \
        '--help[Show usage and exit]'
}

_argus "$@"
