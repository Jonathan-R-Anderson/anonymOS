# bash completion for argus(8) and argus-server(8)
# Install system-wide:
#   sudo cp argus-completion.bash /etc/bash_completion.d/argus
# Install per-user:
#   echo '. /path/to/argus-completion.bash' >> ~/.bashrc

_argus_complete() {
    local cur prev words cword
    _init_completion || return

    local all_opts="
        --config --config-check
        --pid --follow --comm --path --exclude --events
        --ringbuf --summary --rate-limit
        --output --output-fmt --json --syslog
        --pid-file --no-drop-privs
        --rules
        --forward --forward-tls --forward-tls-noverify
        --baseline --baseline-learn --baseline-out
        --threat-intel
        --metrics-port
        --yara-rules-dir
        --lsm-deny
        --mitre-tags
        --webhook
        --exec-hash
        --vt-api-key
        --otx-api-key
        --response-isolate
        --store-path
        --store-query-port
        --container-enrich
        --compliance
        --compliance-report
        --syscall-anom
        --tls-data
        --mem-forensics
        --version --help
    "

    case "$prev" in
        --output-fmt)
            COMPREPLY=( $(compgen -W "text json cef syslog" -- "$cur") )
            return ;;
        --compliance)
            COMPREPLY=( $(compgen -W "cis pci-dss nist soc2" -- "$cur") )
            return ;;
        --events)
            local event_types="EXEC OPEN EXIT CONNECT UNLINK RENAME CHMOD BIND PTRACE DNS SEND WRITE_CLOSE PRIVESC MEMEXEC KMOD_LOAD THREAT_INTEL PROC_SCRAPE NS_ESCAPE"
            COMPREPLY=( $(compgen -W "$event_types" -- "$cur") )
            return ;;
        --config|--output|--pid-file|--rules|--baseline|--baseline-out| \
        --threat-intel|--yara-rules-dir|--store-path|--compliance-report)
            _filedir
            return ;;
        --pid|--follow|--ringbuf|--summary|--rate-limit|--metrics-port| \
        --store-query-port|--syscall-anom|--baseline-learn)
            # numeric argument — no completions
            return ;;
        --forward)
            # host:port — no useful completion
            return ;;
        --webhook|--vt-api-key|--otx-api-key|--otx-api-key)
            # string argument — no completions
            return ;;
    esac

    COMPREPLY=( $(compgen -W "$all_opts" -- "$cur") )
}

_argus_server_complete() {
    local cur prev
    _init_completion || return

    local all_opts="
        --port --output --stats-interval
        --correlate-window --correlate-threshold
        --mgmt-port --hb-timeout
        --help
    "

    case "$prev" in
        --port|--stats-interval|--correlate-window| \
        --correlate-threshold|--mgmt-port|--hb-timeout)
            return ;;  # numeric — no completions
        --output)
            _filedir
            return ;;
    esac

    COMPREPLY=( $(compgen -W "$all_opts" -- "$cur") )
}

complete -F _argus_complete        argus
complete -F _argus_server_complete argus-server
