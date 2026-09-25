#compdef sd

# Zsh completion for PRX-SD (sd)
# Place in /usr/local/share/zsh/site-functions/_sd or ~/.zsh/completions/_sd

_sd() {
    local -a commands
    commands=(
        'scan:Scan a file or directory for threats'
        'monitor:Start real-time file system monitoring'
        'quarantine:Manage quarantined files'
        'update:Check for and apply signature database updates'
        'config:Manage engine configuration'
        'info:Display engine version and system info'
        'import:Import hash signatures from a blocklist file'
    )

    local -a global_opts
    global_opts=(
        '--log-level[Logging level]:level:(trace debug info warn error)'
        '--data-dir[Base data directory]:directory:_directories'
        '--help[Show help]'
        '--version[Show version]'
    )

    _arguments -C \
        '1:command:->command' \
        '*::arg:->args' \
        "${global_opts[@]}"

    case "$state" in
        command)
            _describe -t commands 'sd command' commands
            ;;
        args)
            case "${words[1]}" in
                scan)
                    _arguments \
                        '1:path:_files' \
                        '(-r --recursive)'{-r,--recursive}'[Recurse into subdirectories]' \
                        '--json[Output results as JSON]' \
                        '(-t --threads)'{-t,--threads}'[Number of scanner threads]:count:' \
                        '--auto-quarantine[Automatically quarantine threats]' \
                        '*'{-e,--exclude}'[Glob patterns to exclude]:pattern:' \
                        "${global_opts[@]}"
                    ;;
                monitor)
                    _arguments \
                        '*:path:_directories' \
                        '--block[Block malicious files before access]' \
                        '--daemon[Run as background daemon]' \
                        "${global_opts[@]}"
                    ;;
                quarantine)
                    local -a qactions
                    qactions=(
                        'list:List all quarantined files'
                        'restore:Restore a quarantined file'
                        'delete:Permanently delete a quarantined file'
                        'delete-all:Permanently delete all quarantined files'
                        'stats:Show quarantine statistics'
                    )
                    _arguments -C \
                        '1:action:->qaction' \
                        '*::qarg:->qargs' \
                        "${global_opts[@]}"
                    case "$state" in
                        qaction)
                            _describe -t qactions 'quarantine action' qactions
                            ;;
                        qargs)
                            case "${words[1]}" in
                                restore)
                                    _arguments \
                                        '1:id:' \
                                        '--to[Restore to alternate path]:path:_directories' \
                                        "${global_opts[@]}"
                                    ;;
                                delete)
                                    _arguments \
                                        '1:id:' \
                                        "${global_opts[@]}"
                                    ;;
                                delete-all)
                                    _arguments \
                                        '--yes[Skip confirmation]' \
                                        "${global_opts[@]}"
                                    ;;
                            esac
                            ;;
                    esac
                    ;;
                update)
                    _arguments \
                        '--check-only[Only check for updates]' \
                        '--force[Force re-download]' \
                        '--server-url[Override update server URL]:url:' \
                        "${global_opts[@]}"
                    ;;
                config)
                    local -a cactions
                    cactions=(
                        'show:Display current configuration'
                        'set:Set a configuration key'
                        'reset:Reset configuration to defaults'
                    )
                    _arguments -C \
                        '1:action:->caction' \
                        '*::carg:->cargs' \
                        "${global_opts[@]}"
                    case "$state" in
                        caction)
                            _describe -t cactions 'config action' cactions
                            ;;
                        cargs)
                            case "${words[1]}" in
                                set)
                                    local -a config_keys
                                    config_keys=(
                                        'scan.max_file_size'
                                        'scan.threads'
                                        'scan.timeout'
                                        'scan.archives'
                                        'scan.archive_depth'
                                        'scan.heuristic_threshold'
                                        'update_server_url'
                                    )
                                    _arguments \
                                        '1:key:'"(${config_keys[*]})" \
                                        '2:value:' \
                                        "${global_opts[@]}"
                                    ;;
                            esac
                            ;;
                    esac
                    ;;
                info)
                    _arguments "${global_opts[@]}"
                    ;;
                import)
                    _arguments \
                        '1:blocklist file:_files' \
                        "${global_opts[@]}"
                    ;;
            esac
            ;;
    esac
}

_sd "$@"
