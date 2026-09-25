# Bash completion for PRX-SD (sd)
# Source this file or place in /etc/bash_completion.d/

_sd_completions() {
    local cur prev words cword
    _init_completion || return

    local commands="scan monitor quarantine update config info import"
    local quarantine_actions="list restore delete delete-all stats"
    local config_actions="show set reset"
    local global_opts="--log-level --data-dir --help --version"

    case "${cword}" in
        1)
            COMPREPLY=($(compgen -W "${commands} ${global_opts}" -- "${cur}"))
            return
            ;;
    esac

    local cmd="${words[1]}"

    case "${cmd}" in
        scan)
            case "${prev}" in
                --threads|-t)
                    COMPREPLY=($(compgen -W "1 2 4 8 16" -- "${cur}"))
                    return
                    ;;
                --exclude|-e)
                    return
                    ;;
                --log-level)
                    COMPREPLY=($(compgen -W "trace debug info warn error" -- "${cur}"))
                    return
                    ;;
                --data-dir)
                    _filedir -d
                    return
                    ;;
            esac
            if [[ "${cur}" == -* ]]; then
                COMPREPLY=($(compgen -W "--recursive -r --json --threads -t --auto-quarantine --exclude -e ${global_opts}" -- "${cur}"))
            else
                _filedir
            fi
            ;;
        monitor)
            case "${prev}" in
                --log-level)
                    COMPREPLY=($(compgen -W "trace debug info warn error" -- "${cur}"))
                    return
                    ;;
                --data-dir)
                    _filedir -d
                    return
                    ;;
            esac
            if [[ "${cur}" == -* ]]; then
                COMPREPLY=($(compgen -W "--block --daemon ${global_opts}" -- "${cur}"))
            else
                _filedir -d
            fi
            ;;
        quarantine)
            case "${cword}" in
                2)
                    COMPREPLY=($(compgen -W "${quarantine_actions}" -- "${cur}"))
                    ;;
                *)
                    local qcmd="${words[2]}"
                    case "${qcmd}" in
                        restore)
                            if [[ "${prev}" == "--to" ]]; then
                                _filedir -d
                            elif [[ "${cur}" == -* ]]; then
                                COMPREPLY=($(compgen -W "--to ${global_opts}" -- "${cur}"))
                            fi
                            ;;
                        delete-all)
                            if [[ "${cur}" == -* ]]; then
                                COMPREPLY=($(compgen -W "--yes ${global_opts}" -- "${cur}"))
                            fi
                            ;;
                    esac
                    ;;
            esac
            ;;
        update)
            case "${prev}" in
                --server-url)
                    return
                    ;;
                --log-level)
                    COMPREPLY=($(compgen -W "trace debug info warn error" -- "${cur}"))
                    return
                    ;;
                --data-dir)
                    _filedir -d
                    return
                    ;;
            esac
            if [[ "${cur}" == -* ]]; then
                COMPREPLY=($(compgen -W "--check-only --force --server-url ${global_opts}" -- "${cur}"))
            fi
            ;;
        config)
            case "${cword}" in
                2)
                    COMPREPLY=($(compgen -W "${config_actions}" -- "${cur}"))
                    ;;
                *)
                    local ccmd="${words[2]}"
                    case "${ccmd}" in
                        set)
                            if [ "${cword}" -eq 3 ]; then
                                COMPREPLY=($(compgen -W "scan.max_file_size scan.threads scan.timeout scan.archives scan.archive_depth scan.heuristic_threshold update_server_url" -- "${cur}"))
                            fi
                            ;;
                    esac
                    ;;
            esac
            ;;
        info)
            if [[ "${cur}" == -* ]]; then
                COMPREPLY=($(compgen -W "${global_opts}" -- "${cur}"))
            fi
            ;;
        import)
            case "${prev}" in
                --log-level)
                    COMPREPLY=($(compgen -W "trace debug info warn error" -- "${cur}"))
                    return
                    ;;
                --data-dir)
                    _filedir -d
                    return
                    ;;
            esac
            if [[ "${cur}" == -* ]]; then
                COMPREPLY=($(compgen -W "${global_opts}" -- "${cur}"))
            else
                _filedir
            fi
            ;;
    esac
}

complete -F _sd_completions sd
