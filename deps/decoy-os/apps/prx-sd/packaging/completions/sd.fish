# Fish completion for PRX-SD (sd)
# Place in ~/.config/fish/completions/sd.fish

# Disable file completions by default
complete -c sd -f

# Global options
complete -c sd -l log-level -d 'Logging level' -xa 'trace debug info warn error'
complete -c sd -l data-dir -d 'Base data directory' -rFa '(__fish_complete_directories)'
complete -c sd -l help -d 'Show help'
complete -c sd -l version -d 'Show version'

# Subcommands
complete -c sd -n __fish_use_subcommand -a scan -d 'Scan a file or directory for threats'
complete -c sd -n __fish_use_subcommand -a monitor -d 'Start real-time file system monitoring'
complete -c sd -n __fish_use_subcommand -a quarantine -d 'Manage quarantined files'
complete -c sd -n __fish_use_subcommand -a update -d 'Check for and apply signature updates'
complete -c sd -n __fish_use_subcommand -a config -d 'Manage engine configuration'
complete -c sd -n __fish_use_subcommand -a info -d 'Display engine info'
complete -c sd -n __fish_use_subcommand -a import -d 'Import hash signatures from blocklist'

# scan
complete -c sd -n '__fish_seen_subcommand_from scan' -rF -d 'Path to scan'
complete -c sd -n '__fish_seen_subcommand_from scan' -s r -l recursive -d 'Recurse into subdirectories'
complete -c sd -n '__fish_seen_subcommand_from scan' -l json -d 'Output results as JSON'
complete -c sd -n '__fish_seen_subcommand_from scan' -s t -l threads -d 'Number of scanner threads' -x
complete -c sd -n '__fish_seen_subcommand_from scan' -l auto-quarantine -d 'Automatically quarantine threats'
complete -c sd -n '__fish_seen_subcommand_from scan' -s e -l exclude -d 'Glob patterns to exclude' -x

# monitor
complete -c sd -n '__fish_seen_subcommand_from monitor' -rFa '(__fish_complete_directories)' -d 'Paths to monitor'
complete -c sd -n '__fish_seen_subcommand_from monitor' -l block -d 'Block malicious files before access'
complete -c sd -n '__fish_seen_subcommand_from monitor' -l daemon -d 'Run as background daemon'

# quarantine subcommands
complete -c sd -n '__fish_seen_subcommand_from quarantine; and not __fish_seen_subcommand_from list restore delete delete-all stats' -a list -d 'List quarantined files'
complete -c sd -n '__fish_seen_subcommand_from quarantine; and not __fish_seen_subcommand_from list restore delete delete-all stats' -a restore -d 'Restore a quarantined file'
complete -c sd -n '__fish_seen_subcommand_from quarantine; and not __fish_seen_subcommand_from list restore delete delete-all stats' -a delete -d 'Delete a quarantined file'
complete -c sd -n '__fish_seen_subcommand_from quarantine; and not __fish_seen_subcommand_from list restore delete delete-all stats' -a delete-all -d 'Delete all quarantined files'
complete -c sd -n '__fish_seen_subcommand_from quarantine; and not __fish_seen_subcommand_from list restore delete delete-all stats' -a stats -d 'Show quarantine statistics'
complete -c sd -n '__fish_seen_subcommand_from quarantine; and __fish_seen_subcommand_from restore' -l to -d 'Restore to alternate path' -rFa '(__fish_complete_directories)'
complete -c sd -n '__fish_seen_subcommand_from quarantine; and __fish_seen_subcommand_from delete-all' -l yes -d 'Skip confirmation'

# update
complete -c sd -n '__fish_seen_subcommand_from update' -l check-only -d 'Only check for updates'
complete -c sd -n '__fish_seen_subcommand_from update' -l force -d 'Force re-download'
complete -c sd -n '__fish_seen_subcommand_from update' -l server-url -d 'Override update server URL' -x

# config subcommands
complete -c sd -n '__fish_seen_subcommand_from config; and not __fish_seen_subcommand_from show set reset' -a show -d 'Display current configuration'
complete -c sd -n '__fish_seen_subcommand_from config; and not __fish_seen_subcommand_from show set reset' -a set -d 'Set a configuration key'
complete -c sd -n '__fish_seen_subcommand_from config; and not __fish_seen_subcommand_from show set reset' -a reset -d 'Reset configuration to defaults'
complete -c sd -n '__fish_seen_subcommand_from config; and __fish_seen_subcommand_from set' -xa 'scan.max_file_size scan.threads scan.timeout scan.archives scan.archive_depth scan.heuristic_threshold update_server_url'

# import
complete -c sd -n '__fish_seen_subcommand_from import' -rF -d 'Blocklist file'
