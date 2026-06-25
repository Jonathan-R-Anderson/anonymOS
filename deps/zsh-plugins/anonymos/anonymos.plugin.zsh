# anonymos.plugin.zsh — AnonymOS object-model plugin (Z9.2 / Deliverable 10).
#
# The /hos-sh object commands reborn as a zsh plugin.  On the NATIVE shell, obj/id/ns/svc/sys are
# the real object-ABI builtins (defined in /etc/zshrc's native block, gated by the N0 capability).
# This plugin surfaces the same kernel object model through its filesystem views — the /objects
# store and /config/*.json — which are readable in BOTH flavours, so the object commands and their
# completion (Z8.2 _hos) work everywhere.  Loaded by the Z9 plugin loader.

# /etc/zshrc defines objects/services/sysinfo/caps as simple cat-aliases.  This plugin supersedes
# them with functions, so drop the aliases FIRST — and at top level, not inside a block: zsh parses
# a whole `if … fi` as one unit (expanding the alias before any inner `unalias` could run), so the
# unalias and the function definitions must be separate top-level statements.
unalias objects services sysinfo caps 2>/dev/null

# --- object-model views (both flavours: the kernel exposes these paths regardless of shell) ----
objects()    { cat /objects/store          2>/dev/null || print -ru2 'objects: /objects/store unavailable' }
processes()  { cat /objects/processes      2>/dev/null || print -ru2 'processes: /objects/processes unavailable' }
apps()       { cat /objects/apps           2>/dev/null || print -ru2 'apps: /objects/apps unavailable' }
identities() { cat /config/identities.json 2>/dev/null || print -ru2 'identities: /config/identities.json unavailable' }
services()   { cat /config/services.json   2>/dev/null || print -ru2 'services: /config/services.json unavailable' }
sysinfo()    { cat /config/system.json     2>/dev/null || print -ru2 'sysinfo: /config/system.json unavailable' }
alias caps='identities'

# --- the Z4c verbs as commands — Linux only (native already has obj/svc/sys via /hos-sh) -------
if [[ $EPIN_SHELL != native ]]; then
  obj() { objects }
  svc() { services }
  sys() { sysinfo }
  hos() {
    case $1 in
      obj|objects)    objects ;;
      id|identities)  identities ;;
      svc|services)   services ;;
      sys|system)     sysinfo ;;
      ps|processes)   processes ;;
      apps)           apps ;;
      whoami)         print -r -- "${EPIN_USER:-${USER:-user}}@${EPIN_DOMAIN:-linux}" ;;
      ''|-h|--help|help) print -r -- 'hos {obj|id|svc|sys|ps|apps|whoami} — query the kernel object model' ;;
      *)              print -ru2 "hos: unknown verb '$1' (try: obj id svc sys ps apps whoami)"; return 2 ;;
    esac
  }
fi

# Wire the AnonymOS object-model completion (Z8.2 _hos covers hos/obj/id/ns/svc/sys).
(( $+functions[compdef] )) && compdef _hos hos obj svc sys 2>/dev/null
