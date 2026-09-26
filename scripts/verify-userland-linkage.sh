#!/usr/bin/env bash
# verify-userland-linkage.sh — turn the dynamic-userland boot-bricks the adversarial review found
# into BUILD-TIME failures (all host-runnable; the alternative is discovering them only at boot).
#
# Three checks over the staged ISO tree (cd/) + build/:
#   1. STATIC-ASSERT: binaries that MUST stay static (lkl-boot, the freestanding raw-syscall tools,
#      the kernel-spawned bring-up launchers) must have NO PT_INTERP. A stray -static removal that
#      made one dynamic would silently ABI-skew or add a loader dependency to early bring-up.
#   2. NEEDED-CLOSURE: every dynamic ELF staged in cd/ must have each DT_NEEDED basename present as
#      a cd/<basename> boot module (the kernel resolves DT_NEEDED by exact basename; a miss is a
#      silent boot brick — ld.so fails the lookup). ld-musl-x86_64.so.1 counts as satisfying libc.so
#      only if actually staged.
#   3. DUP-BASENAME: no two cd/ modules share a basename (findBootModuleLib has no version/soname
#      disambiguation and returns the first match — a versioned duplicate shadows the real SONAME).
#
# Exit non-zero on any violation. Intended to run at the end of stage-iso-tree and in CI.
set -uo pipefail

CD="${1:-cd}"
BUILD="${2:-build}"
fail=0
err(){ echo "verify-linkage: ERROR: $*" >&2; fail=1; }
note(){ echo "verify-linkage: $*"; }

have_interp(){ readelf -l "$1" 2>/dev/null | grep -q INTERP; }
is_elf(){ [ -f "$1" ] && [ "$(head -c4 "$1" 2>/dev/null | tr -d '\0')" = $'\x7fELF' ] 2>/dev/null || { [ -f "$1" ] && head -c4 "$1" 2>/dev/null | grep -q ELF; }; }
needed(){ readelf -d "$1" 2>/dev/null | grep -oE 'Shared library: \[[^]]*\]' | sed -E 's/.*\[([^]]*)\].*/\1/'; }
soname(){ readelf -d "$1" 2>/dev/null | grep -oE 'Library soname: \[[^]]*\]' | sed -E 's/.*\[([^]]*)\].*/\1/'; }

# ── 1. must-stay-static ──────────────────────────────────────────────────────────────────────
# Names as staged/built. lkl-boot-musl is build/; the rest are cd/ boot modules (staged basenames).
MUST_STATIC_BUILD="lkl-boot-musl"
MUST_STATIC_CD="hos-netlaunch hos-dbus-launch hos-nm-launch hos-wpa-launch hos-sshd-launch \
hos-udhcpc-launch hos-udhcpc-script hos-wl-trace hos-wifiterm idle hos-attest-deploy \
test-drm drm-gpu-test compositor hello-gui wl-probe store-app display-info -sh"
for b in $MUST_STATIC_BUILD; do
  f="$BUILD/$b"; [ -f "$f" ] || continue
  if have_interp "$f"; then err "$f MUST be static but has PT_INTERP (accidental -static removal?)"; else note "static ok: $f"; fi
done
for b in $MUST_STATIC_CD; do
  f="$CD/$b"; [ -f "$f" ] || continue
  if have_interp "$f"; then err "$f MUST be static but has PT_INTERP"; else note "static ok: $f"; fi
done

# ── 2. NEEDED-closure over every dynamic ELF in cd/ ────────────────────────────────────────────
# Build the set of basenames present in cd/ (flat — boot modules live at cd/<name>).
present=" "
for f in "$CD"/*; do
  [ -f "$f" ] || continue
  present+="$(basename "$f") "
done
dyncount=0
for f in "$CD"/*; do
  [ -f "$f" ] || continue
  head -c4 "$f" 2>/dev/null | grep -q ELF || continue
  have_interp "$f" || continue          # dynamic ELF (has an interpreter)
  dyncount=$((dyncount+1))
  for n in $(needed "$f"); do
    # libc.so is provided by the staged ld-musl-x86_64.so.1
    if [ "$n" = "libc.so" ] || [ "$n" = "libc.musl-x86_64.so.1" ]; then
      case "$present" in *" ld-musl-x86_64.so.1 "*) : ;; *) err "$(basename "$f") NEEDS $n but ld-musl-x86_64.so.1 is not staged in $CD/";; esac
      continue
    fi
    case "$present" in
      *" $n "*) : ;;
      *) err "$(basename "$f") NEEDS $n — no $CD/$n boot module staged (silent boot brick)";;
    esac
  done
done
note "checked NEEDED-closure over $dyncount dynamic module(s) in $CD/"

# ── 3. duplicate basenames in cd/ ──────────────────────────────────────────────────────────────
dups="$(for f in "$CD"/*; do [ -f "$f" ] && basename "$f"; done | sort | uniq -d)"
if [ -n "$dups" ]; then
  for d in $dups; do err "duplicate cd/ module basename '$d' (findBootModuleLib returns the first match — versioned dup shadows the real SONAME)"; done
fi

# ── limine.conf module_path <-> file consistency (a guard the grep-guard at Makefile:1241 misses) ─
if [ -f "$CD/boot/limine/limine.conf" ]; then
  while read -r m; do
    base="${m##*/}"
    [ -f "$CD/$base" ] || err "limine.conf lists module_path .../$base but $CD/$base does not exist"
  done < <(grep -oE 'module_path: boot\(\):/[^ ]+' "$CD/boot/limine/limine.conf" | sed -E 's#.*/##')
  # ld-musl must actually exist (not just be referenced) — skeptic #1's PID1-brick guard
  if grep -q 'boot():/ld-musl-x86_64.so.1' "$CD/boot/limine/limine.conf" && [ ! -f "$CD/ld-musl-x86_64.so.1" ]; then
    err "limine.conf references ld-musl-x86_64.so.1 but $CD/ld-musl-x86_64.so.1 is missing — dynamic PID1 would triple-fault"
  fi
fi

if [ "$fail" -ne 0 ]; then
  echo "verify-linkage: FAILED — fix the above before shipping the ISO (these are boot-bricks)." >&2
  exit 1
fi
note "OK — static-required binaries are static, NEEDED-closure holds, no duplicate basenames."
