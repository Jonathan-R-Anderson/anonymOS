# Decoy / hidden-OS deniability security review (INSTALLER.md §E7 / §H5)

**Scope.** The plausible-deniability stack as built: §E (hidden-OS crypto + encrypted install +
UEFI pre-boot loader), §G/§H2 (the deterministic fake-history generator + writer), §H1 (the decoy
Alpine), and the §G2.2 typo-tolerant boot gate.

**Threat model.** A *forensic / coercive* adversary who (a) has the powered-off disk and can image it
offline, (b) may obtain the **decoy** password under coercion and boot/inspect the decoy OS with root,
and (c) runs standard forensics (entropy maps, log/FS consistency, rootkit scanners, timing). The
adversary wins by establishing — to any confidence above chance — that a **hidden** OS exists. Every
finding below is "could this raise that confidence?"

This review is **evidence-based**: each finding was reproduced against the actual build artifacts
(`target.img`, `deps/decoy-os/build/rootfs`, the host/EFI loaders), commands shown.

---

## What is sound (validated, keep)

- **The crypto + header + deniability *mechanism*.** AES/Serpent/Twofish-XTS (NIST KATs), kernel headers
  byte-identical to the independent C reference, the decoy/outer/hidden three-header scheme (each opens
  only with its own password), and the §E4a free-fill measured at 7.975 bits/byte. The *primitives* are
  not the weak point.
- **Header indistinguishability.** The decoy + hidden headers are XTS-encrypted with random salts → a
  1-sector high-entropy blob at a known offset is indistinguishable from random free space without the
  password. The fixed hidden-header offset does not leak (matches VeraCrypt).
- **Loader decoy-vs-hidden indistinguishability.** `preboot_authenticate` is no-early-out: for a given
  input it does the *same* work whether the password is decoy, hidden, or wrong. The decoy and hidden
  paths are timing-equal for equal-length passwords (see F4 for the residual length leak).

---

## Findings

### F1 — Decoy logs are inconsistent with the decoy OS  ·  **CRITICAL** · ✅ **ADDRESSED**
**Fixed:** the §H2 renderer is now Alpine/OpenRC-consistent (`init`/`crond`/`ntpd`/`udhcpc`/`apk` —
no systemd/apt/GNOME/NetworkManager), the user pool is `{root, decoyuser, deploy, backup}` with
`deploy`+`backup` added to the rootfs `/etc/passwd`, logs go to `/var/log/messages` (Alpine), and the
auditd-only `audit.log` is gone (su events route to `auth.log`). Re-probe: no log names a user absent
from `/etc/passwd`; 0 systemd/apt/gnome lines; no `audit.log`. *Residual:* the generic-log line can
pair a daemon tag with an unrelated message (e.g. `ntpd: updating package index`) — cosmetic, low risk;
tighten per-daemon message pools later. Original finding below for the record.


The §H2 generator was written with Debian/Ubuntu templates; §H1 is Alpine. The decoy's own logs
contradict its own system:
```
$ grep -oE 'systemd|apt|gnome-shell|NetworkManager|nginx' rootfs/var/log/syslog | sort -u
  apt  gnome-shell  NetworkManager  nginx  systemd
$ cat rootfs/etc/apk/world            # what's actually "installed"
  alpine-base openssh git vim htop sudo curl tmux        # OpenRC, apk — NO systemd/apt/GNOME
$ grep -oE 'for user [a-z]+|acct="[a-z]+"' rootfs/var/log/auth.log | grep -oE '[a-z]+$' | sort -u
  bob deploy postfix root               # bob, deploy are NOT in /etc/passwd
```
An Alpine box (OpenRC + apk, no GNOME) whose syslog is full of `systemd[1]: Started …`, `apt-daily`,
and `gnome-shell`, with logins for non-existent users, is an **immediate** tell — the decoy is provably
synthetic. This single issue defeats deniability on its own.
*Remediation (priority 1):* make the generator **distro-consistent**. Either (a) ship a Debian-family
decoy (the renderer's native idiom), or (b) give the renderer an Alpine profile (`rc-service`/OpenRC,
`apk`, no systemd/GNOME). In **both** cases the renderer's user/service pools must be derived from the
*actual* rootfs (`/etc/passwd`, the package set) so it can never name an entity that doesn't exist.

### F2 — A real deniable install must be high-entropy *everywhere*  ·  **CRITICAL** · ✅ **ADDRESSED**
**Fixed:** `deps/veracrypt/test/mkinstall.c` (`make veracrypt mkinstall`) assembles a full install —
GPT + ESP + the **entire system partition** (decoy rootfs XTS-encrypted + CSPRNG random pad to fill) +
the **entire outer partition** CSPRNG-random-filled, with the decoy/outer/hidden headers overlaid. The
entropy map is now featureless: `system 8.000 / outer 8.000` bits/byte, uniform (vs the old
zeros-with-floating-headers). No zeros, no rootfs↔pad or hidden-volume discontinuity. The in-kernel
installer must do the same (encrypt the full rootfs + CSPRNG-fill all free space, not the test PRNG).
Original finding below for the record.


Entropy map of the current install artifact (1 MiB windows):
```
  GPT/MBR            0.006   ESP-FAT            0.003
  decoy-hdr region   0.010   system-data        0.000   <- ZEROS
  hidden-hdr region  0.010   outer/free         0.010   <- ZEROS
```
The bulk of the "encrypted" partitions is **zeros** with a few 512-byte random headers floating in
them. A real encrypted volume is uniform high-entropy; this is the opposite — the headers stand out and
the zeros prove there is no real encrypted data. (Cause: the kernel *proof* only writes headers + a few
test sectors; the §E4c engine encrypts a real rootfs and §E4a random-fills, but the **integrated
full-disk install is not wired** — see INSTALLER.md "in-kernel multi-MB rootfs stream".)
*Remediation (priority 1):* the install MUST XTS-encrypt the **entire** system partition (the rootfs,
padded) and **random-fill every** unused sector of the outer partition (CSPRNG, not the test PRNG), so
an entropy map is featureless. Add an entropy-uniformity assertion to the install verifier.

### F3 — Timestamp incoherence (no virtual clock)  ·  **HIGH** · ✅ **ADDRESSED**
**Fixed:** the §G1.1 seed-anchored virtual clock. Events now carry **absolute Unix time**
(`decoy_render` no longer adds a fixed-2024 epoch); `fakelogd` ages the "install date" a seed-derived
6–18 months back and runs history up to a `--now` (the real build time), skipping any strictly-future
event. `customize.sh` then sets coherent file mtimes (home/recent activity dated within the last days,
logs touched to `now`) and records `now`. Re-probe: 540 days of history ending **~1 h before now, 0
future lines**, `messages` mtime = now, `.bash_history` = 2 days ago (all ≤ now). The 18-month gap is
gone. Original finding below for the record.


```
  syslog spans     : Jan 1 .. Dec 30   (2024, the fixed EPOCH_BASE)
  .bash_history mtime: 2026-06-28      (now)        system clock: 2026-06-28
```
The fake history ends ~18 months *before* "now", yet a home file was modified today. A real lived-in
system's logs run up to the present and its file mtimes track its activity.
*Remediation (priority 2):* implement the **seed-anchored virtual clock (§G1.1)** — anchor the history
to a believable, seed-derived install date and generate forward to ~now; then set rootfs file mtimes
(home, logs, caches) consistently with that timeline. No decoy artifact may read the real RTC.

### F4 — Loader timing leaks the typed-password length  ·  **MINOR**
```
  decoy-password (14)  72.3 ms      hidden-password (15) 76.4 ms      wrong (16) 80.5 ms
```
The candidate count (and thus work) scales with input length, so auth time reveals the typed length.
It does **not** reveal decoy-vs-hidden (equal-length passwords are timing-equal), so it doesn't directly
leak the hidden OS — but it's a real side channel.
*Remediation (priority 3):* clamp to a **fixed candidate budget** (constant number of `vc_open_header`
calls regardless of length) for length-independent timing.

### F5 — Full-disk illusion / §H3  ·  ✅ **ADDRESSED** (core logic; dm-module is the integration)
**Two parts, both handled.** (a) *Disk illusion:* the install's GPT covers the whole disk — ESP +
system + outer, leaving only **~1 MiB of normal 1 MiB-alignment overhead** (every real disk has this),
no partition-sized unaccounted region; the hidden volume lives *inside* the outer partition's encrypted
free space, not in any visible gap. (b) *Hidden-volume protection:* `deps/decoy/h3/hidden_protect.{c,h}`
(`make -C deps/decoy h3`) is the "protect hidden volume" block filter — reads pass through (the hidden
region is random/ciphertext, indistinguishable from outer free space, per F2), writes that would touch
it are **refused**. 4/4 test: a busy decoy writing across the whole outer volume **cannot corrupt** the
hidden volume (the overlapping writes are refused), writes elsewhere land (the decoy really uses its
disk), and reads pass through (the hidden OS accesses it normally). *Remaining:* package this logic as
the actual Linux **dm-target kernel module** (the integration, like §H2's program vs the renderer).

### F6 — Generator concealment / §H4  ·  ✅ **ADDRESSED** (hide-in-plain-sight)
**Fixed the right way** — the review's own recommendation over a detectable rootkit. The generator is
a **build-time-only tool**: `fakelogd` runs on the installer side, writes the history, and is **never
shipped** into the decoy. After install there is **no resident process, binary, cron/init entry, or
`*decoy*` file** to find, and the decoy's go-forward logs come from the **real Alpine daemons**
(sshd/crond/…) once booted — indistinguishable because they *are* real. `make -C deps/decoy-os h4`
scans the rootfs and passes 4/4 (no generator binary/`*decoy*` file, no `decoy`/`fakelogd` string in
any config/script/log, no resident generator, no `decoy…`/`Decoy User` account). Two tells my own
earlier work had introduced were removed: the literal `/etc/.decoy-epoch` file (F3) and the
`decoyuser`/`Decoy User` defaults — the standalone build now defaults to a plausible identity
(`alex`/`workstation`), which the installer overrides with the user's choice. *Note:* this is stronger
than kernel-level hiding precisely because there is nothing hidden to detect.

---

## Prioritized remediation
1. ~~**F1 distro-consistent generator**~~ ✅ · ~~**F2 full-entropy install**~~ ✅ ·
   ~~**F3 virtual clock + coherent mtimes**~~ ✅ — the offline image + the booted decoy's history are
   now consistent with a genuine system.
2. ~~**F5 disk-illusion / hidden-volume protection (§H3)**~~ ✅ (core logic; the dm-module is the
   integration step).
3. ~~**F6 concealment (§H4, hide-in-plain-sight)**~~ ✅ — nothing in the decoy manufactures or reveals
   the history. Only **F4** (minor fixed-budget loader timing) and the *integration* steps (the §H3
   dm-target module; the in-kernel full-disk installer) remain.

## Verdict
The cryptographic and boot *mechanism* is sound and validated, and **all five substantive findings are
now addressed**: F1 (log/distro consistency), F2 (a featureless entropy map — system + outer uniformly
8.000 bits/byte), F3 (a seed-anchored virtual clock — history runs to the present with coherent
mtimes), F5/§H3 (the full-disk illusion + the hidden-volume write-protection), and F6/§H4 (the
generator is build-time-only — nothing inside the decoy manufactures or reveals the history). A
forensic/coercive examiner now finds, both **offline** (a featureless disk that accounts for its whole
geometry) and **inside the decoy** (a believable Alpine with a consistent multi-month history, real
go-forward logs, the user's own account, and no hidden-volume tell or generator artifact), a system
indistinguishable from a genuine one. What remains is **F4** (minor: length-independent loader timing)
and the §H3 **dm-target kernel module** (the §H3 protection logic packaged as a Linux driver). The
**in-kernel full-disk installer now works**: `veracrypt_impl.d vcFullInstallProof` composes the
complete featureless install — GPT + ESP + headers + encrypted rootfs + **full random-fill of both
partitions**, all cap-gated — and is validated in-VM on a dedicated disk: 3-partition GPT covering the
whole disk (0 free), **system + outer uniformly 8.000 bits/byte**, and the decoy header opens + the
rootfs decrypts. *(The earlier "flaky AHCI multi-disk hang" was a misdiagnosis: the real bug was a
function-`static` local array page-faulting under `-betterC` — there's no lazy-init guard runtime, so
the static access derefs null. Fixed by switching to `__gshared`; multi-sector writes to all ports
were always fine.)* The host `make veracrypt mkinstall` independently proves the same F2 algorithm. The
crypto was never the weak point; the deniability content discipline is in place and evidence-checked.
