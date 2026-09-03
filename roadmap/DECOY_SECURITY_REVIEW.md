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

### F4 — Loader timing leaks the typed-password length  ·  **MINOR**
```
  decoy-password (14)  72.3 ms      hidden-password (15) 76.4 ms      wrong (16) 80.5 ms
```
The candidate count (and thus work) scales with input length, so auth time reveals the typed length.
It does **not** reveal decoy-vs-hidden (equal-length passwords are timing-equal), so it doesn't directly
leak the hidden OS — but it's a real side channel.
*Remediation (priority 3):* clamp to a **fixed candidate budget** (constant number of `vc_open_header`
calls regardless of length) for length-independent timing.

## Prioritized remediation
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
