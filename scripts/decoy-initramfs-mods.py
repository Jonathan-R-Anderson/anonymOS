#!/usr/bin/env python3
"""Expand a list of module names into their full load-time dependency closure, from modules.dep.

The decoy's initramfs has to reach the machine's root device before there is any userspace, and
busybox insmod resolves no dependencies: whatever the initramfs does not carry simply never loads.
Hand-listing the modules is what put a decoy on real hardware with no NVMe driver and no SCSI/libata
stack (scsi_mod needs scsi_common, ahci needs libahci+libata, nvme needs nvme_core...), so it found
no block device and dropped to a shell.  This reads the kernel's own modules.dep and prints every
file the requested set transitively needs, deepest first, so insmod order is satisfiable.

  usage: decoy-initramfs-mods.py <modules-root>/<kver> name [name ...]
"""
import os, sys

if len(sys.argv) < 3:
    sys.exit(__doc__)
root, wanted = sys.argv[1], sys.argv[2:]

dep = {}            # "kernel/drivers/.../ahci.ko.gz" -> [dep paths]
by_name = {}        # "ahci" -> path
with open(os.path.join(root, "modules.dep")) as f:
    for line in f:
        if ":" not in line:
            continue
        path, _, deps = line.partition(":")
        path = path.strip()
        dep[path] = deps.split()
        name = os.path.basename(path)
        for suffix in (".ko.gz", ".ko.xz", ".ko.zst", ".ko"):
            if name.endswith(suffix):
                name = name[: -len(suffix)]
                break
        by_name.setdefault(name, path)
        by_name.setdefault(name.replace("_", "-"), path)
        by_name.setdefault(name.replace("-", "_"), path)

order, seen, missing = [], set(), []


def add(path):
    if path in seen:
        return
    seen.add(path)
    for d in dep.get(path, []):
        add(d)                      # dependencies first: insmod can then take the list in order
    order.append(path)


for name in wanted:
    p = by_name.get(name) or by_name.get(name.replace("-", "_")) or by_name.get(name.replace("_", "-"))
    if not p:
        missing.append(name)        # built into this kernel, or renamed upstream
        continue
    add(p)

for p in order:
    print(os.path.join(root, p))
if missing:
    print("# not a module in this kernel: " + " ".join(missing), file=sys.stderr)
