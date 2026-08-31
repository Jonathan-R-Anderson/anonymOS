#!/usr/bin/env python3
# Pack an xkeyboard-config tree into a flat blob the kernel unpacks into the
# rtfs overlay (rtUnpackXkb in posix.d).
#
# Format: repeated [u32 LE pathLen][path bytes][u32 LE dataLen][data bytes].
# Paths are relative to the overlay root, prefixed with usr/share/X11/xkb so the
# kernel recreates the directory tree XKB_CONFIG_ROOT points at.
#
# geometry/ is skipped: it's only used for graphical keyboard *layout* drawing,
# not keymap compilation, and dropping it saves rtfs nodes.
import os, sys, struct

SRC = sys.argv[1]               # .../share/X11/xkb
OUT = sys.argv[2]               # xkb.blob
PREFIX = "usr/share/X11/xkb"
SKIP_TOP = {"geometry"}

n = 0
with open(OUT, "wb") as out:
    for dirpath, _dirs, files in os.walk(SRC):
        for name in sorted(files):
            full = os.path.join(dirpath, name)
            if not os.path.isfile(full) or os.path.islink(full):
                continue
            rel = os.path.relpath(full, SRC)
            top = rel.split(os.sep, 1)[0]
            if top in SKIP_TOP:
                continue
            with open(full, "rb") as f:
                data = f.read()
            p = (PREFIX + "/" + rel.replace(os.sep, "/")).encode()
            out.write(struct.pack("<I", len(p)))
            out.write(p)
            out.write(struct.pack("<I", len(data)))
            out.write(data)
            n += 1

print(f"pack-xkb: {n} files -> {OUT} ({os.path.getsize(OUT)} bytes)")
