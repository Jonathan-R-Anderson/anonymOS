#!/usr/bin/env python3
# Pack a tree of guest data files into a flat blob the kernel unpacks into the
# rtfs overlay (rtUnpackAssets in posix.d).  Mirrors pack-xkb.py's format.
#
# Format: repeated [u32 LE pathLen][path bytes][u32 LE dataLen][data bytes].
# Paths are relative to the overlay root.  Files under SRC are placed at
# <PREFIX>/<relpath>, e.g. build/assets/hypr/wall0.png -> usr/share/hypr/wall0.png
# so Hyprland's resolveAssetPath ("/usr/share" + "/hypr/wall0.png") finds it.
import os, sys, struct

SRC = sys.argv[1]                       # e.g. build/assets
OUT = sys.argv[2]                       # e.g. build/assets.blob
PREFIX = sys.argv[3] if len(sys.argv) > 3 else "usr/share"

n = 0
with open(OUT, "wb") as out:
    for dirpath, _dirs, files in os.walk(SRC):
        for name in sorted(files):
            full = os.path.join(dirpath, name)
            if not os.path.isfile(full) or os.path.islink(full):
                continue
            rel = os.path.relpath(full, SRC)
            with open(full, "rb") as f:
                data = f.read()
            p = (PREFIX + "/" + rel.replace(os.sep, "/")).encode()
            out.write(struct.pack("<I", len(p)))
            out.write(p)
            out.write(struct.pack("<I", len(data)))
            out.write(data)
            n += 1

print(f"pack-assets: {n} files -> {OUT} ({os.path.getsize(OUT)} bytes)")
