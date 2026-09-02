#!/usr/bin/env python3
# Pack the Hyprland config tree into a flat blob the kernel unpacks into the rtfs overlay
# (rtUnpackAssetBlob in posix.d), exactly like xkb.blob / fonts.blob / zshfns.blob.
#
# Format: repeated [u32 LE pathLen][path bytes][u32 LE dataLen][data bytes].
#
# WHY A TREE AND NOT A SINGLE FILE: this is the user's real dots-hyprland config, which is
# LUA, not the classic hyprland.conf format -- hyprland.lua require()s hyprland/{env,execs,
# general,rules,colors,keybinds,variables}, hyprland/lib/init.lua, hyprland/services/*, and
# custom/*.  Hyprland 0.55 sets package.path from the config file's OWN directory:
#
#     configDir/?.lua ; configDir/?/init.lua      (src/config/lua/ConfigManager.cpp)
#
# so laying the tree down at /etc/hypr/ and pointing HYPRLAND_CONFIG at /etc/hypr/hyprland.lua
# makes every require() in it resolve, including the "hyprland/services/create_custom_config"
# form that uses slashes instead of dots.
#
# Shipping every custom/*.lua matters too: services/create_custom_config.lua runs
# create_if_not_exists() for each of them on hyprland.start, and that helper shells out via
# os.execute("mkdir -p ...").  With the files present the loop is a no-op, so the guest never
# depends on os.execute working at all.
import os, sys, struct

SRC  = sys.argv[1]                                   # system/hypr
OUT  = sys.argv[2]                                   # build/hyprcfg.blob
DEST = sys.argv[3] if len(sys.argv) > 3 else "home/user/.config/hypr"

# The 92KB fuzzel-emoji.sh list and the ai/ helpers are host-desktop tooling with no guest
# equivalent -- they would just burn rtfs nodes.  Editor backups likewise.
SKIP_NAMES = {"fuzzel-emoji.sh"}
SKIP_EXT   = (".bak", ".swp", "~")

entries = []
for root, dirs, files in os.walk(SRC):
    dirs[:] = sorted(d for d in dirs if d != "ai")
    for name in sorted(files):
        if name in SKIP_NAMES or name.endswith(SKIP_EXT):
            continue
        full = os.path.join(root, name)
        if os.path.islink(full) or not os.path.isfile(full):
            continue
        rel  = os.path.relpath(full, SRC)
        with open(full, "rb") as f:
            data = f.read()
        entries.append(("%s/%s" % (DEST, rel), data))

with open(OUT, "wb") as out:
    for path, data in entries:
        p = path.encode("utf-8")
        out.write(struct.pack("<I", len(p))); out.write(p)
        out.write(struct.pack("<I", len(data))); out.write(data)

total = sum(len(d) for _, d in entries)
print("packed %d files, %d bytes -> %s" % (len(entries), total, OUT))
for path, data in entries:
    print("    %-56s %7d" % (path, len(data)))
