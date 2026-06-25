#!/usr/bin/env python3
# Pack zsh's autoloadable function + completion tree into a flat blob the kernel
# unpacks into the rtfs overlay (rtUnpackAssetBlob in posix.d), exactly like
# xkb.blob / fonts.blob.
#
# Format: repeated [u32 LE pathLen][path bytes][u32 LE dataLen][data bytes].
#
# zsh autoloads functions by *basename* off $fpath, so we FLATTEN both source
# trees (Functions/** and Completion/**) into one directory at zsh's compiled-in
# default fpath dir (prefix=/system/shell/zsh):
#     system/shell/zsh/share/zsh/5.9/functions/<basename>
# compinit then finds compinit/compaudit/compdump + every _<cmd> completion there,
# and add-zsh-hook / promptinit / vcs_info / zle widgets come along for free.
#
# OS-specific completion subtrees (AIX/BSD/Cygwin/Darwin/Debian/Mandriva/openSUSE/
# Redhat/Solaris) are skipped — they're for other platforms and only burn rtfs nodes.
import os, sys, struct

SRC = sys.argv[1]               # deps/zsh/zsh-5.9  (has Functions/ and Completion/)
OUT = sys.argv[2]               # zshfns.blob
VER = sys.argv[3] if len(sys.argv) > 3 else "5.9"
DEST = "system/shell/zsh/share/zsh/%s/functions" % VER

TREES = ["Functions", "Completion"]
# completion subdirs for other operating systems — irrelevant to AnonymOS
SKIP_DIRS = {"AIX", "BSD", "Cygwin", "Darwin", "Debian", "Mandriva",
             "openSUSE", "Redhat", "Solaris", "CVS"}
# non-function files that live in the trees (build/meta, not autoloadable functions)
SKIP_NAMES = {".distfiles", ".cvsignore", "Makefile", "Makefile.in", ".gitignore"}
SKIP_EXT = (".mdd", ".pro", ".in", ".yo", ".html", ".o", ".syms")

def is_function_file(name):
    if name in SKIP_NAMES:
        return False
    if name.endswith(SKIP_EXT):
        return False
    return True

seen = {}
entries = []
for tree in TREES:
    root = os.path.join(SRC, tree)
    if not os.path.isdir(root):
        continue
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in sorted(dirs) if d not in SKIP_DIRS]
        for name in sorted(files):
            full = os.path.join(dirpath, name)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            if not is_function_file(name):
                continue
            if name in seen:                       # basename collision across trees
                continue
            seen[name] = full
            with open(full, "rb") as f:
                entries.append((name, f.read()))

with open(OUT, "wb") as out:
    for name, data in entries:
        p = ("%s/%s" % (DEST, name)).encode()
        out.write(struct.pack("<I", len(p)))
        out.write(p)
        out.write(struct.pack("<I", len(data)))
        out.write(data)

print("pack-zshfns: %d functions -> %s (%d bytes)" % (len(entries), OUT, os.path.getsize(OUT)))
