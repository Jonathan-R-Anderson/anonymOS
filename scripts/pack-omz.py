#!/usr/bin/env python3
# Pack Oh My Zsh (a functional subset) + Powerlevel9k + the Z9 plugins + the AnonymOS OMZ profile
# into a blob the kernel unpacks into the rtfs (rtUnpackAssetBlob).  Everything lands under
# /system/shell/zsh/omz/  ($ZSH), with $ZSH_CUSTOM = $ZSH/custom.
# Format: repeated [u32 LE pathLen][path][u32 LE dataLen][data].
import os, sys, re, tarfile, struct, glob

OUT  = sys.argv[1]
SRC  = sys.argv[2] if len(sys.argv) > 2 else "deps/zsh-plugins"
ROOT = "system/shell/zsh/omz"

entries = []
def add(path, data): entries.append((path, data))

def from_tar(tarball, want, dest_prefix):
    with tarfile.open(tarball) as t:
        for m in t.getmembers():
            if not m.isfile():
                continue
            rel = m.name.split('/', 1)[1] if '/' in m.name else m.name
            if rel and want(rel):
                add("%s/%s" % (dest_prefix, rel), t.extractfile(m).read())

def one(pattern):
    g = sorted(glob.glob(os.path.join(SRC, pattern)))
    return g[0] if g else None

# 1) Oh My Zsh — only the framework core + lib + the git plugin (the 1485-file repo is mostly
#    plugins/themes we don't ship).
def want_omz(rel):
    return (rel == "oh-my-zsh.sh"
            or rel == "tools/check_for_upgrade.sh"          # oh-my-zsh.sh sources it unconditionally
            or (rel.startswith("lib/") and rel.endswith(".zsh"))
            or (rel.startswith("plugins/git/") and rel.endswith(".zsh")))
from_tar(one("ohmyzsh*.tar.gz"), want_omz, ROOT)

# 2) Powerlevel9k -> $ZSH_CUSTOM/themes/powerlevel9k/
def want_p9k(rel):
    if re.search(r'(^|/)(docker|debug|test|\.github)/', rel):
        return False
    return rel.endswith(".zsh-theme") or (rel.startswith("functions/") and rel.endswith(".zsh"))
from_tar(one("powerlevel9k*.tar.gz"), want_p9k, ROOT + "/custom/themes/powerlevel9k")

# 3) the Z9 plugins, again, under $ZSH_CUSTOM/plugins/<name>/ so OMZ's plugins=() finds them
def want_plug(rel):
    if re.search(r'(^|/)(\.git|tests?|test-data|docs?|images)(/|$)', rel, re.I):
        return False
    return rel.endswith(".zsh") or rel.rsplit('/', 1)[-1] in (".version", ".revision-hash")
for pat in ("zsh-syntax-highlighting*.tar.gz", "zsh-autosuggestions*.tar.gz"):
    tb = one(pat)
    if tb:
        name = re.sub(r'-v?[0-9].*$', '', os.path.basename(tb)[:-len(".tar.gz")])
        from_tar(tb, want_plug, "%s/custom/plugins/%s" % (ROOT, name))

# 4) the AnonymOS OMZ profile (zshrc.omz + any segment files) -> omz/anonymos/
d = os.path.join(SRC, "anonymos-omz")
if os.path.isdir(d):
    for dp, _dirs, fs in os.walk(d):
        for f in sorted(fs):
            full = os.path.join(dp, f)
            with open(full, 'rb') as fh:
                add("%s/anonymos/%s" % (ROOT, os.path.relpath(full, d)), fh.read())

with open(OUT, 'wb') as out:
    for p, data in entries:
        pb = p.encode()
        out.write(struct.pack('<I', len(pb))); out.write(pb)
        out.write(struct.pack('<I', len(data))); out.write(data)
print("pack-omz: %d files -> %s (%d bytes)" % (len(entries), OUT, os.path.getsize(OUT)))
