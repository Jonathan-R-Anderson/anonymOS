#!/usr/bin/env python3
# Pack the vendored zsh plugins (+ the native anonymos plugin) into a flat blob the kernel
# unpacks into the rtfs overlay (rtUnpackAssetBlob in posix.d), same format as xkb.blob /
# fonts.blob / zshfns.blob:  repeated [u32 LE pathLen][path][u32 LE dataLen][data].
#
# Unlike the FLATTENED Z8 function tree, plugins keep their directory structure (a plugin
# sources its sibling files by relative path), staged under:
#     system/shell/zsh/plugins/<plugin>/<relpath>
# Only runtime files ship — test suites / docs / build metadata are skipped (they're most of
# zsh-syntax-highlighting's tree and only burn rtfs nodes).
import os, sys, re, tarfile, struct, glob

OUT = sys.argv[1]                                   # zshplugins.blob
SRC = sys.argv[2] if len(sys.argv) > 2 else "deps/zsh-plugins"
DEST = "system/shell/zsh/plugins"

SKIP_RE    = re.compile(r'(^|/)(\.git|tests?|test-data|docs?|images)(/|$)', re.I)
KEEP_EXT   = ('.zsh',)
KEEP_NAMES = ('.version', '.revision-hash')          # zsh-syntax-highlighting reads these at load

def want(rel):
    if SKIP_RE.search(rel):
        return False
    return rel.endswith(KEEP_EXT) or rel.rsplit('/', 1)[-1] in KEEP_NAMES

entries = []                                        # (destpath, bytes)

# 1) vendored tarballs:  <name>-<ver>.tar.gz  ->  plugin <name>
for tb in sorted(glob.glob(os.path.join(SRC, "*.tar.gz"))):
    base = os.path.basename(tb)[:-len(".tar.gz")]
    name = re.sub(r'-v?[0-9].*$', '', base)         # strip the trailing -<version>
    with tarfile.open(tb) as t:
        for m in t.getmembers():
            if not m.isfile():
                continue
            rel = m.name.split('/', 1)[1] if '/' in m.name else m.name   # drop <topdir>/
            if not rel or not want(rel):
                continue
            entries.append(("%s/%s/%s" % (DEST, name, rel), t.extractfile(m).read()))

# 2) native plugin dirs (no tarball), e.g. deps/zsh-plugins/anonymos/
for d in sorted(glob.glob(os.path.join(SRC, "*/"))):
    name = os.path.basename(d.rstrip('/'))
    for dirpath, _dirs, files in os.walk(d):
        for f in sorted(files):
            full = os.path.join(dirpath, f)
            rel = os.path.relpath(full, d)
            if not want(rel):
                continue
            with open(full, 'rb') as fh:
                entries.append(("%s/%s/%s" % (DEST, name, rel), fh.read()))

with open(OUT, 'wb') as out:
    for path, data in entries:
        p = path.encode()
        out.write(struct.pack('<I', len(p))); out.write(p)
        out.write(struct.pack('<I', len(data))); out.write(data)

print("pack-zshplugins: %d files -> %s (%d bytes)" % (len(entries), OUT, os.path.getsize(OUT)))
for e in entries:
    print("  ", e[0])
