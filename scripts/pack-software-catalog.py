#!/usr/bin/env python3
"""Aggregate the package indexes of the major Linux distributions into ONE catalog blob.

The Software Center (src/util/wl-software.c) is a browser over this file: every package it
lists is a real package that really exists in that distribution's repository today, with its
real version, size, licence and summary -- not a hand-written demo list.  The blob is built
here, on the build host, because the guest has no package manager of its own and (on install
media) no network; shipping the index means the catalog is browsable offline.

Sources (all fetched from the distributions' own mirrors):
  apk     Alpine main + community      -- musl, the SAME libc this OS's Linux personality runs,
                                          so these are the packages that can actually be
                                          installed into a domain here (installable=1)
  deb     Debian stable, Ubuntu LTS    -- glibc; browsable, install needs a glibc runtime
  rpm     Fedora, openSUSE Tumbleweed  -- glibc
  pacman  Arch core + extra            -- glibc
  flatpak Flathub                      -- sandboxed bundles

Usage:
  scripts/pack-software-catalog.py build/software-catalog.bin [--limit N] [--offline]
  --limit N   cap non-Alpine repos at N packages each (default 8000); Alpine is always complete
  --offline   do not hit the network; reuse build/software-cache/ (fails if it is empty)

Output: the binary described in FORMAT below, which src/util/wl-software.c mmaps and reads
directly (no allocation, no parsing pass).  Little-endian throughout; every string is NUL-
terminated ASCII in one pool (the guest's FreeType path renders >= 0x7f as '?', so the text is
folded to ASCII here, once, rather than in the client).

FORMAT
  header  0  magic "HOSSOFT1"
          8  u32 version (1)
         12  u32 repoCount
         16  u32 pkgCount
         20  u32 repoOff        repo records
         24  u32 pkgOff         package records
         28  u32 strOff, 32 u32 strLen
         36  u64 builtEpoch
         44  u32 categoryCount
         48  u32 categoryOff    u32 nameOff per category
  repo   (40 B) u32 name, u32 distro, u32 pkgmgr, u32 baseUrl, u32 arch,
                u32 totalPkgs, u32 includedPkgs, u8 installable, u8 pad[3], u32 reserved,
                u32 accent (0xRRGGBB, the badge colour)
  pkg    (28 B) u32 name, u32 ver, u32 desc, u32 license,
                u32 sizeKb (download), u32 instKb (installed), u16 repoIdx, u16 category
"""
import gzip, io, os, re, struct, sys, tarfile, time, urllib.request, xml.etree.ElementTree as ET

CATEGORIES = ["All", "Accessories", "Development", "Games", "Graphics", "Internet",
              "Multimedia", "Office", "Science", "Security", "System", "Fonts",
              "Libraries", "Other"]
CAT = {c: i for i, c in enumerate(CATEGORIES)}

UA = {"User-Agent": "anonymos-software-catalog/1 (+https://github.com/anonymos)"}
CACHE = "build/software-cache"


def fetch(url, offline=False):
    """Download `url` into the build cache (and reuse it next time)."""
    os.makedirs(CACHE, exist_ok=True)
    key = re.sub(r"[^A-Za-z0-9._-]", "_", url)[-180:]
    path = os.path.join(CACHE, key)
    if os.path.exists(path) and os.path.getsize(path) > 0:
        return open(path, "rb").read()
    if offline:
        raise RuntimeError("offline and not cached: " + url)
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read()
    with open(path, "wb") as f:
        f.write(data)
    return data


def decompress_any(blob):
    """Repository metadata is gzip (Fedora/Debian), zstd (openSUSE) or xz depending on the
    distribution and the year.  Dispatch on the magic; zstd goes through the CLI because the
    stdlib had no zstd module before 3.14."""
    if blob[:2] == b"\x1f\x8b":
        return gzip.decompress(blob)
    if blob[:4] == b"\x28\xb5\x2f\xfd":
        import shutil, subprocess
        exe = shutil.which("zstd") or shutil.which("unzstd")
        if not exe:
            raise RuntimeError("zstd-compressed metadata but no zstd binary on the build host")
        return subprocess.run([exe, "-dc"], input=blob, stdout=subprocess.PIPE, check=True).stdout
    if blob[:6] == b"\xfd7zXZ\x00":
        import lzma
        return lzma.decompress(blob)
    return blob


def ascii_fold(s, cap=None):
    out = []
    for ch in s:
        o = ord(ch)
        if 0x20 <= o < 0x7F:
            out.append(ch)
        elif ch in "’‘":
            out.append("'")
        elif ch in "“”":
            out.append('"')
        elif ch in "–—":
            out.append("-")
        elif o > 0x7F:
            out.append("?")
    s = "".join(out).strip()
    s = re.sub(r"\s+", " ", s)
    if cap and len(s) > cap:
        s = s[: cap - 3].rstrip() + "..."
    return s


# ── per-format index parsers ──────────────────────────────────────────────────────────────
def parse_apk(blob):
    """Alpine APKINDEX.tar.gz -> the APKINDEX member, blocks of 'K:value' lines."""
    tf = tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz")
    m = tf.extractfile("APKINDEX")
    text = m.read().decode("utf-8", "replace")
    for block in text.split("\n\n"):
        f = {}
        for line in block.splitlines():
            if len(line) > 2 and line[1] == ":":
                f[line[0]] = line[2:]
        if "P" not in f:
            continue
        yield {
            "name": f.get("P", ""), "ver": f.get("V", ""), "desc": f.get("T", ""),
            "license": f.get("L", ""), "size": int(f.get("S", "0") or 0),
            "inst": int(f.get("I", "0") or 0), "section": "",
        }


def parse_deb(blob):
    """Debian/Ubuntu Packages.gz -- RFC822 stanzas."""
    text = gzip.decompress(blob).decode("utf-8", "replace")
    for block in text.split("\n\n"):
        f, key = {}, None
        for line in block.splitlines():
            if line[:1] in (" ", "\t"):
                continue                       # continuation (long description body)
            if ":" in line:
                key, _, val = line.partition(":")
                f.setdefault(key.strip(), val.strip())
        if "Package" not in f:
            continue
        yield {
            "name": f.get("Package", ""), "ver": f.get("Version", ""),
            "desc": f.get("Description", ""), "license": "",
            "size": int(f.get("Size", "0") or 0),
            "inst": int(f.get("Installed-Size", "0") or 0) * 1024,
            "section": f.get("Section", ""),
        }


def parse_rpm(repomd_url, offline):
    """Fedora/openSUSE: repomd.xml -> primary.xml.gz -> <package> elements."""
    md = fetch(repomd_url, offline)
    root = ET.fromstring(md)
    ns = {"r": "http://linux.duke.edu/metadata/repo"}
    href = None
    for d in root.findall("r:data", ns):
        if d.get("type") == "primary":
            href = d.find("r:location", ns).get("href")
    if not href:
        raise RuntimeError("no primary.xml in " + repomd_url)
    base = repomd_url.rsplit("/repodata/", 1)[0]
    blob = fetch(base + "/" + href, offline)
    text = decompress_any(blob)
    P = "{http://linux.duke.edu/metadata/common}"
    R = "{http://linux.duke.edu/metadata/rpm}"
    for _, el in ET.iterparse(io.BytesIO(text), events=("end",)):
        if el.tag != P + "package":
            continue
        name = (el.findtext(P + "name") or "")
        v = el.find(P + "version")
        ver = (v.get("ver", "") + "-" + v.get("rel", "")) if v is not None else ""
        sz = el.find(P + "size")
        fmt = el.find(P + "format")
        lic = fmt.findtext(R + "license") if fmt is not None else ""
        grp = fmt.findtext(R + "group") if fmt is not None else ""
        yield {
            "name": name, "ver": ver, "desc": el.findtext(P + "summary") or "",
            "license": lic or "", "size": int(sz.get("package", 0)) if sz is not None else 0,
            "inst": int(sz.get("installed", 0)) if sz is not None else 0,
            "section": grp or "",
        }
        el.clear()


def parse_pacman(blob):
    """Arch core.db / extra.db: a tar.gz of <pkg>/desc files with %FIELD% sections."""
    tf = tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz")
    for m in tf:
        if not m.name.endswith("/desc"):
            continue
        text = tf.extractfile(m).read().decode("utf-8", "replace")
        f, key = {}, None
        for line in text.splitlines():
            if line.startswith("%") and line.endswith("%"):
                key = line.strip("%")
                f[key] = []
            elif line.strip() and key:
                f[key].append(line.strip())
        g = lambda k: (f.get(k) or [""])[0]
        if not g("NAME"):
            continue
        yield {
            "name": g("NAME"), "ver": g("VERSION"), "desc": g("DESC"),
            "license": " ".join(f.get("LICENSE", [])[:2]),
            "size": int(g("CSIZE") or 0), "inst": int(g("ISIZE") or 0),
            "section": " ".join(f.get("GROUPS", [])[:1]),
        }


def parse_flatpak(blob):
    """Flathub appstream: <component> entries with categories."""
    try:
        text = gzip.decompress(blob)
    except OSError:
        text = blob
    root = ET.fromstring(text)
    for c in root.findall("component"):
        cid = c.findtext("id") or ""
        name = c.findtext("name") or cid
        cats = [e.text for e in c.findall("categories/category") if e.text]
        yield {
            "name": cid, "ver": (c.find("releases/release").get("version", "")
                                 if c.find("releases/release") is not None else ""),
            "desc": (c.findtext("summary") or "") + ("" if not name or name == cid else " (" + name + ")"),
            "license": c.findtext("project_license") or "", "size": 0, "inst": 0,
            "section": cats[0] if cats else "",
        }


# ── section/group -> our category enum ────────────────────────────────────────────────────
SECTION_MAP = [
    (r"devel|programming|development|compiler|libdevel|sdk", "Development"),
    (r"game|amusement", "Games"),
    (r"graphic|image|photo|art|3d", "Graphics"),
    (r"net|web|mail|news|internet|comm", "Internet"),
    (r"sound|audio|video|multimedia|music|player", "Multimedia"),
    (r"office|text|editor|productivity|document", "Office"),
    (r"science|math|education|electronics", "Science"),
    (r"security|crypt|auth", "Security"),
    (r"admin|system|kernel|shell|base|utils|metapackages", "System"),
    (r"font", "Fonts"),
    (r"^lib|libs|libraries", "Libraries"),
    (r"accessor|util", "Accessories"),
]


def categorize(pkg):
    hay = (pkg.get("section", "") + " " + pkg["name"]).lower()
    for pat, cat in SECTION_MAP:
        if re.search(pat, hay):
            return CAT[cat]
    if pkg["name"].startswith("lib"):
        return CAT["Libraries"]
    return CAT["Other"]


# ── repository definitions ────────────────────────────────────────────────────────────────
ALPINE = "v3.19"
REPOS = [
    dict(name="Alpine " + ALPINE + " main", distro="Alpine Linux", pkgmgr="apk", installable=1,
         accent=0x0D597F, arch="x86_64", full=True,
         base="https://dl-cdn.alpinelinux.org/alpine/" + ALPINE + "/main/x86_64",
         index="https://dl-cdn.alpinelinux.org/alpine/" + ALPINE + "/main/x86_64/APKINDEX.tar.gz",
         kind="apk"),
    dict(name="Alpine " + ALPINE + " community", distro="Alpine Linux", pkgmgr="apk", installable=1,
         accent=0x0D597F, arch="x86_64", full=True,
         base="https://dl-cdn.alpinelinux.org/alpine/" + ALPINE + "/community/x86_64",
         index="https://dl-cdn.alpinelinux.org/alpine/" + ALPINE + "/community/x86_64/APKINDEX.tar.gz",
         kind="apk"),
    dict(name="Debian stable main", distro="Debian", pkgmgr="apt", installable=0,
         accent=0xA80030, arch="amd64",
         base="http://deb.debian.org/debian",
         index="http://deb.debian.org/debian/dists/stable/main/binary-amd64/Packages.gz",
         kind="deb"),
    dict(name="Ubuntu 24.04 main", distro="Ubuntu", pkgmgr="apt", installable=0,
         accent=0xE95420, arch="amd64",
         base="http://archive.ubuntu.com/ubuntu",
         index="http://archive.ubuntu.com/ubuntu/dists/noble/main/binary-amd64/Packages.gz",
         kind="deb"),
    dict(name="Ubuntu 24.04 universe", distro="Ubuntu", pkgmgr="apt", installable=0,
         accent=0xE95420, arch="amd64",
         base="http://archive.ubuntu.com/ubuntu",
         index="http://archive.ubuntu.com/ubuntu/dists/noble/universe/binary-amd64/Packages.gz",
         kind="deb"),
    dict(name="Fedora 43 Everything", distro="Fedora", pkgmgr="dnf", installable=0,
         accent=0x51A2DA, arch="x86_64",
         base="https://mirrors.kernel.org/fedora/releases/43/Everything/x86_64/os",
         index="https://mirrors.kernel.org/fedora/releases/43/Everything/x86_64/os/repodata/repomd.xml",
         kind="rpm"),
    dict(name="Arch core + extra", distro="Arch Linux", pkgmgr="pacman", installable=0,
         accent=0x1793D1, arch="x86_64",
         base="https://geo.mirror.pkgbuild.com",
         index=["https://geo.mirror.pkgbuild.com/core/os/x86_64/core.db",
                "https://geo.mirror.pkgbuild.com/extra/os/x86_64/extra.db"],
         kind="pacman"),
    dict(name="openSUSE Tumbleweed oss", distro="openSUSE", pkgmgr="zypper", installable=0,
         accent=0x73BA25, arch="x86_64",
         base="https://download.opensuse.org/tumbleweed/repo/oss",
         index="https://download.opensuse.org/tumbleweed/repo/oss/repodata/repomd.xml",
         kind="rpm"),
    dict(name="Flathub", distro="Flatpak", pkgmgr="flatpak", installable=0,
         accent=0x4A86CF, arch="x86_64",
         base="https://flathub.org/repo",
         index="https://flathub.org/repo/appstream/x86_64/appstream.xml.gz",
         kind="flatpak"),
]


def harvest(repo, limit, offline):
    kind = repo["kind"]
    try:
        if kind == "apk":
            pkgs = list(parse_apk(fetch(repo["index"], offline)))
        elif kind == "deb":
            pkgs = list(parse_deb(fetch(repo["index"], offline)))
        elif kind == "rpm":
            pkgs = list(parse_rpm(repo["index"], offline))
        elif kind == "pacman":
            pkgs = []
            for u in repo["index"]:
                pkgs += list(parse_pacman(fetch(u, offline)))
        elif kind == "flatpak":
            pkgs = list(parse_flatpak(fetch(repo["index"], offline)))
        else:
            return None, 0
    except Exception as e:                      # a mirror being down must not fail the build
        print("  [warn] %-28s %s" % (repo["name"], e), file=sys.stderr)
        return None, 0
    # de-duplicate by name, keeping the first (indexes list newest first for apk/pacman)
    seen, uniq = set(), []
    for p in pkgs:
        if not p["name"] or p["name"] in seen:
            continue
        seen.add(p["name"])
        uniq.append(p)
    total = len(uniq)
    uniq.sort(key=lambda p: p["name"])
    if not repo.get("full") and limit and total > limit:
        # Keep a deterministic, evenly-spread sample so the list still spans the alphabet and
        # the UI can say honestly how many were left out.
        step = total / float(limit)
        uniq = [uniq[int(i * step)] for i in range(limit)]
    return uniq, total


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    out = args[0] if args else "build/software-catalog.bin"
    limit = 8000
    for a in sys.argv[1:]:
        if a.startswith("--limit"):
            limit = int(a.split("=", 1)[1]) if "=" in a else limit
    offline = "--offline" in sys.argv

    strings = bytearray(b"\0")
    interned = {"": 0}

    def s(text):
        text = ascii_fold(text or "")
        if text in interned:
            return interned[text]
        off = len(strings)
        strings.extend(text.encode("ascii", "replace") + b"\0")
        interned[text] = off
        return off

    cat_offs = [s(c) for c in CATEGORIES]
    repo_recs, pkg_recs = [], []
    for ri, repo in enumerate(REPOS):
        pkgs, total = harvest(repo, limit, offline)
        if pkgs is None:
            pkgs, total = [], 0
        for p in pkgs:
            pkg_recs.append(struct.pack("<IIIIIIHH",
                                        s(p["name"][:48]), s(p["ver"][:24]),
                                        s(ascii_fold(p["desc"], 96)), s(p["license"][:28]),
                                        min(p["size"] // 1024, 0xFFFFFFFF),
                                        min(p["inst"] // 1024, 0xFFFFFFFF),
                                        ri, categorize(p)))
        repo_recs.append(struct.pack("<IIIIIIIBBBBII",
                                     s(repo["name"]), s(repo["distro"]), s(repo["pkgmgr"]),
                                     s(repo["base"]), s(repo["arch"]),
                                     total, len(pkgs), repo["installable"], 0, 0, 0,
                                     0, repo["accent"]))
        print("  %-28s %6d of %6d packages%s" %
              (repo["name"], len(pkgs), total, "  [installable here]" if repo["installable"] else ""))

    HDR = 52
    repo_off = HDR + 4 * len(cat_offs)
    pkg_off = repo_off + 40 * len(repo_recs)
    str_off = pkg_off + 28 * len(pkg_recs)
    hdr = struct.pack("<8sIIIIIIIQII", b"HOSSOFT1", 1, len(repo_recs), len(pkg_recs),
                      repo_off, pkg_off, str_off, len(strings), int(time.time()),
                      len(cat_offs), HDR)
    assert len(hdr) == HDR, len(hdr)
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "wb") as f:
        f.write(hdr)
        f.write(b"".join(struct.pack("<I", o) for o in cat_offs))
        f.write(b"".join(repo_recs))
        f.write(b"".join(pkg_recs))
        f.write(bytes(strings))
    print("[software-catalog] %s: %d packages from %d repositories, %.1f MiB" %
          (out, len(pkg_recs), len(repo_recs), os.path.getsize(out) / 1048576.0))
    if not pkg_recs:
        sys.exit(1)


if __name__ == "__main__":
    main()
