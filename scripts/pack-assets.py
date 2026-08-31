#!/usr/bin/env python3
"""Pack GUI assets into boot blobs.

Kernel-side unpacking still uses the flat rtfs overlay archive format:
repeated [u32 LE pathLen][path bytes][u32 LE dataLen][data bytes].

G10 adds pipeline behavior on top of that stable format:
- a generated manifest at /usr/share/hos/assets/manifest.json
- metadata for size, checksum, license, version, category, and defaults
- build-time guardrails against proprietary platform assets
- optional category blobs: fonts/icons/cursors/wallpapers/themes
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


CATEGORY_BLOBS = ("fonts", "icons", "cursors", "wallpapers", "themes")
FORBIDDEN_RE = re.compile(
    r"\b(apple|macos|mac\s+os|san\s+francisco|sf\s+pro|sf\s+compact|"
    r"cupertino|proprietary)\b",
    re.IGNORECASE,
)
TEXT_NAMES = {
    "license",
    "copying",
    "copyright",
    "readme",
    "index.theme",
    "cursor.theme",
    "settings.ini",
}
TEXT_SUFFIXES = {".txt", ".md", ".json", ".ini", ".theme", ".svg", ".xml", ".css"}


@dataclass(frozen=True)
class Entry:
    rel: Path
    guest_path: str
    data: bytes
    category: str
    license: str
    version: str

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


def is_text_like(path: Path) -> bool:
    lower = path.name.lower()
    stem = path.stem.lower()
    return lower in TEXT_NAMES or stem in TEXT_NAMES or path.suffix.lower() in TEXT_SUFFIXES


def check_forbidden(path: Path, rel: Path, data: bytes, allow_proprietary: bool) -> None:
    if allow_proprietary:
        return

    haystacks = [rel.as_posix()]
    if is_text_like(path):
        haystacks.append(data[:262144].decode("utf-8", errors="ignore"))

    for text in haystacks:
        match = FORBIDDEN_RE.search(text)
        if match:
            print(
                "pack-assets: refused potentially proprietary GUI asset "
                f"{rel.as_posix()} (matched {match.group(0)!r}); set "
                "HOS_ALLOW_PROPRIETARY_ASSETS=1 only for local experiments",
                file=sys.stderr,
            )
            raise SystemExit(2)


def category_for(rel: Path) -> str:
    parts = rel.parts
    if not parts:
        return "misc"
    first = parts[0]
    if first == "fonts":
        return "fonts"
    if first == "icons":
        if "cursors" in parts or rel.name in {"cursor.theme"}:
            return "cursors"
        return "icons"
    if first == "cursors":
        return "cursors"
    if first in {"backgrounds", "wallpapers", "hypr"}:
        return "wallpapers"
    if first == "themes":
        return "themes"
    if first == "hos":
        return "themes"
    return "misc"


def license_for(src_root: Path, rel: Path) -> str:
    parts = rel.parts
    if not parts:
        return "unknown"
    if parts[0] == "fonts" and len(parts) >= 2 and parts[1] == "noto":
        return "OFL-1.1"
    if parts[0] == "icons" and len(parts) >= 2 and parts[1] == "Epin":
        if "cursors" in parts:
            return "CC-BY-SA-3.0"
        return "CC0-1.0"
    if parts[0] == "icons" and len(parts) >= 2 and parts[1] in {"default", "hicolor"}:
        if "cursors" in parts:
            return "CC-BY-SA-3.0"
        return "CC0-1.0"
    if parts[0] in {"cursors", "backgrounds", "wallpapers", "themes", "hos"}:
        return "CC0-1.0"
    if parts[0] == "hypr":
        return "CC0-1.0"

    cur = src_root / rel.parent
    while src_root in (cur, *cur.parents):
        for name in ("LICENSE", "LICENSE.txt", "COPYING", "copyright"):
            if (cur / name).is_file():
                return f"see {os.path.relpath(cur / name, src_root)}"
        if cur == src_root:
            break
        cur = cur.parent
    return "unknown"


def version_for(rel: Path) -> str:
    parts = rel.parts
    if len(parts) >= 2 and parts[0] == "fonts" and parts[1] == "noto":
        return "packaged"
    if parts and parts[0] in {"icons", "cursors", "backgrounds", "themes", "hos", "hypr"}:
        return "2026.06"
    return "1"


def collect_entries(src_root: Path, prefix: str, allow_proprietary: bool) -> list[Entry]:
    entries: list[Entry] = []
    prefix = prefix.strip("/")
    for path in sorted(src_root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(src_root)
        data = path.read_bytes()
        check_forbidden(path, rel, data, allow_proprietary)
        guest_path = f"{prefix}/{rel.as_posix()}"
        entries.append(
            Entry(
                rel=rel,
                guest_path=guest_path,
                data=data,
                category=category_for(rel),
                license=license_for(src_root, rel),
                version=version_for(rel),
            )
        )
    return entries


def make_manifest(entries: list[Entry], prefix: str) -> bytes:
    by_category: dict[str, dict[str, int]] = {}
    for entry in entries:
        item = by_category.setdefault(entry.category, {"files": 0, "bytes": 0})
        item["files"] += 1
        item["bytes"] += entry.size

    doc = {
        "schema": 1,
        "generated_by": "scripts/pack-assets.py",
        "prefix": prefix.strip("/"),
        "defaults": {
            "ui_font": "Noto Sans 10",
            "monospace_font": "Noto Sans Mono 11",
            "terminal_font": "/usr/share/fonts/noto/NotoSansMono-Regular.ttf",
            "icon_theme": "Epin",
            "cursor_theme": "Epin",
            "gtk_theme": "Epin",
            "wallpaper": "/usr/share/backgrounds/epin/wall0.png",
        },
        "categories": by_category,
        "assets": [
            {
                "name": entry.rel.stem,
                "path": "/" + entry.guest_path,
                "category": entry.category,
                "license": entry.license,
                "size": entry.size,
                "sha256": entry.sha256,
                "version": entry.version,
            }
            for entry in sorted(entries, key=lambda e: e.guest_path)
        ],
    }
    return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_blob(path: Path, entries: list[Entry]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as out:
        for entry in sorted(entries, key=lambda e: e.guest_path):
            p = entry.guest_path.encode("utf-8")
            out.write(struct.pack("<I", len(p)))
            out.write(p)
            out.write(struct.pack("<I", len(entry.data)))
            out.write(entry.data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("src", type=Path, help="asset staging tree, e.g. build/assets")
    parser.add_argument("out", type=Path, help="aggregate output blob")
    parser.add_argument("prefix", nargs="?", default="usr/share")
    parser.add_argument("--category-dir", type=Path, help="directory for fonts/icons/cursors/wallpapers/themes blobs")
    args = parser.parse_args()

    if not args.src.is_dir():
        raise SystemExit(f"pack-assets: missing source tree {args.src}")

    allow_proprietary = os.environ.get("HOS_ALLOW_PROPRIETARY_ASSETS") == "1"
    entries = collect_entries(args.src, args.prefix, allow_proprietary)
    manifest_path = f"{args.prefix.strip('/')}/hos/assets/manifest.json"
    manifest = Entry(
        rel=Path("hos/assets/manifest.json"),
        guest_path=manifest_path,
        data=make_manifest(entries, args.prefix),
        category="themes",
        license="CC0-1.0",
        version="2026.06",
    )
    entries_with_manifest = entries + [manifest]

    write_blob(args.out, entries_with_manifest)
    print(
        f"pack-assets: {len(entries_with_manifest)} files -> {args.out} "
        f"({args.out.stat().st_size} bytes)"
    )

    if args.category_dir:
        args.category_dir.mkdir(parents=True, exist_ok=True)
        for category in CATEGORY_BLOBS:
            blob_entries = [e for e in entries_with_manifest if e.category == category]
            out = args.category_dir / f"{category}.blob"
            write_blob(out, blob_entries)
            total = sum(e.size for e in blob_entries)
            print(f"pack-assets: {category}: {len(blob_entries)} files, {total} bytes -> {out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
