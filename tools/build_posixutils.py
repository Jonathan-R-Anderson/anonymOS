#!/usr/bin/env python3
"""Build D-based POSIX utility binaries for the interactive shell.

This script scans tools/posixutils for translated utilities and compiles each
subdirectory that contains D sources into a standalone binary.  By default the
artifacts are placed under build/posixutils/bin so that the kernel can extend
PATH when launching the interactive shell.
"""
from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence


@dataclass(frozen=True)
class BuildResult:
    name: str
    sources: Sequence[Path]
    output: Path


def repo_root_from(start: Path | None = None) -> Path:
    path = start or Path(__file__).resolve()
    return path.parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compile the D ports of the POSIX utilities",
    )
    parser.add_argument(
        "--dc",
        default=os.environ.get("POSIXUTILS_DC")
        or os.environ.get("SHELL_DC")
        or "ldc2",
        help="D compiler to invoke (default: %(default)s)",
    )
    parser.add_argument(
        "--flags",
        default=[],
        help="Additional flags passed to the D compiler (default depends on compiler)", 
        nargs="*", 
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Directory for the resulting binaries (default: build/posixutils/bin)",
    )
    parser.add_argument(
        "--root",
        type=Path,
        help="Override repository root autodetection",
    )
    return parser.parse_args()


def first_non_comment_char(text: str) -> str | None:
    i = 0
    length = len(text)
    while i < length:
        ch = text[i]
        if ch in "\r\n\t \f\v":
            i += 1
            continue
        if text.startswith("//", i):
            newline = text.find("\n", i + 2)
            if newline == -1:
                return None
            i = newline + 1
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end == -1:
                return None
            i = end + 2
            continue
        return text[i]
    return None


def is_d_source(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    first = first_non_comment_char(text)
    if first is None:
        return False
    if first == "#":
        # Original C sources keep their .d extension but rely on preprocessor
        # directives.  Skip those; they are not part of the D port yet.
        return False
    return True


def ensure_compiler_available(dc: str) -> None:
    if shutil.which(dc) is None:
        raise SystemExit(f"D compiler '{dc}' not found in PATH")


def default_flags_for(dc: str) -> List[str]:
    compiler = Path(dc).name
    if compiler.startswith("dmd"):
        return ["-O", "-release"]
    return ["-O2", "-release"]


def parse_flag_list(value: str | None, dc: str) -> List[str]:
    """
    Accept None | str | List[str]; remove -betterC/--betterC defensively.
    """
    if value is None:
        flags = default_flags_for(dc)
    elif isinstance(value, list):
        flags = value or default_flags_for(dc)
    elif isinstance(value, str):
        flags = shlex.split(value)
    else:
        flags = default_flags_for(dc)
    # POSIX utils rely on Phobos; -betterC breaks that. Strip it if present.
    flags = [f for f in flags if f not in ("-betterC", "--betterC")]
    return flags


def adjust_flags_for_compiler(flags: Sequence[str], dc: str) -> List[str]:
    """Normalise compiler-specific flag spellings."""

    compiler = Path(dc).name
    adjusted: List[str] = []
    for flag in flags:
        if flag.startswith("-version=") and compiler.startswith("ldc"):
            adjusted.append(flag.replace("-version=", "-d-version=", 1))
        else:
            adjusted.append(flag)
    return adjusted


def compile_command(dc: str, flags: Sequence[str], sources: Sequence[Path], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    cmd: List[str] = [dc]
    cmd.extend(str(src) for src in sources)
    cmd.extend(adjust_flags_for_compiler(flags, dc))
    string_import_dirs = {src.parent for src in sources}
    for import_dir in sorted(string_import_dirs):
        cmd.append(f"-J{os.fspath(import_dir)}")
    cmd.append(f"-of={output}")
    subprocess.run(cmd, check=True)
    try:
        mode = output.stat().st_mode
        output.chmod(mode | 0o111)
    except FileNotFoundError:
        # Some compilers may emit into a slightly different path on failure.
        pass


def discover_commands(source_root: Path) -> Iterable[tuple[str, List[Path]]]:
    for entry in sorted(source_root.iterdir()):
        if not entry.is_dir():
            continue
        sources = [src for src in sorted(entry.glob("*.d")) if is_d_source(src)]
        if not sources:
            continue
        yield entry.name, sources


COMMAND_FLAG_OVERRIDES: dict[str, Sequence[str]] = {
    # expr.d expects to be linked with a Bison-generated parser that
    # defines yyparse.  Until that port lands in the tree, build the D
    # lexer with the provided stub implementation instead so that the
    # build keeps moving.  (The stub prints an explanatory error when
    # invoked.)
    "expr": ("-version=NoBison",),
}


def build_all(dc: str, flags: Sequence[str], source_root: Path, output_dir: Path) -> List[BuildResult]:
    results: List[BuildResult] = []
    for name, sources in discover_commands(source_root):
        output = output_dir / name
        print(f"[build] {name}")
        extra_flags = COMMAND_FLAG_OVERRIDES.get(name, ())
        effective_flags = list(flags)
        if extra_flags:
            effective_flags.extend(extra_flags)
        compile_command(dc, effective_flags, sources, output)
        results.append(BuildResult(name, tuple(sources), output))
    return results


def write_manifest(manifest_dir: Path, results: Sequence[BuildResult], root: Path) -> None:
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / "manifest.txt"
    lines = []
    for result in results:
        rel_sources = ",".join(str(src.relative_to(root)) for src in result.sources)
        lines.append(f"{result.name}\t{rel_sources}\n")
    manifest_path.write_text("".join(lines), encoding="utf-8")
    print(f"[ok] Wrote manifest: {manifest_path}")


def main() -> None:
    args = parse_args()
    ensure_compiler_available(args.dc)

    root = repo_root_from(args.root)
    source_root = root / "tools" / "posixutils"
    if not source_root.is_dir():
        raise SystemExit(f"Source directory not found: {source_root}")

    output_dir = args.output or (root / "build" / "posixutils" / "bin")
    output_dir.mkdir(parents=True, exist_ok=True)

    flags = parse_flag_list(args.flags, args.dc)
    results = build_all(args.dc, flags, source_root, output_dir)
    if not results:
        print("[warn] No POSIX utilities were built; nothing to do")
        return

    write_manifest(output_dir.parent, results, root)
    print(f"[ok] Built {len(results)} POSIX utilities into {output_dir}")


if __name__ == "__main__":
    main()
