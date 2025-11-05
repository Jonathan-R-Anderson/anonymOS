#!/usr/bin/env python3
"""Utility for building a D runtime/standard-library toolchain with a cross compiler.

The script is intentionally opinionated but highly configurable.  It accepts either
command-line arguments or a TOML configuration file that describes the location of the
compiler, runtime sources, and any additional modules that should be part of the final
binary.  The goal is to make it possible to bootstrap and iterate on a completely custom
D compiler by reusing an existing cross compiler for the heavy lifting while keeping the
build orchestration reproducible.
"""
from __future__ import annotations

import argparse
import fnmatch
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Sequence

try:  # Python 3.11+
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover - compatibility with older Python
    tomllib = None  # type: ignore[assignment]


@dataclass
class BuildSettings:
    compiler: Path
    runtime: Path
    phobos: Path | None = None
    mstd: Path | None = None
    user_dirs: List[Path] = field(default_factory=list)
    build_dir: Path = Path("build")
    output: Path | None = None
    log_file: Path = Path("build.log")
    target_triple: str | None = None
    gcc: Path | None = None
    compile_flags: List[str] = field(default_factory=list)
    link_flags: List[str] = field(default_factory=list)
    lib_dirs: List[Path] = field(default_factory=list)
    libs: List[str] = field(default_factory=list)
    skip_patterns: List[str] = field(default_factory=list)
    include_dirs: List[Path] = field(default_factory=list)
    conf_file: Path | None = None
    sysroot: Path | None = None
    archiver: Path | None = None
    dry_run: bool = False
    force: bool = False
    keep_going: bool = False

    def all_include_dirs(self) -> List[Path]:
        includes: List[Path] = []
        if self.runtime:
            runtime_src = resolve_source_root(self.runtime)
            includes.append(runtime_src)
        if self.phobos:
            includes.append(resolve_source_root(self.phobos))
        for user_dir in self.user_dirs:
            includes.append(resolve_source_root(user_dir))
        if self.mstd:
            includes.append(resolve_source_root(self.mstd))
        includes.extend(self.include_dirs)
        # Remove duplicates while preserving order
        seen: set[Path] = set()
        unique: List[Path] = []
        for item in includes:
            item = item.resolve()
            if item not in seen:
                seen.add(item)
                unique.append(item)
        return unique


@dataclass
class BuildGroup:
    name: str
    root: Path
    include_dirs: Sequence[Path]
    extra_flags: Sequence[str] = ()


class ToolchainBuilder:
    def __init__(self, settings: BuildSettings) -> None:
        self.settings = settings
        self.build_dir = settings.build_dir.resolve()
        self.build_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = settings.log_file.resolve()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        mode = "w"
        self.log_file = self.log_path.open(mode, encoding="utf-8")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._log(f"Starting toolchain build at {timestamp}")
        self._log(f"Compiler: {settings.compiler}")

    def close(self) -> None:
        if not self.log_file.closed:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._log(f"Build finished at {timestamp}")
            self.log_file.close()

    # Context manager support -------------------------------------------------
    def __enter__(self) -> "ToolchainBuilder":  # pragma: no cover - exercised implicitly
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # pragma: no cover - exercised implicitly
        self.close()

    # Logging ----------------------------------------------------------------
    def _log(self, message: str, *, console: bool = False) -> None:
        self.log_file.write(message + "\n")
        self.log_file.flush()
        if console:
            print(message)

    def _log_command(self, cmd: Sequence[str]) -> None:
        self._log("Running: " + shlex.join(cmd))

    # Build steps ------------------------------------------------------------
    def build(self) -> None:
        groups: List[BuildGroup] = []
        runtime_root = resolve_source_root(self.settings.runtime)
        groups.append(BuildGroup("druntime", runtime_root, [runtime_root]))

        includes = self.settings.all_include_dirs()
        include_dirs = includes

        if self.settings.phobos:
            phobos_root = resolve_source_root(self.settings.phobos)
            groups.append(BuildGroup("phobos", phobos_root, include_dirs))
        if self.settings.mstd:
            mstd_root = resolve_source_root(self.settings.mstd)
            groups.append(BuildGroup("mstd", mstd_root, include_dirs))
        for user_dir in self.settings.user_dirs:
            user_root = resolve_source_root(user_dir)
            groups.append(BuildGroup(user_dir.name, user_root, include_dirs))

        all_objects: List[Path] = []
        group_archives: Dict[str, Path] = {}
        for group in groups:
            self._log(f"\n=== Building {group.name} ===", console=True)
            objects = self._compile_group(group)
            all_objects.extend(objects)
            if self.settings.sysroot:
                archive = self._archive_group(group.name, objects)
                if archive:
                    group_archives[group.name] = archive

        if not all_objects:
            raise RuntimeError("No object files were produced; check your configuration")

        self._link(all_objects, include_dirs)
        if self.settings.sysroot:
            self._create_sysroot(groups, include_dirs, group_archives)

    def _compile_group(self, group: BuildGroup) -> List[Path]:
        sources = sorted(group.root.rglob("*.d"))
        objects: List[Path] = []
        for source in sources:
            if self._is_skipped(source):
                continue
            rel = source.relative_to(group.root)
            obj_path = self.build_dir / group.name / rel.with_suffix(".o")
            obj_path.parent.mkdir(parents=True, exist_ok=True)
            if not self.settings.force and obj_path.exists():
                src_mtime = source.stat().st_mtime
                obj_mtime = obj_path.stat().st_mtime
                if obj_mtime >= src_mtime:
                    self._log(f"Skipping up-to-date {source}")
                    objects.append(obj_path)
                    continue
            cmd = self._compile_command(source, obj_path, group.include_dirs, group.extra_flags)
            objects.append(obj_path)
            self._execute(cmd)
        return objects

    def _compile_command(
        self,
        source: Path,
        obj_path: Path,
        include_dirs: Sequence[Path],
        extra_flags: Sequence[str],
    ) -> List[str]:
        cmd: List[str] = [str(self.settings.compiler), "-c", f"-of={obj_path}"]
        cmd.extend(self._target_flags())
        if self.settings.conf_file:
            cmd.append(f"-conf={self.settings.conf_file}")
        for include in include_dirs:
            cmd.append(f"-I{include}")
        cmd.extend(self.settings.compile_flags)
        cmd.extend(extra_flags)
        cmd.append(str(source))
        return cmd

    def _link(self, objects: Sequence[Path], include_dirs: Sequence[Path]) -> None:
        output = self.settings.output or (self.build_dir / "a.out")
        output.parent.mkdir(parents=True, exist_ok=True)
        cmd: List[str] = [str(self.settings.compiler), f"-of={output}"]
        cmd.extend(self._target_flags())
        if self.settings.conf_file:
            cmd.append(f"-conf={self.settings.conf_file}")
        for include in include_dirs:
            cmd.append(f"-I{include}")
        cmd.extend(self.settings.compile_flags)
        cmd.extend(self.settings.link_flags)
        cmd.extend(str(obj) for obj in objects)
        for lib_dir in self.settings.lib_dirs:
            cmd.append(f"-L-L{lib_dir}")
        for lib in self.settings.libs:
            cmd.append(f"-L-l{lib}")
        self._execute(cmd)
        self._log(f"Linked output: {output}", console=True)

    def _target_flags(self) -> List[str]:
        flags: List[str] = []
        if self.settings.target_triple:
            flags.append(f"-mtriple={self.settings.target_triple}")
        if self.settings.gcc:
            flags.append(f"-gcc={self.settings.gcc}")
        return flags

    def _is_skipped(self, path: Path) -> bool:
        if not self.settings.skip_patterns:
            return False
        rel = str(path.as_posix())
        for pattern in self.settings.skip_patterns:
            if fnmatch.fnmatch(rel, pattern):
                self._log(f"Skipping {path} (matched pattern {pattern})")
                return True
        return False

    def _execute(self, cmd: Sequence[str]) -> None:
        if self.settings.dry_run:
            self._log("DRY RUN: " + shlex.join(cmd), console=True)
            return
        self._log_command(cmd)
        try:
            subprocess.run(cmd, check=True, stdout=self.log_file, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            message = f"Command failed with exit code {exc.returncode}: {shlex.join(cmd)}"
            self._log(message, console=True)
            if self.settings.keep_going:
                return
            raise

    # Sysroot helpers --------------------------------------------------------
    def _archive_group(self, name: str, objects: Sequence[Path]) -> Path | None:
        if not objects:
            self._log(f"No object files for {name}; skipping archive creation")
            return None
        archiver = self._archiver_path()
        archive_dir = self.build_dir / "lib"
        if not self.settings.dry_run:
            archive_dir.mkdir(parents=True, exist_ok=True)
        archive_name = f"lib{self._sanitize_name(name)}.a"
        archive_path = archive_dir / archive_name
        cmd = [archiver, "rcs", str(archive_path)]
        cmd.extend(str(obj) for obj in objects)
        self._execute(cmd)
        self._log(f"Created archive: {archive_path}")
        return archive_path

    def _archiver_path(self) -> str:
        if self.settings.archiver:
            return str(self.settings.archiver)
        archiver = shutil.which("ar")
        if archiver:
            return archiver
        raise RuntimeError("No archiver found; specify --archiver or ensure 'ar' is available")

    def _create_sysroot(
        self,
        groups: Sequence[BuildGroup],
        include_dirs: Sequence[Path],
        group_archives: Dict[str, Path],
    ) -> None:
        sysroot = self.settings.sysroot
        if sysroot is None:
            return
        include_root = sysroot / "include"
        lib_root = sysroot / "lib"
        if self.settings.dry_run:
            self._log(f"DRY RUN: create sysroot directories {include_root} and {lib_root}", console=True)
        else:
            include_root.mkdir(parents=True, exist_ok=True)
            lib_root.mkdir(parents=True, exist_ok=True)

        used_names: set[str] = set()
        copied_dirs: set[Path] = set()

        for group in groups:
            root = group.root.resolve()
            if not root.exists():
                self._log(f"Warning: include root {root} does not exist; skipping", console=True)
                continue
            name = self._unique_sysroot_name(root, group.name, used_names)
            dest = include_root / name
            self._copy_directory(root, dest)
            copied_dirs.add(root)

        for include in include_dirs:
            inc = include.resolve()
            if inc in copied_dirs or not inc.exists():
                if not inc.exists():
                    self._log(f"Warning: include directory {inc} missing; skipping", console=True)
                continue
            name = self._unique_sysroot_name(inc, inc.name, used_names)
            dest = include_root / name
            self._copy_directory(inc, dest)
            copied_dirs.add(inc)

        libs_to_copy: set[Path] = set()
        for archive in group_archives.values():
            libs_to_copy.add(archive)
        for extra in self._discover_external_libs():
            libs_to_copy.add(extra)

        for lib in sorted(libs_to_copy):
            if not lib.exists():
                self._log(f"Warning: library {lib} missing; skipping", console=True)
                continue
            dest = lib_root / lib.name
            self._copy_file(lib, dest)

        self._log(f"Sysroot staged at {sysroot}", console=True)

    def _discover_external_libs(self) -> List[Path]:
        libs: List[Path] = []
        seen: set[Path] = set()
        patterns = ("*.a", "*.lib", "*.so", "*.dylib", "*.bc", "*.o")
        for lib_dir in self.settings.lib_dirs:
            if not lib_dir.exists():
                self._log(f"Library directory {lib_dir} does not exist; skipping", console=True)
                continue
            for pattern in patterns:
                for candidate in lib_dir.glob(pattern):
                    path = candidate.resolve()
                    if path in seen:
                        continue
                    libs.append(path)
                    seen.add(path)
        return libs

    def _copy_directory(self, src: Path, dest: Path) -> None:
        message = f"Copy directory {src} -> {dest}"
        if self.settings.dry_run:
            self._log(f"DRY RUN: {message}", console=True)
            return
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(src, dest)
        self._log(message)

    def _copy_file(self, src: Path, dest: Path) -> None:
        message = f"Copy file {src} -> {dest}"
        if self.settings.dry_run:
            self._log(f"DRY RUN: {message}", console=True)
            return
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        self._log(message)

    def _unique_sysroot_name(self, path: Path, preferred: str, used: set[str]) -> str:
        candidates = []
        if preferred:
            candidates.append(self._sanitize_name(preferred))
        parts = [part for part in path.parts if part]
        if len(parts) >= 2:
            candidates.append(self._sanitize_name("-".join(parts[-2:])))
        if parts:
            candidates.append(self._sanitize_name(parts[-1]))
        candidates.append("include")
        for base in candidates:
            name = self._ensure_unique(base or "component", used)
            if name:
                return name
        return self._ensure_unique("component", used)

    @staticmethod
    def _sanitize_name(value: str) -> str:
        sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
        return sanitized.strip("_")

    @staticmethod
    def _ensure_unique(base: str, used: set[str]) -> str:
        base = base or "component"
        candidate = base
        counter = 2
        while candidate in used:
            candidate = f"{base}_{counter}"
            counter += 1
        used.add(candidate)
        return candidate


def resolve_source_root(path: Path) -> Path:
    path = path.expanduser().resolve()
    candidate = path / "src"
    if candidate.is_dir():
        return candidate
    return path


def parse_args(argv: Sequence[str]) -> BuildSettings:
    parser = argparse.ArgumentParser(
        description="Build a custom D toolchain using an existing (cross) compiler",
    )
    parser.add_argument("--config", type=Path, help="Optional TOML configuration file", default=None)
    parser.add_argument("--compiler", type=Path, help="Path to the D compiler executable", default=None)
    parser.add_argument("--runtime", type=Path, help="Path to druntime root (or its src directory)", default=None)
    parser.add_argument("--phobos", type=Path, help="Path to Phobos root (optional)", default=None)
    parser.add_argument("--mstd", type=Path, help="Path to supplemental modules (optional)", default=None)
    parser.add_argument(
        "--user",
        type=Path,
        dest="user_dirs",
        action="append",
        help="Additional user module directories",
        default=None,
    )
    parser.add_argument("--build-dir", type=Path, default=None)
    parser.add_argument("--output", type=Path, help="Path of the final linked binary", default=None)
    parser.add_argument("--log-file", type=Path, default=None)
    parser.add_argument("--target-triple", type=str, default=None)
    parser.add_argument("--gcc", type=Path, default=None, help="Path to GCC/Clang for cross-linking")
    parser.add_argument(
        "--compile-flag",
        dest="compile_flags",
        action="append",
        default=None,
        help="Additional compiler flag (may be repeated)",
    )
    parser.add_argument(
        "--link-flag",
        dest="link_flags",
        action="append",
        default=None,
        help="Additional linker flag (may be repeated)",
    )
    parser.add_argument(
        "--lib-dir",
        dest="lib_dirs",
        action="append",
        default=None,
        type=Path,
        help="Library search directory for the linker",
    )
    parser.add_argument(
        "--lib",
        dest="libs",
        action="append",
        default=None,
        help="Library name to link against (without the lib prefix)",
    )
    parser.add_argument(
        "--skip",
        dest="skip_patterns",
        action="append",
        default=None,
        help="Glob pattern for source files to skip",
    )
    parser.add_argument(
        "--include-dir",
        dest="include_dirs",
        action="append",
        default=None,
        type=Path,
        help="Extra include/import directory",
    )
    parser.add_argument("--conf", dest="conf_file", type=Path, default=None, help="Path to dmd.conf equivalent")
    parser.add_argument(
        "--sysroot",
        type=Path,
        default=None,
        help="Directory where libraries and headers will be staged",
    )
    parser.add_argument(
        "--archiver",
        type=Path,
        default=None,
        help="Archiver executable used to create static libraries (defaults to 'ar')",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print commands without executing them")
    parser.add_argument("--force", action="store_true", help="Recompile all files even if up to date")
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="Continue compilation after errors (errors will still be reported)",
    )

    args = parser.parse_args(argv)
    config_data = load_config(args.config)
    merged: dict = dict(config_data)

    def set_path(key: str, value: Path | None) -> None:
        if value is not None:
            merged[key] = str(value)

    def set_str(key: str, value: str | None) -> None:
        if value is not None:
            merged[key] = value

    def extend_list(key: str, values):
        if not values:
            return
        existing = merged.get(key)
        if isinstance(existing, list):
            items = list(existing)
        elif existing is None:
            items = []
        else:
            items = [existing]
        items.extend(str(item) for item in values)
        merged[key] = items

    set_path("compiler", args.compiler)
    set_path("runtime", args.runtime)
    set_path("phobos", args.phobos)
    set_path("mstd", args.mstd)
    extend_list("user", args.user_dirs)
    set_path("build_dir", args.build_dir)
    set_path("output", args.output)
    set_path("log_file", args.log_file)
    set_str("target_triple", args.target_triple)
    set_path("gcc", args.gcc)
    extend_list("compile_flags", args.compile_flags)
    extend_list("link_flags", args.link_flags)
    extend_list("lib_dirs", args.lib_dirs)
    extend_list("libs", args.libs)
    extend_list("skip", args.skip_patterns)
    extend_list("include_dirs", args.include_dirs)
    set_path("conf", args.conf_file)
    set_path("sysroot", args.sysroot)
    set_path("archiver", args.archiver)
    if args.dry_run:
        merged["dry_run"] = True
    if args.force:
        merged["force"] = True
    if args.keep_going:
        merged["keep_going"] = True

    try:
        return build_settings_from_dict(merged)
    except ValueError as exc:
        parser.error(str(exc))
        raise  # pragma: no cover - parser.error exits


def build_settings_from_dict(data: dict) -> BuildSettings:
    def resolve_executable(key: str) -> Path:
        value = data.get(key)
        if value is None:
            raise ValueError(f"Missing required configuration value: {key}")

        raw_path = Path(str(value)).expanduser()

        direct_candidates: list[Path] = [raw_path]
        if not raw_path.is_absolute():
            direct_candidates.append(Path.cwd() / raw_path)

        for candidate in direct_candidates:
            if candidate.exists():
                return candidate.resolve()

        search_terms: list[str] = []
        string_value = str(value)
        if string_value:
            search_terms.append(string_value)
        name = raw_path.name
        if name and name not in search_terms:
            search_terms.append(name)

        for term in search_terms:
            found = shutil.which(term)
            if found:
                return Path(found).resolve()

        raise ValueError(
            f"Executable specified for '{key}' was not found: {value}. "
            "Update the configuration or ensure it is available on PATH."
        )

    def require_path(key: str) -> Path:
        value = data.get(key)
        if value is None:
            raise ValueError(f"Missing required configuration value: {key}")
        return Path(value).expanduser().resolve()

    def optional_path(key: str) -> Path | None:
        value = data.get(key)
        if value is None:
            return None
        return Path(value).expanduser().resolve()

    def path_list(key: str) -> List[Path]:
        value = data.get(key, [])
        if isinstance(value, list):
            values = value
        elif value is None:
            values = []
        else:
            values = [value]
        return [Path(item).expanduser().resolve() for item in values if item]

    def str_list(key: str) -> List[str]:
        value = data.get(key, [])
        if isinstance(value, list):
            values = value
        elif value is None:
            values = []
        else:
            values = [value]
        return [str(item) for item in values if item is not None]

    build_dir = optional_path("build_dir") or Path("build").resolve()
    log_file = optional_path("log_file") or Path("build.log").resolve()

    compiler = resolve_executable("compiler")

    return BuildSettings(
        compiler=compiler,
        runtime=require_path("runtime"),
        phobos=optional_path("phobos"),
        mstd=optional_path("mstd"),
        user_dirs=path_list("user"),
        build_dir=build_dir,
        output=optional_path("output"),
        log_file=log_file,
        target_triple=data.get("target_triple"),
        gcc=optional_path("gcc"),
        compile_flags=str_list("compile_flags"),
        link_flags=str_list("link_flags"),
        lib_dirs=path_list("lib_dirs"),
        libs=str_list("libs"),
        skip_patterns=str_list("skip"),
        include_dirs=path_list("include_dirs"),
        conf_file=optional_path("conf"),
        sysroot=optional_path("sysroot"),
        archiver=optional_path("archiver"),
        dry_run=bool(data.get("dry_run", False)),
        force=bool(data.get("force", False)),
        keep_going=bool(data.get("keep_going", False)),
    )



def load_config(path: Path | None) -> dict:
    if path is None:
        return {}
    if tomllib is None:
        raise RuntimeError("TOML support is unavailable; install tomli or use Python 3.11+")
    with path.expanduser().open("rb") as fp:
        data = tomllib.load(fp)
    if not isinstance(data, dict):
        raise ValueError("Configuration file must define a table at the top level")
    return data


def main(argv: Sequence[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    settings = parse_args(argv)
    with ToolchainBuilder(settings) as builder:
        builder.build()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Build cancelled", file=sys.stderr)
        raise
