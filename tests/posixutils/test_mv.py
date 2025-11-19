from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest


def _find_compiler() -> str | None:
    for candidate in ("ldc2", "ldmd2", "dmd", "gdc"):
        path = shutil.which(candidate)
        if path:
            return path
    return None


@pytest.fixture(scope="session")
def mv_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    compiler = _find_compiler()
    if compiler is None:
        pytest.skip("no D compiler available in PATH")

    repo_root = Path(__file__).resolve().parents[2]
    output_dir = tmp_path_factory.mktemp("posixutils-bin")
    build_script = repo_root / "tools" / "build_posixutils.py"
    cmd = [
        sys.executable,
        str(build_script),
        "--dc",
        compiler,
        "--output",
        str(output_dir),
    ]
    subprocess.run(cmd, cwd=repo_root, check=True)
    mv_path = output_dir / "mv"
    if not mv_path.exists():
        pytest.skip("mv binary was not built")
    return mv_path


@pytest.mark.skipif(os.geteuid() != 0, reason="requires root privileges to mount tmpfs")
def test_mv_cross_filesystem_directory_copy(mv_binary: Path, tmp_path: Path) -> None:
    src_root = tmp_path / "srcfs"
    dest_root = tmp_path / "destfs"
    src_root.mkdir()
    dest_root.mkdir()

    mounted = False
    try:
        try:
            subprocess.run(["mount", "-t", "tmpfs", "tmpfs", str(dest_root)], check=True)
        except (FileNotFoundError, subprocess.CalledProcessError) as exc:
            pytest.skip(f"tmpfs mount unavailable: {exc}")
        mounted = True

        tree = src_root / "tree"
        nested = tree / "nested"
        nested.mkdir(parents=True)
        payload = nested / "payload.txt"
        payload.write_text("hello mv", encoding="utf-8")

        os.chmod(tree, 0o750)
        os.chmod(nested, 0o705)
        os.chmod(payload, 0o741)

        now = int(time.time())
        os.utime(tree, (now - 300, now - 300))
        os.utime(nested, (now - 200, now - 200))
        os.utime(payload, (now - 100, now - 100))

        dest_path = dest_root / "tree"
        result = subprocess.run(
            [str(mv_binary), str(tree), str(dest_path)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr + result.stdout

        assert not tree.exists()
        copied_payload = dest_path / "nested" / "payload.txt"
        assert copied_payload.read_text(encoding="utf-8") == "hello mv"

        payload_stat = copied_payload.stat()
        nested_stat = (dest_path / "nested").stat()
        tree_stat = dest_path.stat()

        assert stat.S_IMODE(payload_stat.st_mode) == 0o741
        assert stat.S_IMODE(nested_stat.st_mode) == 0o705
        assert stat.S_IMODE(tree_stat.st_mode) == 0o750

        assert int(payload_stat.st_mtime) == now - 100
        assert int(nested_stat.st_mtime) == now - 200
        assert int(tree_stat.st_mtime) == now - 300
    finally:
        if mounted:
            subprocess.run(["umount", str(dest_root)], check=False)
