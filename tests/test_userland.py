from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest


def _find_compiler() -> str | None:
    for candidate in ("ldc2", "ldmd2", "dmd", "gdc"):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def test_userland_unittests_pass() -> None:
    compiler = _find_compiler()
    if compiler is None:
        pytest.skip("no D compiler available in PATH")

    repo_root = Path(__file__).resolve().parents[1]
    runner = repo_root / "tests" / "userland_test_runner.d"
    cmd = [
        compiler,
        "-I",
        str(repo_root / "src"),
        "-unittest",
        "-run",
        str(runner),
    ]
    result = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True)
    if result.returncode != 0:
        raise AssertionError(result.stderr + result.stdout)
