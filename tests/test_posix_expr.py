from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _find_compiler() -> str | None:
    for candidate in ("ldc2", "ldmd2", "dmd", "gdc"):
        path = shutil.which(candidate)
        if path:
            return path
    return None


@pytest.fixture(scope="module")
def expr_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    compiler = _find_compiler()
    if compiler is None:
        pytest.skip("no D compiler available in PATH")

    build_dir = tmp_path_factory.mktemp("expr-bin")
    binary = build_dir / "expr"
    source = ROOT / "src" / "minimal_os" / "posixutils" / "commands" / "expr" / "expr.d"

    cmd = [
        compiler,
        "-O",
        "-release",
        str(source),
        f"-of={binary}",
    ]
    subprocess.run(cmd, check=True, cwd=ROOT)
    binary.chmod(0o755)
    return binary


def _run_expr(expr_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [expr_path, *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


def test_expr_handles_basic_arithmetic(expr_binary: Path) -> None:
    result = _run_expr(expr_binary, "15", "+", "27")
    assert result.stdout == "42\n"
    assert result.stderr == ""
    assert result.returncode == 0


def test_expr_handles_logical_operators(expr_binary: Path) -> None:
    or_result = _run_expr(expr_binary, "0", "|", "5")
    assert or_result.stdout == "5\n"
    assert or_result.stderr == ""
    assert or_result.returncode == 0

    and_result = _run_expr(expr_binary, "0", "&", "5")
    assert and_result.stdout == "0\n"
    assert and_result.stderr == ""
    assert and_result.returncode == 1


def test_expr_handles_string_comparisons(expr_binary: Path) -> None:
    greater_result = _run_expr(expr_binary, "zebra", ">", "apple")
    assert greater_result.stdout == "1\n"
    assert greater_result.stderr == ""
    assert greater_result.returncode == 0

    equal_result = _run_expr(expr_binary, "foo", "=", "bar")
    assert equal_result.stdout == "0\n"
    assert equal_result.stderr == ""
    assert equal_result.returncode == 1
