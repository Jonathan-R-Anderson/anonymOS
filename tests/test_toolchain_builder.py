from __future__ import annotations

from pathlib import Path
from textwrap import dedent
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from toolchain_builder import build_settings_from_dict, load_config


def _touch_executable(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)


def test_build_settings_from_dict_uses_config_directory_for_relative_paths(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()

    toolchain_dir = tmp_path / "toolchain"
    compiler = toolchain_dir / "ldc2"
    archiver = toolchain_dir / "dar"
    _touch_executable(compiler)
    _touch_executable(archiver)

    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    include_dir = tmp_path / "includes"
    include_dir.mkdir()
    lib_dir = tmp_path / "lib"
    lib_dir.mkdir()
    user_dir = tmp_path / "user"
    user_dir.mkdir()

    config_path = config_dir / "toolchain.toml"
    config_path.write_text(
        dedent(
            """
            compiler = "../toolchain/ldc2"
            runtime = "../runtime"
            user = ["../user"]
            build_dir = "../build-out"
            output = "../build-out/app.bin"
            log_file = "../logs/build.log"
            include_dirs = ["../includes"]
            lib_dirs = ["../lib"]
            sysroot = "../sysroot"
            archiver = "../toolchain/dar"
            """
        ).strip()
    )

    data, base_dir = load_config(config_path)
    settings = build_settings_from_dict(data, base_dir=base_dir)

    assert settings.compiler == compiler.resolve()
    assert settings.runtime == runtime_dir.resolve()
    assert settings.user_dirs == [user_dir.resolve()]
    assert settings.build_dir == (tmp_path / "build-out").resolve()
    assert settings.output == (tmp_path / "build-out" / "app.bin").resolve()
    assert settings.log_file == (tmp_path / "logs" / "build.log").resolve()
    assert settings.include_dirs == [include_dir.resolve()]
    assert settings.lib_dirs == [lib_dir.resolve()]
    assert settings.sysroot == (tmp_path / "sysroot").resolve()
    assert settings.archiver == archiver.resolve()


def test_load_config_without_file(tmp_path: Path) -> None:
    data, base_dir = load_config(None)
    assert data == {}
    assert base_dir is None

    config_path = tmp_path / "cfg" / "toolchain.toml"
    config_path.parent.mkdir()
    config_path.write_text("compiler = \"/bin/false\"\nruntime = \"/tmp\"\n", encoding="utf-8")

    data, base_dir = load_config(config_path)
    assert base_dir == config_path.parent.resolve()
    assert data["compiler"] == "/bin/false"
