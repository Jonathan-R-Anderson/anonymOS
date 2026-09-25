#!/usr/bin/env python3
# Copyright (C) 2026 Musa Jaradat
#
# This script is part of the Orin build and packaging pipeline.
# It compiles Orin into a single executable binary using PyInstaller
# and packs it into a production-ready offline setup archive.

import os
import sys
import shutil
import tarfile
import subprocess
from pathlib import Path

# Config
VERSION = "1.2.0"
APP_NAME = "orin"
PACKAGE_NAME = f"{APP_NAME}-{VERSION}-linux-x86_64"

def main():
    print(f"=== Starting Orin Standalone Packaging Pipeline (v{VERSION}) ===")
    project_root = Path(__file__).resolve().parents[1]
    os.chdir(project_root)

    venv_pyinstaller = project_root / "venv" / "bin" / "pyinstaller"
    if not venv_pyinstaller.exists():
        # Fallback to system-wide or PATH pyinstaller
        venv_pyinstaller = "pyinstaller"

    print(f"[*] Project Root: {project_root}")
    print(f"[*] PyInstaller: {venv_pyinstaller}")

    # Clean build/dist
    build_dir = project_root / "build"
    dist_dir = project_root / "dist"
    if build_dir.exists():
        print("[*] Cleaning build directory...")
        shutil.rmtree(build_dir)
    if dist_dir.exists():
        print("[*] Cleaning dist directory...")
        shutil.rmtree(dist_dir)

    # PyInstaller arguments
    # separator is : on Linux
    add_data_dashboard = "src/orin/core/dashboard.html:orin/core"
    add_data_rules = "rules:rules"
    add_data_assets = "assets:assets"

    pyinstaller_cmd = [
        str(venv_pyinstaller),
        "--onefile",
        "--name", APP_NAME,
        "--add-data", add_data_dashboard,
        "--add-data", add_data_rules,
        "--add-data", add_data_assets,
        "--hidden-import", "yara",
        "--hidden-import", "scapy",
        "--collect-all", "scapy",
        "--collect-all", "cryptography",
        "src/orin/main.py"
    ]

    print(f"[*] Running PyInstaller command:\n    {' '.join(pyinstaller_cmd)}")
    result = subprocess.run(pyinstaller_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print("❌ Error: PyInstaller build failed!")
        print("=== STDOUT ===")
        print(result.stdout)
        print("=== STDERR ===")
        print(result.stderr)
        sys.exit(1)

    print("✓ Binary compiled successfully!")

    binary_path = dist_dir / APP_NAME
    if not binary_path.exists():
        print(f"❌ Error: Compiled binary not found at {binary_path}!")
        sys.exit(1)

    print(f"✓ Binary size: {binary_path.stat().st_size / (1024*1024):.2f} MB")

    # Create layout for distribution archive
    dist_package_dir = dist_dir / PACKAGE_NAME
    dist_package_dir.mkdir(parents=True, exist_ok=True)

    # Copy binary
    print("[*] Copying binary to distribution package...")
    shutil.copy2(binary_path, dist_package_dir / APP_NAME)

    # Copy helper files
    files_to_copy = [
        "orin_config.json.example",
        "install.sh",
        "README.md",
        "LICENSE"
    ]
    for file_name in files_to_copy:
        src_file = project_root / file_name
        if src_file.exists():
            print(f"[*] Copying {file_name}...")
            shutil.copy2(src_file, dist_package_dir / file_name)

    # Copy rules folder
    print("[*] Copying default rules folder...")
    shutil.copytree(project_root / "rules", dist_package_dir / "rules", dirs_exist_ok=True)

    # Create tar.gz archive
    archive_path = dist_dir / f"{PACKAGE_NAME}.tar.gz"
    print(f"[*] Creating release archive at {archive_path}...")
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(dist_package_dir, arcname=PACKAGE_NAME)

    # Clean up intermediate directory
    shutil.rmtree(dist_package_dir)

    print(f"\n🟢 Success: Offline standalone package built successfully!")
    print(f"   Distribution Archive: {archive_path}")
    print(f"   Archive Size: {archive_path.stat().st_size / (1024*1024):.2f} MB")

if __name__ == "__main__":
    main()
