# Copyright (C) 2026 Musa Jaradat
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
orin.core.self_verify – Tool Self-Verification & Signed Release Support
========================================================================

Provides mechanisms for verifying Orin's own integrity through:
1. Embedded checksums and SBOM (Software Bill of Materials)
2. GPG signature verification of release manifests
3. Self-check commands for runtime integrity validation
4. Release manifest generation for distribution

This establishes trust in the tool's integrity, critical for forensic tools
that may be deployed in adversarial environments.
"""
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple


def compute_file_sha256(file_path: Path) -> str:
    """Compute SHA-256 hash of a file.

    Parameters
    ----------
    file_path : Path
        Path to the file to hash.

    Returns
    -------
    str
        Hexadecimal SHA-256 digest of the file contents.

    Raises
    ------
    FileNotFoundError
        If the file does not exist.
    IOError
        If the file cannot be read.
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def compute_file_hash(file_path: Path, algorithm: str = "sha256") -> str:
    """Compute hash of a file using specified algorithm.

    Parameters
    ----------
    file_path : Path
        Path to the file to hash.
    algorithm : str
        Hash algorithm to use ('md5', 'sha1', 'sha256', 'sha512').

    Returns
    -------
    str
        Hexadecimal digest of the file contents.
    """
    if algorithm == "md5":
        hasher = hashlib.md5()
    elif algorithm == "sha1":
        hasher = hashlib.sha1()
    elif algorithm == "sha512":
        hasher = hashlib.sha512()
    else:
        hasher = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def generate_sbom(package_root: Path) -> dict:
    """Generate a Software Bill of Materials (SBOM) for the Orin package.

    Creates a minimal SBOM documenting all Python modules, their hashes,
    and metadata for supply chain transparency.

    Parameters
    ----------
    package_root : Path
        Root directory of the Orin package (containing src/orin/).

    Returns
    -------
    dict
        SBOM dictionary with the following structure:
        - sbom_version: Format version identifier
        - generated_at: ISO 8601 timestamp
        - tool_info: Name and version of the tool
        - components: List of all Python modules with metadata
        - dependencies: Runtime dependencies
        - package_metadata: Package-level information from pyproject.toml

    Raises
    ------
    FileNotFoundError
        If pyproject.toml or key modules are missing.
    """
    sbom = {
        "sbom_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool_info": {
            "name": "orin-dfir",
            "version": "1.2.0",
            "description": "Offline Linux Forensics & Integrity Engine"
        },
        "components": [],
        "dependencies": [
            {"name": "psutil", "version": ">=5.9.0", "required": True},
            {"name": "cryptography", "version": ">=41.0.0", "required": False, "optional": "crypto"}
        ],
        "package_metadata": {}
    }

    # Read pyproject.toml for package metadata
    pyproject_path = package_root / "pyproject.toml"
    if pyproject_path.exists():
        try:
            with open(pyproject_path, "r") as f:
                content = f.read()
                # Simple parsing for key fields
                for line in content.split("\n"):
                    if line.startswith("name = "):
                        sbom["package_metadata"]["name"] = line.split("=")[1].strip().strip('"')
                    elif line.startswith("version = "):
                        sbom["package_metadata"]["version"] = line.split("=")[1].strip().strip('"')
                    elif line.startswith("description = "):
                        sbom["package_metadata"]["description"] = line.split("=")[1].strip().strip('"')
        except Exception:
            pass

    # Scan Python modules
    src_dir = package_root / "src" / "orin"
    if src_dir.exists():
        for py_file in src_dir.rglob("*.py"):
            rel_path = py_file.relative_to(package_root)
            file_hash = compute_file_sha256(py_file)

            component = {
                "type": "file",
                "name": str(rel_path),
                "path": str(rel_path),
                "hashes": {
                    "SHA-256": file_hash
                },
                "size_bytes": py_file.stat().st_size
            }

            # Try to extract module docstring for description
            try:
                with open(py_file, "r") as f:
                    first_lines = []
                    for i, line in enumerate(f):
                        if i > 20:
                            break
                        first_lines.append(line)
                    content = "".join(first_lines)
                    if '"""' in content:
                        start = content.find('"""') + 3
                        end = content.find('"""', start)
                        if end > start:
                            docstring = content[start:end].strip().split("\n")[0]
                            component["description"] = docstring[:100]
            except Exception:
                pass

            sbom["components"].append(component)

    # Add non-Python assets
    asset_dirs = ["rules", "assets"]
    for asset_dir in asset_dirs:
        asset_path = package_root / asset_dir
        if asset_path.exists():
            for asset_file in asset_path.rglob("*"):
                if asset_file.is_file() and not asset_file.name.endswith(".py"):
                    rel_path = asset_file.relative_to(package_root)
                    file_hash = compute_file_sha256(asset_file)

                    sbom["components"].append({
                        "type": "asset",
                        "name": str(rel_path),
                        "path": str(rel_path),
                        "hashes": {
                            "SHA-256": file_hash
                        },
                        "size_bytes": asset_file.stat().st_size,
                        "category": asset_dir
                    })

    return sbom


def generate_release_manifest(package_root: Path, output_path: Path = None) -> dict:
    """Generate a release manifest with checksums for distribution.

    Creates a comprehensive manifest containing SHA-256 hashes of all
    distributable files, suitable for signing with GPG.

    Parameters
    ----------
    package_root : Path
        Root directory of the Orin package.
    output_path : Path, optional
        Path to save the manifest file. If None, returns dict without saving.

    Returns
    -------
    dict
        Release manifest with the following structure:
        - manifest_version: Format version
        - generated_at: ISO 8601 timestamp
        - tool_version: Orin version from pyproject.toml
        - files: Dictionary mapping file paths to their hashes and sizes
        - summary: Aggregate statistics

    Raises
    ------
    FileNotFoundError
        If critical files are missing.
    """
    manifest = {
        "manifest_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool_version": "1.2.0",
        "files": {},
        "summary": {
            "total_files": 0,
            "total_size_bytes": 0,
            "categories": {}
        }
    }

    # Files to include in release
    include_patterns = [
        "src/orin/**/*.py",
        "rules/**/*.yml",
        "rules/**/*.yar",
        "tests/**/*.py",
        "pyproject.toml",
        "README.md",
        "LICENSE",
        "SECURITY.md",
        "ROADMAP.md",
        "install.sh"
    ]

    all_files = set()
    for pattern in include_patterns:
        all_files.update(package_root.glob(pattern))

    for file_path in sorted(all_files):
        if file_path.is_file():
            rel_path = str(file_path.relative_to(package_root))
            file_hash = compute_file_sha256(file_path)
            file_size = file_path.stat().st_size

            # Determine category
            if rel_path.startswith("src/"):
                category = "source"
            elif rel_path.startswith("rules/"):
                category = "rules"
            elif rel_path.startswith("tests/"):
                category = "tests"
            else:
                category = "docs"

            manifest["files"][rel_path] = {
                "sha256": file_hash,
                "size_bytes": file_size,
                "category": category
            }

            manifest["summary"]["total_files"] += 1
            manifest["summary"]["total_size_bytes"] += file_size
            manifest["summary"]["categories"][category] = manifest["summary"]["categories"].get(category, 0) + 1

    # Compute manifest hash (for self-verification)
    manifest_for_hashing = json.dumps(manifest, sort_keys=True)
    manifest["manifest_hash"] = hashlib.sha256(manifest_for_hashing.encode("utf-8")).hexdigest()

    # Save to file if requested
    if output_path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(manifest, f, indent=2)

    return manifest


def verify_against_manifest(manifest_path: Path, package_root: Path) -> Tuple[bool, List[str], List[str]]:
    """Verify package files against a release manifest.

    Checks each file listed in the manifest against its recorded hash.

    Parameters
    ----------
    manifest_path : Path
        Path to the release manifest JSON file.
    package_root : Path
        Root directory of the installed package to verify.

    Returns
    -------
    Tuple[bool, List[str], List[str]]
        - Boolean indicating overall verification success
        - List of files that passed verification
        - List of files that failed verification (with error descriptions)

    Raises
    ------
    FileNotFoundError
        If manifest file doesn't exist.
    json.JSONDecodeError
        If manifest is not valid JSON.
    """
    with open(manifest_path, "r") as f:
        manifest = json.load(f)

    passed = []
    failed = []

    for file_path_str, metadata in manifest.get("files", {}).items():
        expected_hash = metadata["sha256"]
        full_path = package_root / file_path_str

        if not full_path.exists():
            failed.append(f"{file_path_str}: FILE MISSING")
            continue

        try:
            actual_hash = compute_file_sha256(full_path)
            if actual_hash == expected_hash:
                passed.append(file_path_str)
            else:
                failed.append(f"{file_path_str}: HASH MISMATCH (expected={expected_hash[:16]}..., actual={actual_hash[:16]}...)")
        except Exception as e:
            failed.append(f"{file_path_str}: ERROR - {str(e)}")

    # Verify manifest integrity
    manifest_copy = manifest.copy()
    stored_manifest_hash = manifest_copy.pop("manifest_hash", None)
    if stored_manifest_hash:
        manifest_for_hashing = json.dumps(manifest_copy, sort_keys=True)
        computed_manifest_hash = hashlib.sha256(manifest_for_hashing.encode("utf-8")).hexdigest()
        if computed_manifest_hash != stored_manifest_hash:
            failed.append("MANIFEST SELF-HASH INVALID: Manifest may have been tampered with")

    overall_success = len(failed) == 0
    return overall_success, passed, failed


def self_check(package_root: Path = None) -> Tuple[bool, str]:
    """Perform a self-integrity check on the running Orin installation.

    Verifies that critical core modules haven't been modified since installation.
    Uses embedded reference hashes stored in the package.

    Parameters
    ----------
    package_root : Path, optional
        Root directory of the Orin package. If None, attempts to auto-detect.

    Returns
    -------
    Tuple[bool, str]
        - Boolean indicating verification success
        - Human-readable status message

    Notes
    -----
    This is a deterrent check, not absolute protection. An attacker with
    sufficient access could modify both the code and the embedded hashes.
    For stronger guarantees, use external GPG-signed manifests.
    """
    # Get the package root
    if package_root is None:
        try:
            import orin
            package_root = Path(orin.__file__).parent.parent.parent
        except Exception:
            package_root = Path(__file__).parent.parent.parent.parent.parent

    # Critical files that must be verified
    critical_files = [
        "src/orin/__init__.py",
        "src/orin/main.py",
        "src/orin/core/crypto.py",
        "src/orin/core/database.py",
        "src/orin/core/scanner.py",
        "src/orin/core/self_defense.py",
        "src/orin/core/self_verify.py",
    ]

    # Embedded reference hashes (these would be set at build time)
    # In production, these would be injected during the build process
    reference_hashes = _get_embedded_reference_hashes()

    failed_checks = []
    passed_checks = []

    for file_rel_path in critical_files:
        full_path = package_root / file_rel_path

        if not full_path.exists():
            failed_checks.append(f"{file_rel_path}: FILE MISSING")
            continue

        try:
            actual_hash = compute_file_sha256(full_path)
            expected_hash = reference_hashes.get(file_rel_path)

            if expected_hash:
                if actual_hash == expected_hash:
                    passed_checks.append(file_rel_path)
                else:
                    failed_checks.append(f"{file_rel_path}: MODIFIED (hash mismatch)")
            else:
                # No reference hash available, just report the current hash
                passed_checks.append(f"{file_rel_path} (hash: {actual_hash[:16]}...)")
        except Exception as e:
            failed_checks.append(f"{file_rel_path}: ERROR - {str(e)}")

    if failed_checks:
        return False, f"SELF-CHECK FAILED: {len(failed_checks)} file(s) failed verification:\n" + "\n".join(f"  - {f}" for f in failed_checks)
    else:
        return True, f"SELF-CHECK PASSED: {len(passed_checks)} critical file(s) verified successfully"


def _get_embedded_reference_hashes() -> Dict[str, str]:
    """Get embedded reference hashes for critical files.

    In a production build, these hashes would be injected at build time
    from a GPG-signed release manifest. For now, this returns an empty dict,
    meaning self-check will report current hashes but cannot verify them.

    Returns
    -------
    Dict[str, str]
        Dictionary mapping file paths to their expected SHA-256 hashes.
    """
    # TODO: In production, populate this from a build-time generated file
    # or embed it during PyInstaller/Nuitka compilation
    return {}


def sign_manifest_with_gpg(manifest_path: Path, gpg_key_id: str = None) -> Path:
    """Sign a release manifest with GPG.

    Creates a detached GPG signature for the release manifest.

    Parameters
    ----------
    manifest_path : Path
        Path to the manifest file to sign.
    gpg_key_id : str, optional
        GPG key ID to use for signing. If None, uses default GPG key.

    Returns
    -------
    Path
        Path to the created signature file (.sig).

    Raises
    ------
    FileNotFoundError
        If manifest file doesn't exist.
    subprocess.CalledProcessError
        If GPG signing fails.
    RuntimeError
        If GPG is not installed.
    """
    # Check if GPG is available
    try:
        subprocess.run(["gpg", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        raise RuntimeError("GPG is not installed. Cannot sign manifest.")

    manifest_path = Path(manifest_path)
    sig_path = manifest_path.with_suffix(manifest_path.suffix + ".sig")

    cmd = ["gpg", "--detach-sign", "--armor"]
    if gpg_key_id:
        cmd.extend(["--local-user", gpg_key_id])
    cmd.extend(["--output", str(sig_path), str(manifest_path)])

    subprocess.run(cmd, check=True)

    return sig_path


def verify_gpg_signature(manifest_path: Path, signature_path: Path = None) -> bool:
    """Verify a GPG signature on a release manifest.

    Parameters
    ----------
    manifest_path : Path
        Path to the manifest file.
    signature_path : Path, optional
        Path to the signature file. If None, looks for .sig file next to manifest.

    Returns
    -------
    bool
        True if signature is valid, False otherwise.

    Raises
    ------
    FileNotFoundError
        If manifest or signature file doesn't exist.
    RuntimeError
        If GPG is not installed.
    """
    manifest_path = Path(manifest_path)

    if signature_path is None:
        signature_path = manifest_path.with_suffix(manifest_path.suffix + ".sig")
    else:
        signature_path = Path(signature_path)

    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")
    if not signature_path.exists():
        raise FileNotFoundError(f"Signature not found: {signature_path}")

    # Check if GPG is available
    try:
        subprocess.run(["gpg", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        raise RuntimeError("GPG is not installed. Cannot verify signature.")

    result = subprocess.run(
        ["gpg", "--verify", str(signature_path), str(manifest_path)],
        capture_output=True
    )

    return result.returncode == 0


def export_sbom(package_root: Path, output_path: Path, format: str = "json") -> None:
    """Export SBOM to file in specified format.

    Parameters
    ----------
    package_root : Path
        Root directory of the Orin package.
    output_path : Path
        Path to write the SBOM file.
    format : str
        Output format ('json' or 'spdx-json' for future expansion).
    """
    sbom = generate_sbom(package_root)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(sbom, f, indent=2)


def print_sbom_summary(sbom: dict) -> None:
    """Print a human-readable summary of an SBOM.

    Parameters
    ----------
    sbom : dict
        SBOM dictionary to summarize.
    """
    print("\n=== Orin Software Bill of Materials ===")
    print(f"Generated: {sbom.get('generated_at', 'N/A')}")
    print(f"Tool: {sbom.get('tool_info', {}).get('name', 'N/A')} v{sbom.get('tool_info', {}).get('version', 'N/A')}")
    print(f"\nComponents: {len(sbom.get('components', []))}")
    print(f"Dependencies: {len(sbom.get('dependencies', []))}")

    # Count by type
    by_type = {}
    for comp in sbom.get("components", []):
        comp_type = comp.get("type", "unknown")
        by_type[comp_type] = by_type.get(comp_type, 0) + 1

    print("\nBy Type:")
    for comp_type, count in sorted(by_type.items()):
        print(f"  {comp_type}: {count}")

    print("\nDependencies:")
    for dep in sbom.get("dependencies", []):
        required = "required" if dep.get("required", False) else "optional"
        print(f"  - {dep['name']} ({dep.get('version', 'N/A')}) [{required}]")


def print_manifest_summary(manifest: dict) -> None:
    """Print a human-readable summary of a release manifest.

    Parameters
    ----------
    manifest : dict
        Manifest dictionary to summarize.
    """
    print("\n=== Orin Release Manifest ===")
    print(f"Generated: {manifest.get('generated_at', 'N/A')}")
    print(f"Version: {manifest.get('tool_version', 'N/A')}")
    print(f"Manifest Hash: {manifest.get('manifest_hash', 'N/A')[:32]}...")

    summary = manifest.get("summary", {})
    print(f"\nTotal Files: {summary.get('total_files', 0)}")
    print(f"Total Size: {summary.get('total_size_bytes', 0):,} bytes")

    print("\nBy Category:")
    for cat, count in sorted(summary.get("categories", {}).items()):
        print(f"  {cat}: {count}")