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
orin.core.agent_signing – Remote Agent Script Signing & Verification
====================================================================

Provides mechanisms for signing and verifying the integrity of the remote
telemetry agent script before execution on target systems. This ensures
that only trusted, unmodified agent code is deployed during scans.

Features
--------
1. HMAC-SHA256 signing of agent scripts for tamper detection
2. Embedded signature verification before remote execution
3. Support for multiple signature algorithms (SHA256, SHA512)
4. Signature bundle generation and validation
5. Integration with scanner module for automatic verification

Security Considerations
-----------------------
* The signing key must be kept secure and never transmitted to targets
* Signatures provide integrity verification, not confidentiality
* For stronger guarantees, combine with GPG-signed release manifests
* Signature verification occurs locally before SSH transmission
"""
import hashlib
import hmac
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple


#: Minimum passphrase length for HMAC signing key
_MIN_SECRET_LENGTH = 12

#: Supported hash algorithms for agent signing
SUPPORTED_ALGORITHMS = {"sha256", "sha512"}

#: Default algorithm for signing
DEFAULT_ALGORITHM = "sha256"


def _validate_secret(secret_key: str) -> None:
    """Validate the signing secret meets minimum security requirements.

    Parameters
    ----------
    secret_key : str
        The HMAC passphrase to validate.

    Raises
    ------
    ValueError
        If the secret is too short.
    """
    if len(secret_key) < _MIN_SECRET_LENGTH:
        raise ValueError(
            f"Signing passphrase is too short ({len(secret_key)} chars). "
            f"Minimum required: {_MIN_SECRET_LENGTH} characters."
        )


def compute_agent_hash(agent_path: Path, algorithm: str = "sha256") -> str:
    """Compute cryptographic hash of an agent script file.

    Parameters
    ----------
    agent_path : Path
        Path to the agent script file.
    algorithm : str, optional
        Hash algorithm to use ('sha256' or 'sha512').

    Returns
    -------
    str
        Hexadecimal digest of the file contents.

    Raises
    ------
    FileNotFoundError
        If the agent file does not exist.
    ValueError
        If an unsupported algorithm is specified.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm '{algorithm}'. "
            f"Supported: {', '.join(sorted(SUPPORTED_ALGORITHMS))}"
        )

    hasher = hashlib.sha256() if algorithm == "sha256" else hashlib.sha512()

    with open(agent_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)

    return hasher.hexdigest()


def sign_agent_script(
    agent_path: Path,
    secret_key: str,
    algorithm: str = DEFAULT_ALGORITHM,
    metadata: Optional[Dict] = None
) -> Dict:
    """Generate a signed bundle for a remote agent script.

    Creates a signature bundle containing the agent script content,
    HMAC signature, and metadata for integrity verification.

    Parameters
    ----------
    agent_path : Path
        Path to the agent script file to sign.
    secret_key : str
        HMAC passphrase for signing. Must be at least 12 characters.
    algorithm : str, optional
        Hash algorithm for HMAC computation (default: sha256).
    metadata : dict, optional
        Additional metadata to include in the signature bundle.

    Returns
    -------
    dict
        Signature bundle with the following structure:
        - version: Bundle format version
        - signed_at: ISO 8601 timestamp
        - agent_name: Name of the signed agent file
        - agent_hash: SHA256 hash of the agent content
        - algorithm: Hash algorithm used
        - metadata: Optional additional metadata
        - content: The agent script content
        - signature: HMAC-SHA256 signature over content + hash

    Raises
    ------
    ValueError
        If the secret key is too short or algorithm is unsupported.
    FileNotFoundError
        If the agent file does not exist.
    """
    _validate_secret(secret_key)

    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm '{algorithm}'. "
            f"Supported: {', '.join(sorted(SUPPORTED_ALGORITHMS))}"
        )

    agent_path = Path(agent_path)
    if not agent_path.exists():
        raise FileNotFoundError(f"Agent script not found: {agent_path}")

    # Read agent content
    content = agent_path.read_text(encoding="utf-8")

    # Compute content hash
    content_hash = compute_agent_hash(agent_path, algorithm="sha256")

    # Create deterministic message for signing
    message_to_sign = f"{content}:{content_hash}"

    # Compute HMAC signature
    signature = hmac.new(
        secret_key.encode("utf-8"),
        message_to_sign.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    # Build signature bundle
    bundle = {
        "version": "1.0.0",
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "agent_name": agent_path.name,
        "agent_hash": content_hash,
        "algorithm": algorithm,
        "metadata": metadata or {},
        "content": content,
        "signature": signature
    }

    return bundle


def verify_agent_signature(
    bundle: Dict,
    secret_key: str
) -> Tuple[bool, str]:
    """Verify the signature of a signed agent bundle.

    Validates that the agent content has not been tampered with by
    recomputing the HMAC signature and comparing it to the stored value.

    Parameters
    ----------
    bundle : dict
        The signature bundle to verify (as returned by sign_agent_script).
    secret_key : str
        HMAC passphrase used for signing.

    Returns
    -------
    Tuple[bool, str]
        - Boolean indicating verification success
        - Human-readable status message

    Raises
    ------
    ValueError
        If the secret key is too short or bundle is malformed.
    """
    _validate_secret(secret_key)

    # Validate bundle structure
    required_fields = ["version", "content", "signature", "agent_hash"]
    for field in required_fields:
        if field not in bundle:
            return False, f"Invalid bundle: missing '{field}' field"

    content = bundle["content"]
    stored_signature = bundle["signature"]
    stored_hash = bundle["agent_hash"]

    # Verify content hash matches
    computed_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(computed_hash, stored_hash):
        return False, "CRITICAL: Agent content hash mismatch - file may be corrupted or tampered"

    # Recompute signature
    message_to_verify = f"{content}:{stored_hash}"
    computed_signature = hmac.new(
        secret_key.encode("utf-8"),
        message_to_verify.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    # Constant-time comparison
    if not hmac.compare_digest(computed_signature, stored_signature):
        return False, "CRITICAL: Signature verification failed - agent may have been tampered with"

    return True, f"Agent '{bundle.get('agent_name', 'unknown')}' signature verified successfully"


def save_signed_bundle(bundle: Dict, output_path: Path) -> None:
    """Save a signed agent bundle to a JSON file.

    Parameters
    ----------
    bundle : dict
        The signature bundle to save.
    output_path : Path
        Path where the bundle file will be written.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)


def load_signed_bundle(bundle_path: Path) -> Dict:
    """Load a signed agent bundle from a JSON file.

    Parameters
    ----------
    bundle_path : Path
        Path to the bundle file.

    Returns
    -------
    dict
        The loaded signature bundle.

    Raises
    ------
    FileNotFoundError
        If the bundle file does not exist.
    json.JSONDecodeError
        If the file is not valid JSON.
    """
    bundle_path = Path(bundle_path)
    with open(bundle_path, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_verified_agent(
    bundle: Dict,
    secret_key: str,
    output_path: Optional[Path] = None
) -> Tuple[bool, str, Optional[str]]:
    """Verify a bundle and extract the agent content if valid.

    Parameters
    ----------
    bundle : dict
        The signature bundle to verify and extract from.
    secret_key : str
        HMAC passphrase for verification.
    output_path : Path, optional
        If provided, write the verified agent to this path.

    Returns
    -------
    Tuple[bool, str, Optional[str]]
        - Boolean indicating success
        - Status message
        - Agent content if successful, None otherwise
    """
    is_valid, message = verify_agent_signature(bundle, secret_key)

    if not is_valid:
        return False, message, None

    content = bundle["content"]

    if output_path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        message += f" (saved to {output_path})"

    return True, message, content


def generate_agent_manifest(
    agent_paths: list,
    secret_key: str,
    output_path: Optional[Path] = None
) -> Dict:
    """Generate a manifest with signatures for multiple agent scripts.

    Creates a comprehensive manifest documenting all agent scripts,
    their hashes, and signatures for batch verification.

    Parameters
    ----------
    agent_paths : list
        List of paths to agent scripts to include in manifest.
    secret_key : str
        HMAC passphrase for signing.
    output_path : Path, optional
        Path to save the manifest file.

    Returns
    -------
    dict
        Manifest containing all agent signatures and metadata.
    """
    _validate_secret(secret_key)

    manifest = {
        "manifest_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "agents": []
    }

    for agent_path in agent_paths:
        agent_path = Path(agent_path)
        if not agent_path.exists():
            continue

        try:
            bundle = sign_agent_script(agent_path, secret_key)
            manifest["agents"].append({
                "name": agent_path.name,
                "path": str(agent_path),
                "hash": bundle["agent_hash"],
                "signature": bundle["signature"],
                "signed_at": bundle["signed_at"]
            })
        except Exception as e:
            manifest["agents"].append({
                "name": agent_path.name,
                "path": str(agent_path),
                "error": str(e)
            })

    # Compute manifest self-hash
    manifest_for_hashing = json.dumps(manifest, sort_keys=True)
    manifest["manifest_hash"] = hashlib.sha256(
        manifest_for_hashing.encode("utf-8")
    ).hexdigest()

    if output_path:
        save_signed_bundle(manifest, output_path)

    return manifest


def verify_gpg_signature_on_bundle(
    bundle_path: Path,
    signature_path: Optional[Path] = None
) -> bool:
    """Verify a GPG signature on an agent bundle file.

    Parameters
    ----------
    bundle_path : Path
        Path to the bundle file.
    signature_path : Path, optional
        Path to the detached signature file.

    Returns
    -------
    bool
        True if signature is valid, False otherwise.
    """
    bundle_path = Path(bundle_path)

    if signature_path is None:
        signature_path = bundle_path.with_suffix(bundle_path.suffix + ".sig")

    if not bundle_path.exists():
        raise FileNotFoundError(f"Bundle not found: {bundle_path}")
    if not signature_path.exists():
        raise FileNotFoundError(f"Signature not found: {signature_path}")

    try:
        result = subprocess.run(
            ["gpg", "--verify", str(signature_path), str(bundle_path)],
            capture_output=True
        )
        return result.returncode == 0
    except FileNotFoundError:
        raise RuntimeError("GPG is not installed. Cannot verify signature.")


def sign_bundle_with_gpg(
    bundle_path: Path,
    gpg_key_id: Optional[str] = None
) -> Path:
    """Create a GPG signature for an agent bundle file.

    Parameters
    ----------
    bundle_path : Path
        Path to the bundle file to sign.
    gpg_key_id : str, optional
        GPG key ID to use. Uses default key if None.

    Returns
    -------
    Path
        Path to the created signature file.
    """
    bundle_path = Path(bundle_path)

    try:
        subprocess.run(["gpg", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        raise RuntimeError("GPG is not installed. Cannot sign bundle.")

    sig_path = bundle_path.with_suffix(bundle_path.suffix + ".sig")

    cmd = ["gpg", "--detach-sign", "--armor"]
    if gpg_key_id:
        cmd.extend(["--local-user", gpg_key_id])
    cmd.extend(["--output", str(sig_path), str(bundle_path)])

    subprocess.run(cmd, check=True)

    return sig_path


class AgentSigner:
    """High-level interface for agent signing operations.

    Provides a convenient object-oriented interface for signing and
    verifying remote agent scripts with support for key management.

    Parameters
    ----------
    secret_key : str
        HMAC passphrase for signing operations.
    algorithm : str, optional
        Hash algorithm to use (default: sha256).

    Example
    -------
    >>> signer = AgentSigner(secret_key="my-secure-passphrase-here")
    >>> bundle = signer.sign("/path/to/remote_agent.py")
    >>> signer.save(bundle, "/path/to/bundle.json")
    """

    def __init__(self, secret_key: str, algorithm: str = DEFAULT_ALGORITHM):
        _validate_secret(secret_key)
        if algorithm not in SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"Unsupported algorithm '{algorithm}'. "
                f"Supported: {', '.join(sorted(SUPPORTED_ALGORITHMS))}"
            )
        self.secret_key = secret_key
        self.algorithm = algorithm

    def sign(self, agent_path: Path, metadata: Optional[Dict] = None) -> Dict:
        """Sign an agent script.

        Parameters
        ----------
        agent_path : Path
            Path to the agent script.
        metadata : dict, optional
            Additional metadata to include.

        Returns
        -------
        dict
            Signature bundle.
        """
        return sign_agent_script(
            agent_path,
            self.secret_key,
            algorithm=self.algorithm,
            metadata=metadata
        )

    def verify(self, bundle: Dict) -> Tuple[bool, str]:
        """Verify a signature bundle.

        Parameters
        ----------
        bundle : dict
            Bundle to verify.

        Returns
        -------
        Tuple[bool, str]
            Verification result and message.
        """
        return verify_agent_signature(bundle, self.secret_key)

    def save(self, bundle: Dict, output_path: Path) -> None:
        """Save a bundle to file.

        Parameters
        ----------
        bundle : dict
            Bundle to save.
        output_path : Path
            Output file path.
        """
        save_signed_bundle(bundle, output_path)

    def load(self, bundle_path: Path) -> Dict:
        """Load a bundle from file.

        Parameters
        ----------
        bundle_path : Path
            Bundle file path.

        Returns
        -------
        dict
            Loaded bundle.
        """
        return load_signed_bundle(bundle_path)

    def extract(
        self,
        bundle: Dict,
        output_path: Optional[Path] = None
    ) -> Tuple[bool, str, Optional[str]]:
        """Verify and extract agent content.

        Parameters
        ----------
        bundle : dict
            Bundle to extract from.
        output_path : Path, optional
            Where to save extracted content.

        Returns
        -------
        Tuple[bool, str, Optional[str]]
            Result, message, and content.
        """
        return extract_verified_agent(
            bundle,
            self.secret_key,
            output_path=output_path
        )