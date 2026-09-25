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
Test suite for orin.core.agent_signing module.

Tests cover:
1. Agent script signing functionality
2. Signature verification (valid and tampered)
3. Bundle save/load operations
4. Agent extraction after verification
5. GPG signature integration
6. AgentSigner class interface
7. Error handling and edge cases
"""
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from orin.core.agent_signing import (
    _validate_secret,
    compute_agent_hash,
    sign_agent_script,
    verify_agent_signature,
    save_signed_bundle,
    load_signed_bundle,
    extract_verified_agent,
    generate_agent_manifest,
    sign_bundle_with_gpg,
    verify_gpg_signature_on_bundle,
    AgentSigner,
    SUPPORTED_ALGORITHMS,
    DEFAULT_ALGORITHM,
    _MIN_SECRET_LENGTH
)


class TestSecretValidation:
    """Tests for secret key validation."""

    def test_valid_secret(self):
        """Valid secret should not raise."""
        _validate_secret("secure-passphrase-123")

    def test_short_secret_raises(self):
        """Short secret should raise ValueError."""
        with pytest.raises(ValueError, match="too short"):
            _validate_secret("short")

    def test_minimum_length_secret(self):
        """Secret at minimum length should pass."""
        _validate_secret("123456789012")  # Exactly 12 chars

    def test_one_below_minimum_raises(self):
        """Secret one char below minimum should fail."""
        with pytest.raises(ValueError):
            _validate_secret("12345678901")  # 11 chars


class TestAgentHashComputation:
    """Tests for agent hash computation."""

    def test_compute_sha256_hash(self, tmp_path):
        """Compute SHA256 hash of a file."""
        agent_file = tmp_path / "agent.py"
        agent_file.write_text("#!/usr/bin/env python3\nprint('hello')\n")

        hash_result = compute_agent_hash(agent_file, algorithm="sha256")

        assert len(hash_result) == 64  # SHA256 hex length
        assert all(c in '0123456789abcdef' for c in hash_result)

    def test_compute_sha512_hash(self, tmp_path):
        """Compute SHA512 hash of a file."""
        agent_file = tmp_path / "agent.py"
        agent_file.write_text("#!/usr/bin/env python3\nprint('hello')\n")

        hash_result = compute_agent_hash(agent_file, algorithm="sha512")

        assert len(hash_result) == 128  # SHA512 hex length

    def test_unsupported_algorithm_raises(self, tmp_path):
        """Unsupported algorithm should raise ValueError."""
        agent_file = tmp_path / "agent.py"
        agent_file.write_text("content")

        with pytest.raises(ValueError, match="Unsupported algorithm"):
            compute_agent_hash(agent_file, algorithm="md5")

    def test_missing_file_raises(self, tmp_path):
        """Missing file should raise FileNotFoundError."""
        non_existent = tmp_path / "missing.py"

        with pytest.raises(FileNotFoundError):
            compute_agent_hash(non_existent)

    def test_hash_deterministic(self, tmp_path):
        """Same file should produce same hash."""
        agent_file = tmp_path / "agent.py"
        content = "#!/usr/bin/env python3\nprint('test')\n"
        agent_file.write_text(content)

        hash1 = compute_agent_hash(agent_file)
        hash2 = compute_agent_hash(agent_file)

        assert hash1 == hash2


class TestAgentSigning:
    """Tests for agent script signing."""

    def test_sign_agent_script(self, tmp_path):
        """Sign an agent script successfully."""
        agent_file = tmp_path / "remote_agent.py"
        agent_file.write_text("#!/usr/bin/env python3\nprint('telemetry')\n")

        bundle = sign_agent_script(
            agent_file,
            secret_key="secure-signing-key-123"
        )

        assert "version" in bundle
        assert "signed_at" in bundle
        assert "agent_name" in bundle
        assert bundle["agent_name"] == "remote_agent.py"
        assert "agent_hash" in bundle
        assert "signature" in bundle
        assert "content" in bundle
        assert bundle["content"] == agent_file.read_text()

    def test_sign_with_metadata(self, tmp_path):
        """Sign agent with custom metadata."""
        agent_file = tmp_path / "agent.py"
        agent_file.write_text("content")

        metadata = {"author": "test", "version": "1.0"}
        bundle = sign_agent_script(
            agent_file,
            secret_key="secure-key-here-123",
            metadata=metadata
        )

        assert bundle["metadata"] == metadata

    def test_sign_nonexistent_file_raises(self, tmp_path):
        """Signing nonexistent file should raise."""
        with pytest.raises(FileNotFoundError):
            sign_agent_script(
                tmp_path / "missing.py",
                secret_key="secure-key-here-123"
            )

    def test_sign_short_key_raises(self, tmp_path):
        """Signing with short key should raise."""
        agent_file = tmp_path / "agent.py"
        agent_file.write_text("content")

        with pytest.raises(ValueError, match="too short"):
            sign_agent_script(agent_file, secret_key="short")


class TestSignatureVerification:
    """Tests for signature verification."""

    @pytest.fixture
    def signed_bundle(self, tmp_path):
        """Create a valid signed bundle for testing."""
        agent_file = tmp_path / "agent.py"
        agent_file.write_text("#!/usr/bin/env python3\nprint('verified')\n")

        return sign_agent_script(
            agent_file,
            secret_key="verification-key-123"
        )

    def test_verify_valid_signature(self, signed_bundle):
        """Valid signature should verify successfully."""
        is_valid, message = verify_agent_signature(
            signed_bundle,
            secret_key="verification-key-123"
        )

        assert is_valid is True
        assert "verified successfully" in message

    def test_verify_wrong_key_fails(self, signed_bundle):
        """Wrong key should fail verification."""
        is_valid, message = verify_agent_signature(
            signed_bundle,
            secret_key="wrong-key-here-123"
        )

        assert is_valid is False
        assert "tampered" in message

    def test_verify_tampered_content_fails(self, signed_bundle):
        """Tampered content should fail verification."""
        # Tamper with content
        signed_bundle["content"] = signed_bundle["content"] + "\n# TAMPERED"

        is_valid, message = verify_agent_signature(
            signed_bundle,
            secret_key="verification-key-123"
        )

        assert is_valid is False
        assert "hash mismatch" in message.lower() or "tampered" in message

    def test_verify_missing_fields_fails(self):
        """Bundle missing required fields should fail."""
        incomplete_bundle = {"version": "1.0"}  # Missing content, signature, hash

        is_valid, message = verify_agent_signature(
            incomplete_bundle,
            secret_key="verification-key-123"
        )

        assert is_valid is False
        assert "missing" in message

    def test_verify_short_key_raises(self, signed_bundle):
        """Short verification key should raise."""
        with pytest.raises(ValueError, match="too short"):
            verify_agent_signature(signed_bundle, secret_key="short")


class TestBundleSaveLoad:
    """Tests for bundle persistence."""

    def test_save_and_load_bundle(self, tmp_path):
        """Save and load a bundle round-trip."""
        agent_file = tmp_path / "agent.py"
        agent_file.write_text("content")

        bundle = sign_agent_script(
            agent_file,
            secret_key="save-load-key-123"
        )

        bundle_path = tmp_path / "bundle.json"
        save_signed_bundle(bundle, bundle_path)

        loaded = load_signed_bundle(bundle_path)

        assert loaded == bundle

    def test_load_nonexistent_file_raises(self, tmp_path):
        """Loading nonexistent file should raise."""
        with pytest.raises(FileNotFoundError):
            load_signed_bundle(tmp_path / "missing.json")


class TestAgentExtraction:
    """Tests for verified agent extraction."""

    @pytest.fixture
    def signed_bundle(self, tmp_path):
        """Create a valid signed bundle."""
        agent_file = tmp_path / "agent.py"
        agent_file.write_text("#!/usr/bin/env python3\nextract me\n")
        return sign_agent_script(agent_file, secret_key="extract-key-123")

    def test_extract_without_save(self, signed_bundle):
        """Extract agent without saving to file."""
        is_valid, message, content = extract_verified_agent(
            signed_bundle,
            secret_key="extract-key-123"
        )

        assert is_valid is True
        assert content is not None
        assert "extract me" in content

    def test_extract_with_save(self, signed_bundle, tmp_path):
        """Extract and save agent to file."""
        output_path = tmp_path / "extracted_agent.py"

        is_valid, message, content = extract_verified_agent(
            signed_bundle,
            secret_key="extract-key-123",
            output_path=output_path
        )

        assert is_valid is True
        assert output_path.exists()
        assert output_path.read_text() == content

    def test_extract_invalid_bundle_fails(self, signed_bundle):
        """Extracting invalid bundle should fail."""
        signed_bundle["signature"] = "invalid_signature"

        is_valid, message, content = extract_verified_agent(
            signed_bundle,
            secret_key="extract-key-123"
        )

        assert is_valid is False
        assert content is None


class TestAgentManifest:
    """Tests for multi-agent manifest generation."""

    def test_generate_manifest_single_agent(self, tmp_path):
        """Generate manifest for single agent."""
        agent_file = tmp_path / "agent.py"
        agent_file.write_text("content")

        manifest = generate_agent_manifest(
            [agent_file],
            secret_key="manifest-key-123"
        )

        assert "manifest_version" in manifest
        assert "generated_at" in manifest
        assert "agents" in manifest
        assert len(manifest["agents"]) == 1
        assert manifest["agents"][0]["name"] == "agent.py"
        assert "manifest_hash" in manifest

    def test_generate_manifest_multiple_agents(self, tmp_path):
        """Generate manifest for multiple agents."""
        agent1 = tmp_path / "agent1.py"
        agent2 = tmp_path / "agent2.py"
        agent1.write_text("content1")
        agent2.write_text("content2")

        manifest = generate_agent_manifest(
            [agent1, agent2],
            secret_key="manifest-key-123"
        )

        assert len(manifest["agents"]) == 2

    def test_generate_manifest_skips_missing(self, tmp_path):
        """Manifest generation should skip missing files."""
        existing = tmp_path / "exists.py"
        existing.write_text("content")
        missing = tmp_path / "missing.py"

        manifest = generate_agent_manifest(
            [existing, missing],
            secret_key="manifest-key-123"
        )

        assert len(manifest["agents"]) == 1

    def test_generate_manifest_saves_file(self, tmp_path):
        """Manifest should save to file when path provided."""
        agent_file = tmp_path / "agent.py"
        agent_file.write_text("content")
        output_path = tmp_path / "manifest.json"

        manifest = generate_agent_manifest(
            [agent_file],
            secret_key="manifest-key-123",
            output_path=output_path
        )

        assert output_path.exists()
        with open(output_path) as f:
            saved = json.load(f)
        assert saved == manifest


class TestGPGIntegration:
    """Tests for GPG signature integration."""

    def test_gpg_not_installed_raises(self, tmp_path):
        """Should raise RuntimeError if GPG not available."""
        bundle_path = tmp_path / "bundle.json"
        bundle_path.write_text("{}")

        with patch('subprocess.run', side_effect=FileNotFoundError()):
            with pytest.raises(RuntimeError, match="GPG is not installed"):
                sign_bundle_with_gpg(bundle_path)

    def test_verify_gpg_missing_bundle_raises(self, tmp_path):
        """Verifying missing bundle should raise."""
        with pytest.raises(FileNotFoundError):
            verify_gpg_signature_on_bundle(tmp_path / "missing.json")


class TestAgentSignerClass:
    """Tests for AgentSigner high-level interface."""

    def test_init_valid(self):
        """Initialize AgentSigner with valid parameters."""
        signer = AgentSigner(secret_key="signer-key-123")
        assert signer.secret_key == "signer-key-123"
        assert signer.algorithm == DEFAULT_ALGORITHM

    def test_init_custom_algorithm(self):
        """Initialize with custom algorithm."""
        signer = AgentSigner(
            secret_key="signer-key-123",
            algorithm="sha512"
        )
        assert signer.algorithm == "sha512"

    def test_init_invalid_algorithm_raises(self):
        """Invalid algorithm should raise."""
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            AgentSigner(secret_key="signer-key-123", algorithm="md5")

    def test_init_short_key_raises(self):
        """Short key should raise."""
        with pytest.raises(ValueError, match="too short"):
            AgentSigner(secret_key="short")

    def test_sign_method(self, tmp_path):
        """Test sign method."""
        agent_file = tmp_path / "agent.py"
        agent_file.write_text("content")

        signer = AgentSigner(secret_key="signer-key-123")
        bundle = signer.sign(agent_file)

        assert "signature" in bundle

    def test_verify_method(self, tmp_path):
        """Test verify method."""
        agent_file = tmp_path / "agent.py"
        agent_file.write_text("content")

        signer = AgentSigner(secret_key="signer-key-123")
        bundle = signer.sign(agent_file)
        is_valid, message = signer.verify(bundle)

        assert is_valid is True

    def test_save_load_methods(self, tmp_path):
        """Test save and load methods."""
        agent_file = tmp_path / "agent.py"
        agent_file.write_text("content")
        bundle_path = tmp_path / "bundle.json"

        signer = AgentSigner(secret_key="signer-key-123")
        bundle = signer.sign(agent_file)
        signer.save(bundle, bundle_path)
        loaded = signer.load(bundle_path)

        assert loaded == bundle

    def test_extract_method(self, tmp_path):
        """Test extract method."""
        agent_file = tmp_path / "agent.py"
        agent_file.write_text("extracted content")

        signer = AgentSigner(secret_key="signer-key-123")
        bundle = signer.sign(agent_file)
        is_valid, message, content = signer.extract(bundle)

        assert is_valid is True
        assert "extracted content" in content


class TestIntegrationWithRealAgent:
    """Integration tests using the actual remote_agent.py."""

    def test_sign_real_remote_agent(self):
        """Sign the actual remote_agent.py script."""
        agent_path = Path(__file__).parent.parent / "src" / "orin" / "collectors" / "remote_agent.py"

        if not agent_path.exists():
            pytest.skip("remote_agent.py not found")

        bundle = sign_agent_script(
            agent_path,
            secret_key="integration-test-key-123"
        )

        assert bundle["agent_name"] == "remote_agent.py"
        assert len(bundle["content"]) > 0

        # Verify immediately after signing
        is_valid, message = verify_agent_signature(
            bundle,
            secret_key="integration-test-key-123"
        )

        assert is_valid is True

    def test_tamper_detection_on_real_agent(self, tmp_path):
        """Verify tamper detection works on real agent."""
        agent_path = Path(__file__).parent.parent / "src" / "orin" / "collectors" / "remote_agent.py"

        if not agent_path.exists():
            pytest.skip("remote_agent.py not found")

        bundle = sign_agent_script(
            agent_path,
            secret_key="tamper-test-key-123"
        )

        # Tamper with content
        original_content = bundle["content"]
        bundle["content"] = original_content + "\n# MALICIOUS CODE INSERTED"

        is_valid, message = verify_agent_signature(
            bundle,
            secret_key="tamper-test-key-123"
        )

        assert is_valid is False
        assert "tampered" in message.lower() or "mismatch" in message.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])