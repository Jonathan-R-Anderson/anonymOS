// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title EncryptedAttestationVault
/// @notice Permissionless store of per-install ENCRYPTED attestation records for EpinAnonymOS.
///
/// Each record is opaque ciphertext produced entirely CLIENT-SIDE: the installer derives a key
/// from the user's install password with Argon2id and seals the payload with an AEAD. This
/// contract — and its deployer, and the entire public — only ever see ciphertext. There is no
/// operator key and no recovery path: lose the password, lose the record. That is deliberate; a
/// second key able to read these would turn this back into user tracking.
///
/// The sealed payload is COMPACT (kept small because on-chain bytes cost gas even on an L2): the
/// system-file integrity-manifest ROOT + the boot gatekeeper's IP whitelist + metadata. The full
/// per-file hash list lives locally (encrypted) and is bound to this on-chain root.
///
/// Records are keyed by a client-chosen `id` that the installer derives from the password + a
/// per-install salt (NOT the sender address), so the record is not inherently linked to the
/// throwaway, Tor-funded wallet that pays the gas. First writer of an id claims it; only that
/// address can update it afterwards (prevents a public id from being griefed/overwritten). This
/// links an id to its writer address on-chain — acceptable because that address is a single-use
/// wallet and the payload stays sealed; to update from a different wallet, use a new id.
///
/// Dependency-free / plain EVM so it deploys on any Ethereum L2 (Base / Arbitrum / Optimism / …)
/// or L1. The boot gatekeeper reads a record with a plain `eth_call get(id)` over Tor.
contract EncryptedAttestationVault {
    uint256 public constant MAX_RECORD_BYTES = 8192;

    mapping(bytes32 => bytes) private records;
    mapping(bytes32 => address) public ownerOf;
    mapping(bytes32 => uint64) public versionOf;

    event RecordPut(bytes32 indexed id, address indexed writer, uint64 version, uint256 length);

    error EmptyId();
    error BadLength();
    error NotRecordOwner();

    /// @notice Create or replace the sealed record stored at `id`.
    /// @param id         a secret the user derives from password+salt (only they can address it)
    /// @param ciphertext the client-side-sealed payload (root + whitelist + meta), <= MAX_RECORD_BYTES
    function put(bytes32 id, bytes calldata ciphertext) external {
        if (id == bytes32(0)) revert EmptyId();
        if (ciphertext.length == 0 || ciphertext.length > MAX_RECORD_BYTES) revert BadLength();

        address o = ownerOf[id];
        if (o == address(0)) {
            ownerOf[id] = msg.sender;
        } else if (o != msg.sender) {
            revert NotRecordOwner();
        }

        records[id] = ciphertext;
        uint64 v = versionOf[id] + 1;
        versionOf[id] = v;
        emit RecordPut(id, msg.sender, v, ciphertext.length);
    }

    /// @notice Read the sealed record at `id`. The gatekeeper calls this read-only (eth_call).
    /// Returns empty bytes if nothing is stored — callers MUST fail closed (boot the decoy).
    function get(bytes32 id) external view returns (bytes memory) {
        return records[id];
    }

    /// @notice Whether an id has ever been written (for clients that want to distinguish
    /// "no record" from "empty" without pulling the payload).
    function exists(bytes32 id) external view returns (bool) {
        return ownerOf[id] != address(0);
    }
}
