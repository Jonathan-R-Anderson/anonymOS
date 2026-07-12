// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title UpdateRegistry
/// @notice Permissionless, server-less release registry for EpinAnonymOS system and
/// software updates (roadmap/SYSTEM_UPDATE_ROADMAP.md).
///
/// TRUST MODEL — "creator deploys once, everyone else just interacts":
///   * The OS creator DEPLOYS this contract a single time. The deployer is recorded as
///     `creator` for PROVENANCE ONLY and holds NO authority over anyone else's records.
///   * Thereafter ANY account may PUBLISH releases under its OWN address-namespace, and
///     ANYONE may READ / VALIDATE any release with no permission and no gas (view calls
///     via eth_call). There is no admin, no owner-gated publishing, no pause switch.
///   * Each publisher is sovereign over its own (publisher, channel) namespace and can
///     only ever move its own channel FORWARD (monotonic version → anti-rollback).
///
/// HOW THE OS USES IT:
///   * The base OS pins the creator's publisher address; its updater trusts only the
///     creator's (address, "stable") record for system images.
///   * Third-party software publishers use their own address; users opt into those
///     addresses. Same contract, same validate() path, zero central gatekeeper.
///
/// The record stores only HASHES (artifact merkle root + signature hash) — never the
/// payload. Authenticity is proven off-chain by the publisher's Ed25519 signature over
/// the manifest; this registry adds anti-rollback, freshness, and public transparency.
/// Dependency-free so it compiles with a stock solc and deploys on the ZKsync Era EVM
/// path (same as BootIntegrityRegistry).
contract UpdateRegistry {
    struct Release {
        uint64  version;         // monotonic per (publisher, channel) — anti-rollback
        bytes32 artifactRoot;    // SHA-256 merkle root of the signed update bundle
        bytes32 manifestSigHash; // hash of the detached Ed25519 signature (provenance)
        uint64  timestamp;       // block time of publication (freshness)
        bool    revoked;         // publisher-set kill switch for the current release
    }

    /// Provenance only: the deployer. Has NO power over other publishers' records.
    address public immutable creator;

    /// publisher address => keccak256(channel) => latest release.
    mapping(address => mapping(bytes32 => Release)) private _releases;

    /// Optional: a publisher's advertised Ed25519 signing public key (32 bytes), so a
    /// client can fetch the verifying key on-chain as well as pinning it locally.
    mapping(address => bytes32) public signingKey;

    event Published(
        address indexed publisher,
        bytes32 indexed channel,
        uint64 version,
        bytes32 artifactRoot,
        bytes32 manifestSigHash
    );
    event Revoked(address indexed publisher, bytes32 indexed channel, uint64 version);
    event SigningKeySet(address indexed publisher, bytes32 pubkey);

    error NotNewer();      // version must strictly increase for this (publisher, channel)
    error EmptyArtifact(); // artifactRoot may not be zero

    constructor() {
        creator = msg.sender;
    }

    /// Publish (or upgrade) a release under YOUR OWN address for `channel`.
    /// Permissionless: msg.sender IS the publisher identity. Enforces monotonic version
    /// so a publisher can never rewind (or freeze-attack) its own channel.
    function publish(
        bytes32 channel,
        uint64 version,
        bytes32 artifactRoot,
        bytes32 manifestSigHash
    ) external {
        if (artifactRoot == bytes32(0)) revert EmptyArtifact();
        Release storage r = _releases[msg.sender][channel];
        if (version <= r.version) revert NotNewer();
        r.version = version;
        r.artifactRoot = artifactRoot;
        r.manifestSigHash = manifestSigHash;
        r.timestamp = uint64(block.timestamp);
        r.revoked = false;
        emit Published(msg.sender, channel, version, artifactRoot, manifestSigHash);
    }

    /// Advertise your Ed25519 signing public key (optional; local pinning still governs).
    function setSigningKey(bytes32 pubkey) external {
        signingKey[msg.sender] = pubkey;
        emit SigningKeySet(msg.sender, pubkey);
    }

    /// Publisher-only kill switch: mark YOUR current release for `channel` revoked.
    /// Only ever affects msg.sender's own namespace.
    function revoke(bytes32 channel) external {
        Release storage r = _releases[msg.sender][channel];
        r.revoked = true;
        emit Revoked(msg.sender, channel, r.version);
    }

    // ── permissionless reads (validation) — free via eth_call, no account needed ──

    function getRelease(address publisher, bytes32 channel)
        external
        view
        returns (
            uint64 version,
            bytes32 artifactRoot,
            bytes32 manifestSigHash,
            uint64 timestamp,
            bool revoked
        )
    {
        Release storage r = _releases[publisher][channel];
        return (r.version, r.artifactRoot, r.manifestSigHash, r.timestamp, r.revoked);
    }

    /// Convenience validator the updater calls to gate a candidate: true iff
    /// (publisher, channel) currently anchors EXACTLY `artifactRoot`, at `version >=
    /// minVersion`, and is not revoked. The kernel still verifies the Ed25519 signature
    /// locally; this only confirms the on-chain anchor agrees (anti-rollback + freshness).
    function validate(
        address publisher,
        bytes32 channel,
        uint64 minVersion,
        bytes32 artifactRoot
    ) external view returns (bool) {
        Release storage r = _releases[publisher][channel];
        return
            !r.revoked &&
            artifactRoot != bytes32(0) &&
            r.version >= minVersion &&
            r.artifactRoot == artifactRoot;
    }
}
