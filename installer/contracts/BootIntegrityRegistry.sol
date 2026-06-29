// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BootIntegrityRegistry
/// @notice Stores an EpinAnonymOS boot-module hash manifest root and optional
/// per-file content hashes. The contract is dependency-free so it can compile
/// with a stock Solidity compiler and deploy on ZKsync Era's EVM path.
contract BootIntegrityRegistry {
    address public owner;
    bytes32 public systemRoot;
    bytes32 public manifestHash;
    uint64 public fileCount;
    uint64 public version;

    mapping(bytes32 => bytes32) public fileHashes;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event RootUpdated(bytes32 indexed systemRoot, bytes32 indexed manifestHash, uint64 fileCount, uint64 version);
    event FileHashUpdated(bytes32 indexed pathHash, bytes32 indexed contentHash, uint64 version);

    error NotOwner();
    error LengthMismatch();
    error EmptyRoot();
    error EmptyOwner();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(bytes32 initialRoot, bytes32 initialManifestHash, uint64 initialFileCount) {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
        _updateRoot(initialRoot, initialManifestHash, initialFileCount);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert EmptyOwner();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function updateRoot(bytes32 newRoot, bytes32 newManifestHash, uint64 newFileCount) external onlyOwner {
        _updateRoot(newRoot, newManifestHash, newFileCount);
    }

    function setFileHashes(bytes32[] calldata pathHashes, bytes32[] calldata contentHashes) external onlyOwner {
        if (pathHashes.length != contentHashes.length) revert LengthMismatch();
        for (uint256 i = 0; i < pathHashes.length; i++) {
            fileHashes[pathHashes[i]] = contentHashes[i];
            emit FileHashUpdated(pathHashes[i], contentHashes[i], version);
        }
    }

    function getFileHash(bytes32 pathHash) external view returns (bytes32) {
        return fileHashes[pathHash];
    }

    function _updateRoot(bytes32 newRoot, bytes32 newManifestHash, uint64 newFileCount) internal {
        if (newRoot == bytes32(0)) revert EmptyRoot();
        systemRoot = newRoot;
        manifestHash = newManifestHash;
        fileCount = newFileCount;
        version += 1;
        emit RootUpdated(newRoot, newManifestHash, newFileCount, version);
    }
}
