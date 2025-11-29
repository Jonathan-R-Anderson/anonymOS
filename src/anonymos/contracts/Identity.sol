// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AnonymOSIdentity {
    address public owner;
    bytes32 public userFingerprint;
    bool public isInitialized;

    struct FileRecord {
        string path;
        bytes32 contentHash;
        uint256 timestamp;
    }

    mapping(string => FileRecord) public fileRegistry;
    string[] public filePaths;

    event FingerprintRegistered(bytes32 fingerprint);
    event FileUpdated(string path, bytes32 contentHash);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function registerFingerprint(bytes32 _fingerprint) external onlyOwner {
        require(!isInitialized, "Already initialized");
        userFingerprint = _fingerprint;
        isInitialized = true;
        emit FingerprintRegistered(_fingerprint);
    }

    function updateFileHash(string memory _path, bytes32 _hash) external onlyOwner {
        require(isInitialized, "Fingerprint not registered");
        
        if (fileRegistry[_path].timestamp == 0) {
            filePaths.push(_path);
        }

        fileRegistry[_path] = FileRecord({
            path: _path,
            contentHash: _hash,
            timestamp: block.timestamp
        });

        emit FileUpdated(_path, _hash);
    }

    function getFileHash(string memory _path) external view returns (bytes32) {
        return fileRegistry[_path].contentHash;
    }
}
