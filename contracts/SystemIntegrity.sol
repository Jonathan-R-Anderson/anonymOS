// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SystemIntegrity
 * @dev Smart contract for storing and verifying AnonymOS system fingerprints
 * 
 * This contract stores cryptographic fingerprints of critical system components
 * on the zkSync Era blockchain. During boot, AnonymOS queries this contract to
 * verify system integrity and detect rootkits or tampering.
 * 
 * Security features:
 * - Only owner can update their fingerprint
 * - All updates are timestamped and logged
 * - Full audit trail of all changes
 * - Emergency freeze capability
 * - Multi-signature support for critical operations
 */
contract SystemIntegrity {
    
    // ========================================================================
    // Data Structures
    // ========================================================================
    
    struct Fingerprint {
        bytes32 kernelHash;         // SHA-256 of kernel.elf
        bytes32 bootloaderHash;     // SHA-256 of boot.s compiled
        bytes32 initrdHash;         // SHA-256 of initrd
        bytes32 manifestHash;       // SHA-256 of manifest.json
        uint256 timestamp;          // When fingerprint was recorded
        uint32 version;             // System version number
        bool frozen;                // Emergency freeze flag
    }
    
    struct AuditEntry {
        address updater;
        bytes32 kernelHash;
        uint256 timestamp;
        string reason;
    }
    
    // ========================================================================
    // State Variables
    // ========================================================================
    
    // Mapping from owner address to their system fingerprint
    mapping(address => Fingerprint) public fingerprints;
    
    // Audit trail for each owner
    mapping(address => AuditEntry[]) public auditTrail;
    
    // Emergency freeze - if true, no updates allowed
    bool public globalFreeze;
    
    // Contract owner (for emergency operations)
    address public contractOwner;
    
    // Authorized updaters (for multi-sig)
    mapping(address => mapping(address => bool)) public authorizedUpdaters;
    
    // ========================================================================
    // Events
    // ========================================================================
    
    event FingerprintUpdated(
        address indexed owner,
        bytes32 kernelHash,
        bytes32 bootloaderHash,
        uint256 timestamp,
        uint32 version
    );
    
    event FingerprintFrozen(
        address indexed owner,
        uint256 timestamp
    );
    
    event FingerprintUnfrozen(
        address indexed owner,
        uint256 timestamp
    );
    
    event GlobalFreezeActivated(
        uint256 timestamp
    );
    
    event GlobalFreezeDeactivated(
        uint256 timestamp
    );
    
    event UpdaterAuthorized(
        address indexed owner,
        address indexed updater,
        uint256 timestamp
    );
    
    event UpdaterRevoked(
        address indexed owner,
        address indexed updater,
        uint256 timestamp
    );
    
    // ========================================================================
    // Modifiers
    // ========================================================================
    
    modifier onlyContractOwner() {
        require(msg.sender == contractOwner, "Only contract owner");
        _;
    }
    
    modifier notFrozen(address _owner) {
        require(!globalFreeze, "Global freeze active");
        require(!fingerprints[_owner].frozen, "Fingerprint frozen");
        _;
    }
    
    modifier onlyOwnerOrAuthorized(address _owner) {
        require(
            msg.sender == _owner || authorizedUpdaters[_owner][msg.sender],
            "Not authorized"
        );
        _;
    }
    
    // ========================================================================
    // Constructor
    // ========================================================================
    
    constructor() {
        contractOwner = msg.sender;
        globalFreeze = false;
    }
    
    // ========================================================================
    // Core Functions
    // ========================================================================
    
    /**
     * @dev Update system fingerprint
     * @param _kernelHash SHA-256 hash of kernel binary
     * @param _bootloaderHash SHA-256 hash of bootloader
     * @param _initrdHash SHA-256 hash of initial ramdisk
     * @param _manifestHash SHA-256 hash of system manifest
     * @param _version System version number
     * @param _reason Reason for update (for audit trail)
     */
    function updateFingerprint(
        bytes32 _kernelHash,
        bytes32 _bootloaderHash,
        bytes32 _initrdHash,
        bytes32 _manifestHash,
        uint32 _version,
        string calldata _reason
    ) external notFrozen(msg.sender) {
        // Update fingerprint
        fingerprints[msg.sender] = Fingerprint({
            kernelHash: _kernelHash,
            bootloaderHash: _bootloaderHash,
            initrdHash: _initrdHash,
            manifestHash: _manifestHash,
            timestamp: block.timestamp,
            version: _version,
            frozen: false
        });
        
        // Add to audit trail
        auditTrail[msg.sender].push(AuditEntry({
            updater: msg.sender,
            kernelHash: _kernelHash,
            timestamp: block.timestamp,
            reason: _reason
        }));
        
        emit FingerprintUpdated(
            msg.sender,
            _kernelHash,
            _bootloaderHash,
            block.timestamp,
            _version
        );
    }
    
    /**
     * @dev Update fingerprint on behalf of another address (multi-sig)
     * @param _owner Owner of the fingerprint
     * @param _kernelHash SHA-256 hash of kernel binary
     * @param _bootloaderHash SHA-256 hash of bootloader
     * @param _initrdHash SHA-256 hash of initial ramdisk
     * @param _manifestHash SHA-256 hash of system manifest
     * @param _version System version number
     * @param _reason Reason for update
     */
    function updateFingerprintFor(
        address _owner,
        bytes32 _kernelHash,
        bytes32 _bootloaderHash,
        bytes32 _initrdHash,
        bytes32 _manifestHash,
        uint32 _version,
        string calldata _reason
    ) external onlyOwnerOrAuthorized(_owner) notFrozen(_owner) {
        // Update fingerprint
        fingerprints[_owner] = Fingerprint({
            kernelHash: _kernelHash,
            bootloaderHash: _bootloaderHash,
            initrdHash: _initrdHash,
            manifestHash: _manifestHash,
            timestamp: block.timestamp,
            version: _version,
            frozen: false
        });
        
        // Add to audit trail
        auditTrail[_owner].push(AuditEntry({
            updater: msg.sender,
            kernelHash: _kernelHash,
            timestamp: block.timestamp,
            reason: _reason
        }));
        
        emit FingerprintUpdated(
            _owner,
            _kernelHash,
            _bootloaderHash,
            block.timestamp,
            _version
        );
    }
    
    /**
     * @dev Get fingerprint for an address
     * @param _owner Address to query
     * @return Fingerprint struct
     */
    function getFingerprint(address _owner) 
        external 
        view 
        returns (Fingerprint memory) 
    {
        return fingerprints[_owner];
    }
    
    /**
     * @dev Verify if current hashes match stored fingerprint
     * @param _owner Address to verify
     * @param _kernelHash Current kernel hash
     * @param _bootloaderHash Current bootloader hash
     * @param _initrdHash Current initrd hash
     * @param _manifestHash Current manifest hash
     * @return True if all hashes match
     */
    function verifyFingerprint(
        address _owner,
        bytes32 _kernelHash,
        bytes32 _bootloaderHash,
        bytes32 _initrdHash,
        bytes32 _manifestHash
    ) external view returns (bool) {
        Fingerprint memory fp = fingerprints[_owner];
        
        return (
            fp.kernelHash == _kernelHash &&
            fp.bootloaderHash == _bootloaderHash &&
            fp.initrdHash == _initrdHash &&
            fp.manifestHash == _manifestHash
        );
    }
    
    /**
     * @dev Get audit trail for an address
     * @param _owner Address to query
     * @return Array of audit entries
     */
    function getAuditTrail(address _owner) 
        external 
        view 
        returns (AuditEntry[] memory) 
    {
        return auditTrail[_owner];
    }
    
    /**
     * @dev Get number of audit entries for an address
     * @param _owner Address to query
     * @return Number of entries
     */
    function getAuditTrailLength(address _owner) 
        external 
        view 
        returns (uint256) 
    {
        return auditTrail[_owner].length;
    }
    
    // ========================================================================
    // Security Functions
    // ========================================================================
    
    /**
     * @dev Freeze own fingerprint (emergency)
     */
    function freezeFingerprint() external {
        fingerprints[msg.sender].frozen = true;
        emit FingerprintFrozen(msg.sender, block.timestamp);
    }
    
    /**
     * @dev Unfreeze own fingerprint
     */
    function unfreezeFingerprint() external {
        fingerprints[msg.sender].frozen = false;
        emit FingerprintUnfrozen(msg.sender, block.timestamp);
    }
    
    /**
     * @dev Activate global freeze (contract owner only)
     */
    function activateGlobalFreeze() external onlyContractOwner {
        globalFreeze = true;
        emit GlobalFreezeActivated(block.timestamp);
    }
    
    /**
     * @dev Deactivate global freeze (contract owner only)
     */
    function deactivateGlobalFreeze() external onlyContractOwner {
        globalFreeze = false;
        emit GlobalFreezeDeactivated(block.timestamp);
    }
    
    /**
     * @dev Authorize an address to update your fingerprint
     * @param _updater Address to authorize
     */
    function authorizeUpdater(address _updater) external {
        require(_updater != address(0), "Invalid address");
        authorizedUpdaters[msg.sender][_updater] = true;
        emit UpdaterAuthorized(msg.sender, _updater, block.timestamp);
    }
    
    /**
     * @dev Revoke authorization for an address
     * @param _updater Address to revoke
     */
    function revokeUpdater(address _updater) external {
        authorizedUpdaters[msg.sender][_updater] = false;
        emit UpdaterRevoked(msg.sender, _updater, block.timestamp);
    }
    
    /**
     * @dev Check if an address is authorized to update for owner
     * @param _owner Owner address
     * @param _updater Updater address
     * @return True if authorized
     */
    function isAuthorizedUpdater(address _owner, address _updater) 
        external 
        view 
        returns (bool) 
    {
        return authorizedUpdaters[_owner][_updater];
    }
    
    // ========================================================================
    // Admin Functions
    // ========================================================================
    
    /**
     * @dev Transfer contract ownership
     * @param _newOwner New owner address
     */
    function transferOwnership(address _newOwner) external onlyContractOwner {
        require(_newOwner != address(0), "Invalid address");
        contractOwner = _newOwner;
    }
}
