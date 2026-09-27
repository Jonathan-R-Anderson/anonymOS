// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title NodeRegistry — binds a Ethereum wallet to a P2P (Ed25519) node identity
/// and records which facilitation services the node may earn AXON for.
/// @notice The node signs an off-chain REGISTER(chainId, registry, wallet,
/// p2pPublicKey, nodeId, capabilities, nonce) statement that peers/aggregators
/// verify against p2pPublicKey (EVM cannot cheaply verify Ed25519). On-chain we
/// enforce wallet control and p2p-key uniqueness, and store the capabilities
/// bitmap + a privacy-preserving endpoint commitment (important over I2P).
contract NodeRegistry is Ownable {
    // Capability bits — mirror the node's advertised roles.
    uint256 public constant CAP_DHT = 1 << 0;
    uint256 public constant CAP_GATEWAY = 1 << 1;
    uint256 public constant CAP_STORAGE = 1 << 2;
    uint256 public constant CAP_LOADBALANCE = 1 << 3;
    uint256 public constant CAP_DOCKER_WORKER = 1 << 4;
    uint256 public constant CAP_DOCKER_CONTROLLER = 1 << 5;
    uint256 public constant CAP_WITNESS = 1 << 6;

    // AXON additions (roadmap §17.2). NEVER RENUMBER AN EXISTING BIT:
    // internal/facilitation/receipt.go derives the receipt ServiceType index
    // from the bit position, so a renumber silently misattributes every receipt
    // and the node earns nothing while appearing healthy.
    uint256 public constant CAP_RELAY = 1 << 7; // forwards cells at L4
    // CAP_GUARD is a VETO bit. Unset means "never pin me as a guard". Set does
    // NOT make the node eligible: the client computes eligibility from its own
    // measurements (§8.5), because a self-asserted guard flag would let an
    // adversary volunteer for the one position that sees the client's address.
    uint256 public constant CAP_GUARD = 1 << 8;
    uint256 public constant CAP_RENDEZVOUS = 1 << 9;
    uint256 public constant CAP_INTRO = 1 << 10;
    uint256 public constant CAP_BOOTSTRAP = 1 << 11;
    uint256 public constant CAP_EXIT = 1 << 12; // outbound clearnet, opt-in

    // There is deliberately NO CAP_SERVICE and there never will be (§17.1). An
    // on-chain advertisement that a node hosts an anonymous service is a
    // deanonymisation vector with no compensating benefit. A service node that
    // also relays advertises CAP_RELAY and nothing else.

    // Widened from (1 << 7) - 1. Every AXON role bit sat at 1<<7 or above, so
    // every one of them reverted with BadCapabilities against the old value:
    // no relay could advertise an AXON capability at all. This is the one line
    // §17.2 says has to change, and changing it is a REDEPLOY plus
    // re-registration of existing nodes.
    uint256 public constant CAP_ALL = (1 << 13) - 1;

    struct Node {
        address owner; // wallet controlling rewards/stake
        bytes32 nodeId; // keccak256(p2pPublicKey)
        bytes p2pPublicKey; // Ed25519 public key (32 bytes)
        bytes32 endpointCommitment; // hash(endpoint || nodeSecret || epoch) — no raw endpoint on-chain
        uint256 capabilities; // bitmap
        uint64 registeredAt;
        uint64 lastActiveEpoch;
        bool active;
    }

    mapping(bytes32 => Node) private _nodes; // nodeId -> Node
    mapping(bytes32 => bool) public p2pKeyUsed; // keccak256(p2pPublicKey) -> used
    mapping(address => bytes32[]) private _ownerNodes;

    event NodeRegistered(bytes32 indexed nodeId, address indexed owner, uint256 capabilities);
    event NodeUpdated(bytes32 indexed nodeId, uint256 capabilities, bytes32 endpointCommitment);
    event NodeDeactivated(bytes32 indexed nodeId);
    event KeyRotated(bytes32 indexed oldNodeId, bytes32 indexed newNodeId, address indexed owner);
    event ActiveEpochBumped(bytes32 indexed nodeId, uint64 epoch);

    error BadCapabilities();
    error KeyAlreadyRegistered();
    error NodeExists();
    error NotNodeOwner();
    error UnknownNode();
    error BadSignature();

    /// @notice Digest a lightweight node signs to register via a relayer. Binds
    /// the chain + this contract + the registration params so a signature can't be
    /// replayed elsewhere; the owner is RECOVERED from the signature (so it never
    /// has to be trusted from the relayer).
    bytes32 public constant REGISTER_TYPEHASH = keccak256(
        "Register(uint256 chainId,address registry,bytes32 p2pKeyHash,uint256 capabilities,bytes32 endpointCommitment,uint256 nonce)"
    );

    constructor(address initialOwner) Ownable(initialOwner) {}

    modifier onlyNodeOwner(bytes32 nodeId) {
        if (_nodes[nodeId].owner != msg.sender) revert NotNodeOwner();
        _;
    }

    /// @notice Register a node directly (msg.sender becomes the owning wallet).
    /// nodeId is keccak256(p2pPublicKey); capabilities must be a non-empty subset
    /// of CAP_ALL.
    function register(bytes calldata p2pPublicKey, uint256 capabilities, bytes32 endpointCommitment)
        external
        returns (bytes32 nodeId)
    {
        return _register(msg.sender, p2pPublicKey, capabilities, endpointCommitment);
    }

    /// @notice Register via a relayer for a LIGHTWEIGHT node that never sends its
    /// own transactions. The node signs registrationDigest(...) with its wallet
    /// key; anyone (the website's paymaster/relayer) may submit it. The owning
    /// wallet is recovered from the signature, so the relayer is never trusted to
    /// name the owner and cannot pay itself.
    function registerWithSig(
        bytes calldata p2pPublicKey,
        uint256 capabilities,
        bytes32 endpointCommitment,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bytes32 nodeId) {
        bytes32 digest = registrationDigest(p2pPublicKey, capabilities, endpointCommitment, nonce);
        address owner = ecrecover(digest, v, r, s);
        if (owner == address(0)) revert BadSignature();
        return _register(owner, p2pPublicKey, capabilities, endpointCommitment);
    }

    /// @notice The digest a lightweight node signs to register via a relayer.
    function registrationDigest(
        bytes calldata p2pPublicKey,
        uint256 capabilities,
        bytes32 endpointCommitment,
        uint256 nonce
    ) public view returns (bytes32) {
        return keccak256(abi.encode(
            REGISTER_TYPEHASH, block.chainid, address(this),
            keccak256(p2pPublicKey), capabilities, endpointCommitment, nonce
        ));
    }

    function _register(address owner, bytes calldata p2pPublicKey, uint256 capabilities, bytes32 endpointCommitment)
        internal
        returns (bytes32 nodeId)
    {
        if (capabilities == 0 || (capabilities & ~CAP_ALL) != 0) revert BadCapabilities();
        bytes32 keyHash = keccak256(p2pPublicKey);
        if (p2pKeyUsed[keyHash]) revert KeyAlreadyRegistered();
        nodeId = keyHash;
        if (_nodes[nodeId].owner != address(0)) revert NodeExists();
        _nodes[nodeId] = Node({
            owner: owner,
            nodeId: nodeId,
            p2pPublicKey: p2pPublicKey,
            endpointCommitment: endpointCommitment,
            capabilities: capabilities,
            registeredAt: uint64(block.timestamp),
            lastActiveEpoch: 0,
            active: true
        });
        p2pKeyUsed[keyHash] = true;
        _ownerNodes[owner].push(nodeId);
        emit NodeRegistered(nodeId, owner, capabilities);
    }

    /// @notice Update capabilities / endpoint commitment. Node-owner only.
    function updateNode(bytes32 nodeId, uint256 capabilities, bytes32 endpointCommitment)
        external
        onlyNodeOwner(nodeId)
    {
        if (capabilities == 0 || (capabilities & ~CAP_ALL) != 0) revert BadCapabilities();
        Node storage node = _nodes[nodeId];
        node.capabilities = capabilities;
        node.endpointCommitment = endpointCommitment;
        emit NodeUpdated(nodeId, capabilities, endpointCommitment);
    }

    /// @notice Retire a node (stops earning). Node-owner only.
    function deactivate(bytes32 nodeId) external onlyNodeOwner(nodeId) {
        _nodes[nodeId].active = false;
        emit NodeDeactivated(nodeId);
    }

    /// @notice Rotate to a new p2p key (new nodeId), keeping the same owner and
    /// capabilities; the old node is retired. Node-owner only.
    function rotateKey(bytes32 oldNodeId, bytes calldata newP2pKey, bytes32 endpointCommitment)
        external
        onlyNodeOwner(oldNodeId)
        returns (bytes32 newNodeId)
    {
        bytes32 keyHash = keccak256(newP2pKey);
        if (p2pKeyUsed[keyHash]) revert KeyAlreadyRegistered();
        Node storage old = _nodes[oldNodeId];
        newNodeId = keyHash;
        _nodes[newNodeId] = Node({
            owner: old.owner,
            nodeId: newNodeId,
            p2pPublicKey: newP2pKey,
            endpointCommitment: endpointCommitment,
            capabilities: old.capabilities,
            registeredAt: uint64(block.timestamp),
            lastActiveEpoch: old.lastActiveEpoch,
            active: true
        });
        p2pKeyUsed[keyHash] = true;
        old.active = false;
        _ownerNodes[old.owner].push(newNodeId);
        emit KeyRotated(oldNodeId, newNodeId, old.owner);
    }

    /// @notice Record that a node was active in `epoch`. Callable by an
    /// authorized epoch settler later; for now the node owner may set it.
    function bumpActiveEpoch(bytes32 nodeId, uint64 epoch) external onlyNodeOwner(nodeId) {
        _nodes[nodeId].lastActiveEpoch = epoch;
        emit ActiveEpochBumped(nodeId, epoch);
    }

    // --- views ---------------------------------------------------------------

    function getNode(bytes32 nodeId) external view returns (Node memory) {
        if (_nodes[nodeId].owner == address(0)) revert UnknownNode();
        return _nodes[nodeId];
    }

    function isRegistered(bytes32 nodeId) external view returns (bool) {
        return _nodes[nodeId].owner != address(0);
    }

    function nodesOf(address owner) external view returns (bytes32[] memory) {
        return _ownerNodes[owner];
    }

    function hasCapability(bytes32 nodeId, uint256 cap) external view returns (bool) {
        Node storage node = _nodes[nodeId];
        return node.active && (node.capabilities & cap) == cap;
    }
}
