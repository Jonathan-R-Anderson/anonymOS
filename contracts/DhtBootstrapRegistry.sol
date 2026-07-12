// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title DhtBootstrapRegistry
/// @notice Creator-controlled registry of I2P destinations used to BOOTSTRAP into the
/// EpinAnonymOS Kademlia-over-I2P update/marketplace DHT (roadmap/SYSTEM_UPDATE_ROADMAP.md).
///
/// TRUST MODEL — "only the creator controls it; anyone may register":
///   * The OS creator DEPLOYS and OWNS this contract and is its sole admin (curate/remove
///     spam or stale entries, transfer ownership). Unlike `UpdateRegistry` (permissionless),
///     the creator governs the set here.
///   * ANY node may `register(i2pDest)` to submit its OWN I2P destination and advertise
///     itself as a willing bootstrap peer, and may `deactivate()` itself when leaving.
///   * ANYONE reads the active set (free `view` calls) to get a list of I2P destinations to
///     dial when first joining the DHT — the on-chain seed list, complementing the peer
///     destinations pinned in the image.
///
/// Only the I2P destination + liveness are stored; the DHT itself carries routing/content.
/// Dependency-free so it compiles with stock solc on the ZKsync Era EVM path.
contract DhtBootstrapRegistry {
    struct Node {
        bytes  i2pDest;      // I2P destination (base64) or .b32 address of the bootstrap peer
        uint64 registeredAt; // block time of the latest registration
        bool   active;       // node.deactivate() or owner.remove() clears this
    }

    /// The creator — sole admin of this registry.
    address public owner;

    mapping(address => Node) public nodes;   // registrant address => its bootstrap record
    address[] public nodeList;               // enumerable list of every address ever seen
    mapping(address => bool) private _known; // dedup guard for nodeList

    /// Max I2P destination length accepted (a full base64 destination is ~516 bytes; allow
    /// slack). Bounds calldata + storage cost per entry.
    uint256 public constant MAX_DEST = 640;

    event Registered(address indexed node, bytes i2pDest);
    event Deactivated(address indexed node);
    event Removed(address indexed node);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error BadDestination();
    error EmptyOwner();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // ── open registration (anyone) ────────────────────────────────────────────

    /// Register (or update) YOUR OWN I2P destination as a DHT bootstrap peer.
    function register(bytes calldata i2pDest) external {
        if (i2pDest.length == 0 || i2pDest.length > MAX_DEST) revert BadDestination();
        if (!_known[msg.sender]) {
            _known[msg.sender] = true;
            nodeList.push(msg.sender);
        }
        nodes[msg.sender] = Node({i2pDest: i2pDest, registeredAt: uint64(block.timestamp), active: true});
        emit Registered(msg.sender, i2pDest);
    }

    /// Leave the bootstrap set (your record stays but is marked inactive).
    function deactivate() external {
        nodes[msg.sender].active = false;
        emit Deactivated(msg.sender);
    }

    // ── creator-only governance ────────────────────────────────────────────────

    /// Curate the set: deactivate a spam/stale node. Creator only.
    function remove(address node) external onlyOwner {
        nodes[node].active = false;
        emit Removed(node);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert EmptyOwner();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    // ── permissionless reads (bootstrap) — free via eth_call ───────────────────

    function nodeCount() external view returns (uint256) {
        return nodeList.length;
    }

    function getNode(address node)
        external
        view
        returns (bytes memory i2pDest, uint64 registeredAt, bool active)
    {
        Node storage nd = nodes[node];
        return (nd.i2pDest, nd.registeredAt, nd.active);
    }

    /// Page through registered addresses [start, start+limit) so a bootstrapping client can
    /// pull the seed list without unbounded calldata. Filter `active` client-side via getNode.
    function nodesPage(uint256 start, uint256 limit) external view returns (address[] memory page) {
        uint256 len = nodeList.length;
        if (start >= len) return new address[](0);
        uint256 end = start + limit;
        if (end > len) end = len;
        page = new address[](end - start);
        for (uint256 i = start; i < end; i++) page[i - start] = nodeList[i];
    }
}
