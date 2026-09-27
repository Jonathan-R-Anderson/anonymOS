// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title AxonRegistry — ownership of the names in ONE namespace, and nothing else.
///
/// Deployed once per namespace; the root registry holds only the label ->
/// registrar mapping. It knows a name, its owner, its expiry, and a 32-byte
/// Ed25519 DomainIdentity. It does NOT know endpoints, services, content, users
/// or lookups (§12.7) — a registry that knew those would be a resolver, and a
/// resolver on chain is a per-lookup public record of who asked for what.
///
/// ACQUISITION (§12.4a). A name is paid for in the network token via exactly two
/// routes and no third:
///
///   PRIMARY    register()  — first issuance, proceeds to the DAO treasury
///   SECONDARY  transfer()  — from the current owner, levied
///
/// THE ANTI-SQUATTING GUARD (§12.4a.2). Per-acquirer counters price the ACT of
/// registering and are defeated by splitting across addresses — §12.4a.1 works
/// that through and it is a negative result, not an oversight. The mechanism that
/// does NOT split is a levy on the EXIT: every resale is a transfer this contract
/// executes, so the levy attaches to the name rather than to anyone's identity
/// and cannot be Sybilled. It decays with holding time, so a squatter flipping
/// within months forfeits most of the spread and a genuine holder selling after
/// years does not.
///
/// What that does NOT stop, stated because it is the case that matters: an
/// adversary who wants to DENY a name rather than profit from it never sells and
/// is untouched by the levy. Against them only cost applies, and cost is a price.
///
/// EVERY POLICY NUMBER HERE IS [NEEDS RESEARCH]. The levy decay in particular
/// decides whether this is a squatting deterrent or a tax on ordinary transfer,
/// and it cannot be picked from an armchair. They are constructor arguments so a
/// deployment states them rather than inheriting a guess.
contract AxonRegistry is Ownable {
    using SafeERC20 for IERC20;

    // ---------------------------------------------------------------- storage
    // Layout is part of the interface, not an implementation detail (§12.5), and
    // MUST be confirmed with `solc --storage-layout` before anything depends on
    // it. The compiler is the authority; this is design intent.

    /// @notice §93.2's machine. ACTIVE is the zero value, so an untouched name
    /// needs no migration and no initialisation.
    enum NameState { ACTIVE, PRUNED, SEIZED, RECYCLABLE }

    struct StateChange {
        NameState state;
        uint64    at;            // block timestamp
        uint256   proposalId;    // the vote that authorised it
        address   previousOwner; // zero unless the name changed hands
    }

    struct Name {
        address owner;        // OwnerIdentity (secp256k1). NEVER on the overlay.
        uint64  expiresAt;
        uint32  version;      // bumped on EVERY mutation. Anti-rollback (§11.7).
        bytes32 domainKey;    // DomainIdentity, Ed25519 public key, verbatim.
        bytes32 resolver;     // 0 = DHT records only (the default).
        bytes32 skeleton;     // confusable class (§11.3.3).
        uint64  registeredAt;
        uint64  acquiredAt;   // reset on transfer: the levy clock (§12.4a.2).
        uint64  keyValidFrom;
        uint256 bond;         // locked at registration, released on transfer/expiry.
        uint8   flags;        // bit0 transferLocked, bit1 revoked
    }

    IERC20  public immutable token;      // the network token (§12.4a)
    address public immutable treasury;   // the DAO
    bytes32 public immutable TLD_NODE;

    uint64  public immutable GRACE_PERIOD;
    uint64  public immutable COMMIT_MIN_AGE;
    uint64  public immutable COMMIT_MAX_AGE;
    uint64  public immutable TERM;

    uint256 public immutable BASE_PRICE;
    uint256 public immutable BOND_PER_NAME;
    /// @notice Levy in basis points at zero holding time.
    uint16  public immutable LEVY_BPS;
    /// @notice Seconds of holding that halve the levy.
    uint64  public immutable LEVY_HALF_LIFE;
    /// @notice Names one account may take per epoch before the surcharge starts.
    uint16  public immutable BURST_FREE;
    uint64  public immutable EPOCH;
    /// @notice Reveals one account may make per block.
    uint16  public immutable REVEALS_PER_BLOCK;
    /// @notice How long a seized name is withheld before it can be re-registered.
    ///
    /// [NEEDS RESEARCH] as a figure. What IS derived is that it cannot be zero
    /// (R-93.3): a name released at the instant of seizure is re-registered by
    /// the seized party from a fresh wallet within a block, and the seizure has
    /// cost them a gas fee and nothing else. The constructor rejects zero.
    uint64  public immutable SEIZE_QUARANTINE;

    mapping(bytes32 => Name)    private _names;       // nameHash -> name
    mapping(bytes32 => address) public  classHolder;  // skeleton -> owner
    mapping(bytes32 => uint256) public  commitments;  // commitment -> timestamp
    mapping(bytes32 => bool)    public  reservedLabel;

    mapping(address => mapping(uint64 => uint16)) public epochTakes;
    mapping(address => mapping(uint256 => uint16)) public blockReveals;

    // ------------------------------------------------- governance (Part X §93)
    /// @notice The DAO Governance contract. Until it is set, NOTHING can be
    /// pruned or seized — which is F-94.1's sequencing ruling expressed as code
    /// rather than as a note. The DAO's voting weight is defined (§94) but three
    /// of its four inputs are not yet measurable and there is no Governance
    /// contract on chain; writing seizure state before one exists would make
    /// "the blockchain is authoritative" mean "whatever one server writes is
    /// authoritative".
    address public governor;

    mapping(bytes32 => NameState) public stateOf;
    /// @notice When a seizure took effect. The quarantine runs from here.
    mapping(bytes32 => uint64)  public seizedAt;
    /// @notice Append-only. Reassignment moves the name; it never rewrites this
    /// (R-93.3): a new owner must be judged on their own content, and a resolver
    /// that could not tell the previous seizure from the new tenancy would
    /// enforce a prune against someone who had nothing to do with it.
    mapping(bytes32 => StateChange[]) private _history;

    uint256 public levyPool;   // the DAO's accumulated take
    uint256 public feePool;    // primary-issuance proceeds

    // ----------------------------------------------------------------- events
    event Committed  (bytes32 indexed commitment, uint256 timestamp);
    event Registered (bytes32 indexed nameHash, address indexed owner,
                      bytes32 skeleton, uint64 expiresAt, uint32 version,
                      uint256 pricePaid, uint256 bondLocked);
    event Transferred(bytes32 indexed nameHash, address indexed from,
                      address indexed to, uint256 salePrice, uint256 levy,
                      uint32 version);
    event Released   (bytes32 indexed nameHash, uint32 version);
    event GovernorSet(address indexed governor);
    event Pruned     (bytes32 indexed nameHash, uint256 indexed proposalId, uint32 version);
    event Seized     (bytes32 indexed nameHash, uint256 indexed proposalId,
                      address indexed previousOwner, uint32 version);
    event Restored   (bytes32 indexed nameHash, uint256 indexed proposalId,
                      address indexed owner, uint32 version);
    event Recyclable (bytes32 indexed nameHash, uint64 at);

    // ----------------------------------------------------------------- errors
    error BadLabel();      error Reserved();      error ClassHeld();
    error NotOwner();      error NotAvailable();  error NoCommit();
    error CommitTooNew();  error CommitTooOld();  error Locked();
    error RevealRateLimited();
    error NotGovernor();   error NoGovernor();    error BadState();
    error Quarantined();   error ZeroQuarantine();

    constructor(
        address initialOwner,
        IERC20  token_,
        address treasury_,
        bytes32 tldNode,
        uint64[6] memory times,   // grace, commitMin, commitMax, term, epoch, seizeQuarantine
        uint256[2] memory money,  // basePrice, bondPerName
        uint16[3] memory limits,  // levyBps, burstFree, revealsPerBlock
        uint64 levyHalfLife
    ) Ownable(initialOwner) {
        token = token_;
        treasury = treasury_;
        TLD_NODE = tldNode;
        GRACE_PERIOD = times[0];
        COMMIT_MIN_AGE = times[1];
        COMMIT_MAX_AGE = times[2];
        TERM = times[3];
        EPOCH = times[4];
        // R-93.3: the quarantine cannot be zero. Refused in the constructor
        // rather than documented, because a deployment that passed zero would
        // look correct and make every seizure a no-op.
        if (times[5] == 0) revert ZeroQuarantine();
        SEIZE_QUARANTINE = times[5];
        BASE_PRICE = money[0];
        BOND_PER_NAME = money[1];
        LEVY_BPS = limits[0];
        BURST_FREE = limits[1];
        REVEALS_PER_BLOCK = limits[2];
        LEVY_HALF_LIFE = levyHalfLife;
    }

    // ------------------------------------------------------------ commit
    function commit(bytes32 commitment) external {
        commitments[commitment] = block.timestamp;
        emit Committed(commitment, block.timestamp);
    }

    // ------------------------------------------------------------ register
    /// @notice PRIMARY acquisition: first issuance, from the DAO.
    /// @dev The caller must have approved `price + BOND_PER_NAME` of the token.
    function register(
        bytes32 nameHash,
        bytes32 skeleton,
        uint8   labelLen,
        bytes32 secret,
        bytes32 domainKey
    ) external returns (uint256 price) {
        // 1. RATE LIMIT FIRST, before any storage is read. A dictionary sweep
        //    must be stopped before it costs a lookup per word — an ordering
        //    that is free here and impossible to retrofit.
        if (REVEALS_PER_BLOCK != 0) {
            uint16 n = blockReveals[msg.sender][block.number];
            if (n >= REVEALS_PER_BLOCK) revert RevealRateLimited();
            blockReveals[msg.sender][block.number] = n + 1;
        }

        // 2. The commitment must exist and be the right age.
        bytes32 c = keccak256(abi.encode(nameHash, msg.sender, secret, domainKey));
        uint256 at = commitments[c];
        if (at == 0) revert NoCommit();
        if (block.timestamp < at + COMMIT_MIN_AGE) revert CommitTooNew();
        if (COMMIT_MAX_AGE != 0 && block.timestamp > at + COMMIT_MAX_AGE) revert CommitTooOld();

        // 3. Availability, counting the grace period AND the governance states.
        //
        // Routed through _available rather than repeating the owner/expiry test
        // here. The direct test was wrong for a seized name: seizure sets
        // `owner` to zero, so `existing.owner != address(0)` is false and the
        // name looked available in the same block it was taken -- which is
        // precisely the re-registration R-93.3's quarantine exists to stop.
        // One predicate, one place, and this is why.
        Name storage existing = _names[nameHash];
        if (!_available(nameHash)) revert NotAvailable();

        // 4. The confusable class. Held by the SAME owner is fine and is the
        //    point: defensive registration of your own variants must be
        //    affordable, or the rule punishes the party it protects.
        address holder = classHolder[skeleton];
        if (holder != address(0) && holder != msg.sender) revert ClassHeld();
        if (reservedLabel[nameHash]) revert Reserved();
        if (labelLen < 3) revert BadLabel();

        // 5. Price, including the burst surcharge.
        price = priceOf(labelLen);
        if (EPOCH != 0) {
            uint64 epoch = uint64(block.timestamp) / EPOCH;
            uint16 taken = epochTakes[msg.sender][epoch] + 1;
            epochTakes[msg.sender][epoch] = taken;
            price = burstSurcharge(price, taken);
        }

        delete commitments[c];

        // 6. Money. Price to the fee pool, bond LOCKED in the contract.
        if (price != 0) {
            token.safeTransferFrom(msg.sender, address(this), price);
            feePool += price;
        }
        if (BOND_PER_NAME != 0) {
            token.safeTransferFrom(msg.sender, address(this), BOND_PER_NAME);
        }

        uint32 v = existing.version + 1;
        _names[nameHash] = Name({
            owner: msg.sender,
            expiresAt: uint64(block.timestamp) + TERM,
            version: v,
            domainKey: domainKey,
            resolver: bytes32(0),
            skeleton: skeleton,
            registeredAt: uint64(block.timestamp),
            acquiredAt: uint64(block.timestamp),
            keyValidFrom: uint64(block.timestamp),
            bond: BOND_PER_NAME,
            flags: 0
        });
        classHolder[skeleton] = msg.sender;

        // A RECYCLABLE name returns to ACTIVE for its new owner. The HISTORY is
        // untouched (R-93.3): the new owner is judged on their own content, and
        // a record a new owner could erase would let a seized party launder a
        // name by re-registering it and clearing the trail.
        if (stateOf[nameHash] != NameState.ACTIVE) {
            stateOf[nameHash] = NameState.ACTIVE;
            seizedAt[nameHash] = 0;
            _history[nameHash].push(StateChange(NameState.ACTIVE, uint64(block.timestamp),
                                                0, address(0)));
        }

        emit Registered(nameHash, msg.sender, skeleton,
                        uint64(block.timestamp) + TERM, v, price, BOND_PER_NAME);
    }

    // ------------------------------------------------------------ transfer
    /// @notice SECONDARY acquisition: from the current owner. THE ONLY path that
    /// moves a name, which is what makes the levy unavoidable (§12.4a.2).
    /// @param salePrice what the buyer pays the seller, in the network token.
    function transfer(bytes32 nameHash, address to, uint256 salePrice)
        external returns (uint256 levy)
    {
        Name storage n = _names[nameHash];
        if (n.owner != msg.sender) revert NotOwner();
        if (block.timestamp >= n.expiresAt) revert NotAvailable();
        if (n.flags & 1 != 0) revert Locked();

        levy = levyFor(salePrice, uint64(block.timestamp) - n.acquiredAt);
        if (levy != 0) {
            // The buyer pays the levy on top; the DAO is paid directly rather
            // than through the seller, so a seller cannot under-report by
            // settling off chain and calling this with salePrice = 0 without
            // also forfeiting the contract's enforcement of the sale.
            token.safeTransferFrom(to, treasury, levy);
            levyPool += levy;
        }
        if (salePrice != 0) {
            token.safeTransferFrom(to, msg.sender, salePrice);
        }

        n.owner = to;
        // The levy clock RESETS. A levy that inherited the previous holder's
        // clock would let a squatter launder the decay by selling to themselves.
        n.acquiredAt = uint64(block.timestamp);
        n.version += 1;
        classHolder[n.skeleton] = to;

        emit Transferred(nameHash, msg.sender, to, salePrice, levy, n.version);
    }

    // ------------------------------------------------------------ release
    /// @notice Give up a name and reclaim its bond.
    /// @dev The name becomes available IMMEDIATELY, without the grace period an
    /// expired name gets. Grace protects an owner who forgot to renew; release
    /// is that owner choosing to let go, and withholding their name for 30 days
    /// afterwards would protect nobody. Re-registration still needs an aged
    /// commitment, so this is the same race as expiry, not a new one.
    function release(bytes32 nameHash) external {
        Name storage n = _names[nameHash];
        if (n.owner != msg.sender) revert NotOwner();
        // R-93.6. release() makes a name available IMMEDIATELY, and the comment
        // above gives the right reason for a VOLUNTARY release. That reasoning
        // INVERTS under governance state: a pruned owner who could release would
        // hand their name straight back to the pool and re-register it from a
        // fresh wallet in the next block, converting a prune into a rename. The
        // two paths must not share code, so this one refuses.
        if (stateOf[nameHash] != NameState.ACTIVE) revert BadState();
        uint256 bond = n.bond;
        delete classHolder[n.skeleton];
        n.owner = address(0);
        n.expiresAt = uint64(block.timestamp);
        n.bond = 0;
        n.version += 1;
        if (bond != 0) token.safeTransfer(msg.sender, bond);
        emit Released(nameHash, n.version);
    }

    // ------------------------------------------------------ governance (§93)

    modifier onlyGovernor() {
        if (governor == address(0)) revert NoGovernor();
        if (msg.sender != governor) revert NotGovernor();
        _;
    }

    /// @notice Point this registry at the DAO Governance contract.
    /// @dev Owner-set once the Governance contract exists. Until then every
    /// governance path below reverts with NoGovernor, which is F-94.1's
    /// sequencing ruling enforced by the contract instead of trusted to a
    /// process.
    function setGovernor(address governor_) external onlyOwner {
        governor = governor_;
        emit GovernorSet(governor_);
    }

    /// @notice Mark a name PRUNED. The owner keeps it; the network stops
    /// facilitating it.
    /// @dev Per R-93.2's table, a prune does NOT take the name — that is what
    /// distinguishes it from a seizure — so `owner`, `bond` and `expiresAt` are
    /// untouched and the name still renews. What changes is `domainKey`: with it
    /// zeroed, no descriptor validates, so a node that ignores the prune state
    /// entirely still cannot resolve the name (R-93.4). Compliance stops being a
    /// policy question and becomes a signature question.
    function prune(bytes32 nameHash, uint256 proposalId) external onlyGovernor {
        Name storage n = _names[nameHash];
        if (n.owner == address(0)) revert NotAvailable();
        if (stateOf[nameHash] != NameState.ACTIVE) revert BadState();

        stateOf[nameHash] = NameState.PRUNED;
        n.domainKey = bytes32(0);
        n.keyValidFrom = uint64(block.timestamp);
        n.version += 1;                       // §11.7 anti-rollback
        _history[nameHash].push(StateChange(NameState.PRUNED, uint64(block.timestamp),
                                            proposalId, address(0)));
        emit Pruned(nameHash, proposalId, n.version);
    }

    /// @notice Seize a name: the network takes it, and the quarantine starts.
    /// @dev The DAO never receives or holds a key. `domainKey` is zeroed, not
    /// handed over (R-93.4) — escrowing registrants' keys would put one
    /// compromise between an attacker and every domain in the network, and
    /// disclosing a key hands it to everyone rather than disabling it. With the
    /// key zero, nobody can publish: not the previous owner, not the DAO, not an
    /// attacker.
    ///
    /// The bond is NOT returned. A returned bond would make seizure cost the
    /// seized party nothing beyond the name itself.
    function seize(bytes32 nameHash, uint256 proposalId) external onlyGovernor {
        Name storage n = _names[nameHash];
        address previousOwner = n.owner;
        if (previousOwner == address(0)) revert NotAvailable();
        NameState st = stateOf[nameHash];
        if (st == NameState.SEIZED || st == NameState.RECYCLABLE) revert BadState();

        stateOf[nameHash] = NameState.SEIZED;
        seizedAt[nameHash] = uint64(block.timestamp);
        n.domainKey = bytes32(0);
        n.keyValidFrom = uint64(block.timestamp);
        n.owner = address(0);                 // the network holds it now
        n.bond = 0;                           // forfeited, see above
        n.version += 1;
        levyPool += 0;                        // bond stays in the contract
        delete classHolder[n.skeleton];       // the confusable class is freed
        _history[nameHash].push(StateChange(NameState.SEIZED, uint64(block.timestamp),
                                            proposalId, previousOwner));
        emit Seized(nameHash, proposalId, previousOwner, n.version);
    }

    /// @notice A successful appeal (§93). Returns a PRUNED name to its owner.
    /// @dev Only from PRUNED. A SEIZED name has already lost its owner, and
    /// handing it back would require the contract to know who to hand it to at a
    /// point where `owner` is deliberately zero; restoring a seizure is a
    /// reassignment through the registrar and goes through `register()` like any
    /// other, with the history intact.
    ///
    /// The domain key is NOT restored. The contract never held it, and the owner
    /// must publish a fresh one — which is the right outcome anyway, since a key
    /// that was public knowledge as "the key of a pruned domain" should not come
    /// back into service.
    function restore(bytes32 nameHash, uint256 proposalId) external onlyGovernor {
        Name storage n = _names[nameHash];
        if (stateOf[nameHash] != NameState.PRUNED) revert BadState();
        if (n.owner == address(0)) revert NotAvailable();

        stateOf[nameHash] = NameState.ACTIVE;
        n.version += 1;
        _history[nameHash].push(StateChange(NameState.ACTIVE, uint64(block.timestamp),
                                            proposalId, address(0)));
        emit Restored(nameHash, proposalId, n.owner, n.version);
    }

    /// @notice Move a seized name to RECYCLABLE once its quarantine has run.
    /// @dev Permissionless on purpose: the quarantine is a time bound, and
    /// requiring a governance transaction to notice that time has passed would
    /// let inaction extend a seizure indefinitely — a prune with no vote behind
    /// it, arrived at by nobody doing anything.
    function makeRecyclable(bytes32 nameHash) external {
        if (stateOf[nameHash] != NameState.SEIZED) revert BadState();
        if (block.timestamp < seizedAt[nameHash] + SEIZE_QUARANTINE) revert Quarantined();
        stateOf[nameHash] = NameState.RECYCLABLE;
        _history[nameHash].push(StateChange(NameState.RECYCLABLE, uint64(block.timestamp),
                                            0, address(0)));
        emit Recyclable(nameHash, uint64(block.timestamp));
    }

    /// @notice The full state history of a name. Append-only (R-93.3).
    function historyOf(bytes32 nameHash) external view returns (StateChange[] memory) {
        return _history[nameHash];
    }

    // ------------------------------------------------------------ views
    function nameOf(bytes32 nameHash) external view returns (Name memory) {
        return _names[nameHash];
    }

    function available(bytes32 nameHash) external view returns (bool) {
        return _available(nameHash);
    }

    /// @dev The governance states gate availability, and the order matters.
    /// A SEIZED name has `owner == address(0)`, so the ordinary test below would
    /// call it available the moment it was seized — which is exactly the
    /// same-block re-registration R-93.3's quarantine exists to prevent. The
    /// state check therefore comes FIRST.
    function _available(bytes32 nameHash) internal view returns (bool) {
        NameState st = stateOf[nameHash];
        if (st == NameState.SEIZED) return false;   // quarantine running
        if (st == NameState.PRUNED) return false;   // still owned, just refused
        Name storage n = _names[nameHash];
        if (st == NameState.RECYCLABLE) return true;
        return n.owner == address(0) ||
               block.timestamp >= n.expiresAt + GRACE_PERIOD;
    }

    /// @notice Length pricing: short names cost more (§12.4).
    function priceOf(uint8 labelLen) public view returns (uint256) {
        if (labelLen == 3) return BASE_PRICE * 100;
        if (labelLen == 4) return BASE_PRICE * 20;
        if (labelLen == 5) return BASE_PRICE * 5;
        return BASE_PRICE;
    }

    /// @notice Superlinear cost of the n-th name one account takes in an epoch.
    /// @dev Kept despite §12.4a.1's negative result — a prepared adversary
    /// splits across accounts and pays base price every time — because it costs
    /// an UNPREPARED adversary something and an honest registrant nothing. It is
    /// NOT the guard and must not be described as one.
    function burstSurcharge(uint256 base, uint16 nth) public view returns (uint256) {
        if (nth <= BURST_FREE) return base;
        uint256 over = nth - BURST_FREE;
        return base * (over * over + 1);
    }

    /// @notice The DAO's cut of a secondary sale, halving per LEVY_HALF_LIFE.
    /// @dev Integer-only shifts, so an off-chain implementation reproduces it
    /// exactly. A levy computed in floating point is a levy two implementations
    /// disagree about.
    function levyFor(uint256 salePrice, uint64 heldSeconds)
        public view returns (uint256)
    {
        if (salePrice == 0 || LEVY_BPS == 0) return 0;
        uint256 bps = LEVY_BPS;
        if (LEVY_HALF_LIFE != 0) {
            uint256 halvings = heldSeconds / LEVY_HALF_LIFE;
            if (halvings >= 16) return 0;   // LEVY_BPS is uint16
            bps >>= halvings;
        }
        return (salePrice * bps) / 10_000;
    }

    // ------------------------------------------------------------ admin
    /// @notice Reserved labels are set once at deployment and have NO setter,
    /// so the set is immutable and verifiable from storage (§11.3.1).
    function seedReserved(bytes32[] calldata hashes) external onlyOwner {
        for (uint256 i = 0; i < hashes.length; i++) reservedLabel[hashes[i]] = true;
    }

    /// @notice Sweep primary-issuance proceeds to the DAO.
    function sweepFees() external {
        uint256 amount = feePool;
        feePool = 0;
        if (amount != 0) token.safeTransfer(treasury, amount);
    }
}
