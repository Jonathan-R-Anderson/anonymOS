// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

// =============================================================================
// §12.0's types. Declared at file level, not inside the contract, because the
// interface below returns them and a resolver binding against ITLDRegistry must
// not need TLDRegistry's source to know what a Namespace is.
// =============================================================================

/// @notice A namespace's lifecycle (§12.0).
///
/// PROPOSED is the only state the root holds that does NOT resolve: it is a
/// bonded proposal waiting on the governor, and a resolver treats it exactly as
/// NONE (10-resolver.md R3: NXNAMESPACE). RETIRED is terminal -- a retired label
/// is never re-created, see `proposeNamespace`.
enum NsStatus { NONE, PROPOSED, ACTIVE, FROZEN, RETIRING, RETIRED }

/// @notice What the namespace's registrar may do to a name later, surfaced to
/// users at registration time and in resolver diagnostics (§12.0, §13.3a).
enum RegClass { IMMUTABLE, UPGRADEABLE, STEWARDED }

/// @notice One namespace, as the root holds it.
///
/// FIELD ORDER IS NOT §12.0's LISTING ORDER, ON PURPOSE. §12.0 lists the fields
/// as registrar, registrarClass, status, steward, charter, bond, activatedAt,
/// retiresAt, recordSchema; laid out in that order the compiler puts
/// recordSchema in the FIFTH word, so 10-resolver.md's R3 -- "prove
/// Namespace{registrar, class, status, recordSchema}" -- would cost two storage
/// proofs (~2989 B each, §12.1) on every cold resolution. Ordered as below,
/// everything R3 needs for an ACTIVE namespace is ONE word (nsBase+0), and the
/// two timestamps a non-ACTIVE status needs are the next word (nsBase+1).
///
/// §12.5's own sketch of this layout does not fit: it puts
/// `steward | activatedAt | retiresAt` in one word, which is 20+8+8 = 36 bytes.
/// The compiler would have moved retiresAt to the next slot and every proof
/// written against the sketch would have read the wrong word. The layout below
/// is CONFIRMED by solc (see "Storage layout" in TLDRegistry).
///
/// ONE FIELD IS ADDED: `frozenAt`. §12.0a says a freeze "blocks NEW
/// registrations only; existing names keep resolving". The root calls nothing on
/// a registrar (§12.0), and the first registrar -- AxonRegistry, IMMUTABLE and
/// already on mainnet -- does not read the root, so the registrar keeps
/// accepting transactions while its namespace is FROZEN. What makes "new
/// registrations are blocked" true is the RESOLVER refusing a name in a FROZEN
/// namespace whose registeredAt >= frozenAt, and it cannot do that without
/// frozenAt. Without the field, FROZEN would be a label with no rule behind it.
///
/// ABI NOTE: `namespaceOf` returns this struct as a static tuple in exactly
/// this field order. A client decoding it (dendritic-node
/// internal/axon/registrar) must use this order, not §12.0's.
struct Namespace {
    address  registrar;       // nsBase+0  bytes [12..32) of the BE word   implements IRegistrar (§12.0)
    RegClass registrarClass;  // nsBase+0  byte  11
    NsStatus status;          // nsBase+0  byte  10
    uint16   recordSchema;    // nsBase+0  bytes [8..10)
    uint64   activatedAt;     // nsBase+0  bytes [0..8)
    uint64   retiresAt;       // nsBase+1  bytes [24..32)  0 unless RETIRING; never decreases while RETIRING
    uint64   frozenAt;        // nsBase+1  bytes [16..24)  0 unless frozen (see above)
    address  steward;         // nsBase+2  bytes [12..32)  0 unless STEWARDED; powers are namespace-local only
    bytes32  charter;         // nsBase+3  ContentIdentity of the human-readable policy (§10)
    uint256  bond;            // nsBase+4  proposer's bond while PROPOSED; 0 once returned or slashed
}

/// @notice The registrar interface §12.0 specifies. Every namespace's registrar
/// is meant to implement it; the root calls NOTHING on it -- resolvers and
/// clients do.
///
/// [NEEDS RESEARCH] / KNOWN GAP: AxonRegistry, the first namespace's registrar
/// (mainnet 0x5B2D1cd4AB437e1d4a0adC1416FEe2ff517ef0DB), does NOT implement this
/// interface. It exposes `nameOf(bytes32)` and `available(bytes32)` instead of
/// ownerOf / domainKeyOf / expiresAt / available(string) / schemaVersion. That
/// is one reason the root does not ERC-165-check registrars: the contract this
/// root most needs to accept would fail the check. Resolvers read registrar
/// state through storage proofs (§12.5), and AxonRegistry's layout is the
/// shape they expect by default.
interface IRegistrar {
    function ownerOf(bytes32 nameHash) external view returns (address);
    function domainKeyOf(bytes32 nameHash) external view returns (bytes32, uint64);
    function expiresAt(bytes32 nameHash) external view returns (uint64);
    function available(string calldata label) external view returns (bool);
    function schemaVersion() external view returns (uint16);
}

/// @notice §12.0's root interface. Mutations are deliberately absent from it:
/// they belong to the governor, behind the timelocks below, and a resolver
/// binding against this interface has no reason to see them.
interface ITLDRegistry {
    function namespaceOf(bytes32 labelHash) external view returns (Namespace memory);
    function isEligible(string calldata label) external view returns (bool);
}

/// @title TLDRegistry — the AXON root zone, as a contract (§11.0, §12.0, §12.0a).
///
/// WHAT IT IS. A table of NAMESPACES, not names. It knows that `lab` exists, that
/// it is ACTIVE, and which registrar contract decides who may register beneath
/// it. It knows nothing about `alice`. A name `alice.lab.axon` is resolved in two
/// verified reads (§12.5): `lab`'s registrar out of this contract, then `alice`
/// out of that registrar.
///
/// THE ROOT SUFFIX IS NOT VOTABLE (§11.0.2 R16 part 1). Every name ends in
/// ROOT_SUFFIX; the governed labels sit at the SECOND level, so however many
/// namespaces the vote creates, the collision surface with the IANA root stays
/// exactly one label wide. That is why ROOT_SUFFIX is a compile-time constant
/// here and not a constructor argument or a parameter: a deployment that could
/// choose it could choose wrong, and a governor that could change it would own
/// the one decision that makes a votable root survivable.
///
/// THE INVARIANT THAT MATTERS MOST (§12.0a), enforced by what is ABSENT:
///
///   Governance acts on the root. It never acts on a name, a key, a service,
///   or a byte of traffic.
///
/// So there is no function here that transfers, revokes, mints or seizes a name;
/// none that reads or writes a DomainIdentity; none that changes a namespace's
/// registrar or registrarClass after it is proposed (so an IMMUTABLE registrar
/// cannot be "upgraded" by repointing the root at another one); none that calls
/// a registrar at all; and none that lowers a RETIRING namespace's retiresAt.
/// test/TLDRegistry.test.ts enumerates the ABI to hold that true -- adding a
/// mutating function fails the build until somebody justifies it there.
///
/// WHO MAY DO WHAT (§12.0a "Enumerated powers"), with the timelocks ENFORCED
/// here as queue -> wait -> execute, not left to the governor's discipline:
///
///   power                               who         delay (floor)  call
///   ----------------------------------  ----------  -------------  -----------------------------
///   post a namespace proposal + bond    anyone      --             proposeNamespace
///   create a namespace                  governor    14 days        queueCreate -> execute
///   reject a proposal (slash/return)    governor    --             rejectProposal
///   freeze new registrations            guardian    0              guardianFreeze
///   freeze new registrations            governor    7 days         queueFreeze -> execute
///   unfreeze                            governor    7 days         queueUnfreeze -> execute
///   begin retiring                      governor    90 days notice beginRetirement -> execute
///   update the reserved-label list      governor    30 days        queueSetReserved -> execute
///   update the IANA root-zone snapshot  governor    30 days        queueSetIana -> execute
///   set root parameters                 governor    30 days        queueSetParams -> execute
///   register a recordSchema version     governor    30 days        queueAddSchema -> execute
///   move a namespace to a newer schema  governor    30 days        queueAdoptSchema -> execute
///   (re)authorise the guardian          governor    30 days        queueSetGuardian -> execute
///   hand the root to a new governor     governor    30 days + accept  queueGovernorHandover -> execute -> acceptGovernor
///   veto any queued action              guardian or governor       cancel
///
/// Execution after the delay is PERMISSIONLESS, for the reason AxonRegistry
/// gives for makeRecyclable: requiring a governance transaction to notice that
/// time has passed would let inaction become a decision nobody voted for. The
/// governor decides at queue time; the guardian or governor may veto until
/// execution; the clock does the rest.
///
/// THE GOVERNOR IS AN ADDRESS (§12.0a: "shipping the root registry with
/// governance stubbed to a multisig and a published migration path is a
/// legitimate v1"). The migration path is `queueGovernorHandover` ->
/// 30 days -> `execute` -> `acceptGovernor` from the new address. Two-step, so
/// the root cannot be handed to a contract that is unable to act as its
/// governor; timelocked, so a capture attempt is visible for 30 days before it
/// lands, and resolvers can repoint (the fork right, §12.0a) before it does.
/// AxonGovernance as deployed CANNOT be that governor: its Action enum is fixed
/// at SIGNAL/PRUNE/SEIZE/RESTORE on AxonRegistry. A DAO governor for this root
/// is a new contract.
///
/// THE GUARDIAN IS A VETO, NOT A GOVERNOR. It may cancel a queued action and may
/// freeze a namespace's new registrations immediately (a 14-day timelock cannot
/// answer a live exploit). It may not create, unfreeze, retire, reject, set,
/// slash, or execute ahead of a timelock. It expires and must be re-authorised
/// by the governor, and it may resign. It is an acknowledged centralisation
/// point and a standing target; anyone describing this root as trustless while
/// a guardian exists is wrong (§12.0a). Because its veto covers EVERY queued
/// action, it can veto its own replacement, and a governor and guardian can
/// re-queue and re-veto each other indefinitely. That entrenchment is bounded by
/// the guardian's expiry and by nothing else -- which is why expiry is
/// mandatory (MAX_GUARDIAN_TERM) rather than optional.
///
/// THE TIMELOCKS ARE PARAMETERS WITH FLOORS. §12.0a lists "timelock lengths"
/// among the root parameters a supermajority may set. [INTERPRETATION] It does
/// not say they may be set BELOW the table, and a timelock a governor can set to
/// zero is a formality, which §12.0a says it is not. So each delay has a floor
/// equal to the §12.0a table (MIN_* below) and a ceiling (MAX_DELAY) so a
/// captured governor cannot make itself unreplaceable by stretching the handover
/// delay to a century. A changed delay applies to actions queued AFTER the
/// change; an action's eta is fixed when it is queued.
///
/// EVERY POLICY NUMBER IS [NEEDS RESEARCH] except where the spec fixes it: the
/// proposal bond, PROPOSAL_STALE_AFTER, MAX_DELAY and MAX_GUARDIAN_TERM are
/// judgement, stated as constants or parameters so a deployment states them
/// rather than inheriting a guess.
///
/// UNAUDITED. Not deployed.
contract TLDRegistry is ITLDRegistry {
    using SafeERC20 for IERC20;

    // ------------------------------------------------------------ constants

    /// @notice The single fixed trailing label (§11.3: the one compile-time
    /// constant in the naming spec). NOT VOTABLE. Changing it is a different
    /// root, not a governance action.
    string  public constant ROOT_SUFFIX = "axon";
    /// @notice keccak256(ROOT_SUFFIX).
    bytes32 public constant ROOT_LABEL_HASH = keccak256(bytes(ROOT_SUFFIX));
    /// @notice namehash(ROOT_SUFFIX) = keccak256(0x00*32 ‖ keccak256(ROOT_SUFFIX))
    /// (§11.3.2). Parent of every namespace node.
    bytes32 public constant ROOT_NODE = keccak256(abi.encodePacked(bytes32(0), ROOT_LABEL_HASH));

    /// @notice Namespace label bounds (§11.3.1): at most 24 because they are
    /// typed constantly; at least 3 because one- and two-character labels are
    /// reserved for ccTLDs (§11.0.2 part 3).
    uint256 public constant MIN_NS_LEN = 3;
    uint256 public constant MAX_NS_LEN = 24;

    /// @notice §12.0a's timelock table, as FLOORS. See the contract NatSpec.
    uint64 public constant MIN_CREATE_DELAY  = 14 days;
    uint64 public constant MIN_FREEZE_DELAY  = 7 days;   // freeze by vote, and unfreeze
    uint64 public constant MIN_RETIRE_NOTICE = 90 days;  // "90 days minimum"; also the shortest RETIRING period
    uint64 public constant MIN_LIST_DELAY    = 30 days;  // reserved list and IANA snapshot
    uint64 public constant MIN_PARAMS_DELAY  = 30 days;  // params, guardian, governor handover
    uint64 public constant MIN_SCHEMA_DELAY  = 30 days;

    /// @notice Ceiling on every delay. [NEEDS RESEARCH] as a figure; what is
    /// derived is that there must be one -- without it a captured governor sets
    /// paramsDelay to 100 years and the handover that would remove it never
    /// arrives.
    uint64 public constant MAX_DELAY = 730 days;

    /// @notice Longest single guardian authorisation. [NEEDS RESEARCH] as a
    /// figure; §12.0a requires only that the guardian EXPIRES.
    uint64 public constant MAX_GUARDIAN_TERM = 365 days;

    /// @notice How long an unqueued proposal must sit before its proposer may
    /// take the bond back without a governor decision.
    ///
    /// [NEEDS RESEARCH] as a figure. Two failure modes bound it. Too short, and a
    /// griefer squats a label in PROPOSED, watches the mempool for the governor's
    /// slashing rejectProposal, withdraws first, and re-proposes -- the bond
    /// never bites. No withdrawal at all, and a governor that goes dark (the
    /// multisig loses keys, the DAO stops meeting quorum) locks every bond
    /// forever. 60 days gives the governor two of its own 30-day cycles to act.
    uint64 public constant PROPOSAL_STALE_AFTER = 60 days;

    // ------------------------------------------------------------ types

    /// @notice Why a label is not eligible as a namespace (§11.0.2 part 3,
    /// §11.3.1). Checked in this order; the first failure is reported.
    ///
    /// LENGTH is checked FIRST, unlike internal/axon/name's order (charset, LDH,
    /// then length), because the LDH checks index the label and an empty label
    /// has nothing to index. The order matters only for the reason given, never
    /// for accept/refuse.
    enum Ineligibility {
        NONE,            // eligible
        LENGTH,          // outside [3, 24]
        CHARSET,         // a byte outside [a-z0-9-]. UPPERCASE IS REFUSED, not folded:
                         // the contract hashes exactly what it is given, so "Lab"
                         // and "lab" would be different namespaces
        HYPHEN,          // leading or trailing "-"
        IDNA_PREFIX,     // "-" at positions 3 AND 4 ("xn--..."), §11.3.1
        ROOT_SUFFIX,     // the root itself
        SPECIAL_USE,     // IETF special-use / IANA-infrastructure / ICANN-reserved, fixed in code
        AXON_RESERVED,   // AXON's own permanently reserved labels (key, srv), fixed in code
        IANA_DELEGATED,  // in the IANA root-zone snapshot (governor-updatable data)
        RESERVED_LIST    // on the governor-maintained reserved list
    }

    enum Kind {
        NONE,
        CREATE,          // payload abi.encode(string label)
        FREEZE,          // payload abi.encode(bytes32 labelHash)
        UNFREEZE,        // payload abi.encode(bytes32 labelHash)
        RETIRE,          // payload abi.encode(bytes32 labelHash); eta == retiresAt
        SET_RESERVED,    // payload abi.encode(string[] labels, bool reserved)
        SET_IANA,        // payload abi.encode(string[] labels, bool delegated, uint64 snapshotAt)
        SET_PARAMS,      // payload abi.encode(Params)
        ADD_SCHEMA,      // payload abi.encode(uint16 version, bytes32 spec)
        ADOPT_SCHEMA,    // payload abi.encode(bytes32 labelHash, uint16 version)
        SET_GUARDIAN,    // payload abi.encode(address guardian, uint64 expiresAt)
        SET_GOVERNOR     // payload abi.encode(address newGovernor)
    }

    enum ActionState { NONE, QUEUED, EXECUTED, CANCELLED }

    /// @notice A queued action. The payload itself is NOT stored -- only its
    /// hash -- and is emitted in ActionQueued, so anyone can reconstruct and
    /// audit it from logs, and execution must present the same bytes. That is
    /// what lets an IANA-snapshot update of a thousand labels sit in the queue
    /// for 30 days at the cost of one slot.
    struct Action {
        Kind        kind;
        ActionState state;
        uint64      eta;          // earliest execution, block.timestamp
        bytes32     subject;      // labelHash for namespace actions, else 0
        bytes32     payloadHash;  // keccak256(payload)
    }

    /// @notice Who proposed a namespace and when. Not in Namespace because a
    /// resolver never needs it, and every word in Namespace is a word a
    /// resolver's proof might have to cover.
    struct Proposal {
        address proposer;
        uint64  proposedAt;
    }

    /// @notice Root parameters (§12.0a "Set root parameters (bond, deposit,
    /// timelock lengths)"). [INTERPRETATION] §12.0a names both a "bond" and a
    /// "deposit"; with the governor stubbed to an address there is one thing a
    /// proposer posts, so there is one figure, proposalBond, denominated in the
    /// network token (§12.4a's ruling for names, applied to proposals too).
    struct Params {
        uint256 proposalBond;
        uint64  createDelay;
        uint64  freezeDelay;
        uint64  retireNotice;
        uint64  listDelay;
        uint64  paramsDelay;
        uint64  schemaDelay;
    }

    // ------------------------------------------------------------ immutables

    /// @notice The network token the proposal bond is posted in (AxonToken).
    IERC20  public immutable token;
    /// @notice Where a slashed bond goes (the DAO Treasury).
    address public immutable treasury;

    // ------------------------------------------------------------ storage
    //
    // STORAGE LAYOUT -- PART OF THE INTERFACE (§12.5), CONFIRMED BY solc
    // (hardhat build-info storageLayout, solc 0.8.24, 2026-09-30). Resolvers
    // prove against these slots; NEW STORAGE IS APPENDED AT THE END, NEVER
    // INTERLEAVED (the rule AxonRegistry learned twice, §12.5).
    //
    //   slot  0 +0   _ns                 mapping(bytes32 => Namespace)
    //   slot  1 +0   ianaDelegated       mapping(bytes32 => bool)
    //   slot  2 +0   reservedLabel       mapping(bytes32 => bool)
    //   slot  3 +0   governor            address
    //   slot  3 +20  ianaSnapshotAt      uint64
    //   slot  3 +28  genesisSealed       bool
    //   slot  4 +0   guardian            address
    //   slot  4 +20  guardianExpiresAt   uint64
    //   slot  5 +0   pendingGovernor     address
    //   slot  6..8   _params             Params (bond; 4 delays; 2 delays)
    //   slot  9 +0   _actions            mapping(uint256 => Action)
    //   slot 10 +0   actionCount         uint256
    //   slot 11 +0   proposals           mapping(bytes32 => Proposal)
    //   slot 12 +0   pendingCreate       mapping(bytes32 => uint256)
    //   slot 13 +0   registrarNamespace  mapping(address => bytes32)
    //   slot 14 +0   schemaSpec          mapping(uint16 => bytes32)
    //
    // A namespace, with labelHash = keccak256(label):
    //
    //   nsBase = keccak256( labelHash ‖ uint256(0) )  == ethproof.StorageSlotKey(labelHash, 0)
    //
    //   nsBase+0  activatedAt | recordSchema | status | registrarClass | registrar
    //             BE word w[0..32):  w[0..8) activatedAt  w[8..10) recordSchema
    //                                w[10] status  w[11] registrarClass  w[12..32) registrar
    //   nsBase+1  w[16..24) frozenAt   w[24..32) retiresAt   (w[0..16) zero)
    //   nsBase+2  w[12..32) steward
    //   nsBase+3  charter
    //   nsBase+4  bond
    //
    // An ACTIVE namespace is proven with ONE slot (nsBase+0). FROZEN and
    // RETIRING add nsBase+1. Nothing a resolver needs lives beyond +1.

    mapping(bytes32 => Namespace) private _ns;
    /// @notice The IANA root-zone snapshot (§11.0.2 part 3), keyed by
    /// keccak256(label). DATA, not policy: ~1,000 labels cannot be a compile-time
    /// constant and cannot be written in one transaction, so it is seeded during
    /// genesis and updated by the governor under the 30-day list delay. The
    /// contract's view goes stale and the real root does not stop moving;
    /// resolvers re-check against their own anchored snapshot (§11.0.2).
    mapping(bytes32 => bool) public ianaDelegated;
    /// @notice The governor-maintained reserved list (§12.0a), keyed by
    /// keccak256(label). Read ONLY by the eligibility predicate, i.e. only when
    /// a namespace is proposed or created -- which is how "cannot retroactively
    /// invalidate an active namespace" is enforced: nothing about an existing
    /// namespace ever reads it.
    mapping(bytes32 => bool) public reservedLabel;

    address public governor;
    /// @notice The IANA list version the snapshot reflects, as published in its
    /// header ("# Version 2026093000" -> 2026093000). 0 until seeded.
    uint64  public ianaSnapshotAt;
    /// @notice False during genesis: the governor may seed the IANA snapshot and
    /// the reserved list directly, and NOTHING else works -- no proposal can be
    /// made against a predicate that is still being written. Sealing is
    /// one-way.
    bool    public genesisSealed;

    address public guardian;
    uint64  public guardianExpiresAt;

    address public pendingGovernor;

    Params  internal _params;

    mapping(uint256 => Action) private _actions;
    uint256 public actionCount;

    mapping(bytes32 => Proposal) public proposals;
    /// @notice labelHash => the queued CREATE action, 0 if none. While one is
    /// queued the proposal is frozen in place -- it cannot be rejected or
    /// withdrawn -- so the action that executes is always the proposal that was
    /// queued, never a different one re-proposed under the same label.
    mapping(bytes32 => uint256) public pendingCreate;
    /// @notice registrar => the namespace it serves. One registrar, one
    /// namespace, forever (§11.0.3 rule 1): AxonRegistry's confusable-class
    /// table is per CONTRACT, so a registrar shared by two namespaces would let
    /// a name in one block its look-alike in the other -- an implicit
    /// cross-namespace right the spec rules out.
    mapping(address => bytes32) public registrarNamespace;
    /// @notice recordSchema version => ContentIdentity of its specification.
    /// Additive only (§12.0a): written once, never overwritten, never deleted.
    mapping(uint16 => bytes32) public schemaSpec;

    // ------------------------------------------------------------ events

    event NamespaceProposed(bytes32 indexed labelHash, string label, address indexed proposer,
                            address registrar, RegClass registrarClass, address steward,
                            bytes32 charter, uint16 recordSchema, uint256 bond);
    event ProposalClosed   (bytes32 indexed labelHash, address indexed proposer, uint256 bond,
                            bool slashed, bool byGovernor);
    event NamespaceActivated(bytes32 indexed labelHash, string label, address indexed registrar,
                            RegClass registrarClass, uint16 recordSchema, uint64 activatedAt);
    event NamespaceFrozen  (bytes32 indexed labelHash, uint64 frozenAt, bool byGuardian);
    event NamespaceUnfrozen(bytes32 indexed labelHash);
    event RetirementBegun  (bytes32 indexed labelHash, uint64 retiresAt, uint256 indexed actionId);
    event RetirementCancelled(bytes32 indexed labelHash);
    event NamespaceRetired (bytes32 indexed labelHash);
    event SchemaAdded      (uint16 indexed version, bytes32 spec);
    event SchemaAdopted    (bytes32 indexed labelHash, uint16 from, uint16 to);
    event ReservedSet      (bytes32 indexed labelHash, string label, bool reserved);
    event IanaSet          (bytes32 indexed labelHash, string label, bool delegated);
    event IanaSnapshot     (uint64 snapshotAt);
    event GenesisSealed    ();
    event ParamsSet        (Params params);
    event GuardianSet      (address indexed guardian, uint64 expiresAt);
    event GovernorPending  (address indexed pending);
    event GovernorAccepted (address indexed previous, address indexed governor);
    event ActionQueued     (uint256 indexed id, Kind indexed kind, bytes32 indexed subject,
                            uint64 eta, bytes payload);
    event ActionCancelled  (uint256 indexed id, address indexed by);
    event ActionExecuted   (uint256 indexed id, Kind indexed kind);

    // ------------------------------------------------------------ errors

    error NotGovernor();
    error NotGuardian();
    error NotPendingGovernor();
    error NotProposer();
    error GenesisOpen();
    error GenesisClosed();
    error ZeroAddress();
    error Ineligible(Ineligibility reason);
    error BadStatus(NsStatus status);
    error NotAContract(address registrar);
    error RegistrarInUse(address registrar, bytes32 labelHash);
    error StewardMismatch(RegClass registrarClass, address steward);
    error NoCharter();
    error UnknownSchema(uint16 version);
    error SchemaExists(uint16 version);
    error SchemaNotNewer(uint16 current, uint16 proposed);
    error CreatePending(uint256 actionId);
    error NotStale(uint64 withdrawableAt);
    error NotQueued(uint256 id);
    error TooEarly(uint256 id, uint64 eta);
    error BadPayload(uint256 id);
    error RetirementFinal(uint256 id);
    error DelayOutOfRange(uint64 delay, uint64 min, uint64 max);
    error BadGuardianTerm(uint64 expiresAt);
    error SameGovernor();

    // ------------------------------------------------------------ modifiers

    modifier onlyGovernor() {
        if (msg.sender != governor) revert NotGovernor();
        _;
    }

    /// @dev An expired guardian is no guardian: §12.0a "it expires and must be
    /// re-authorised". Checked on every use, so expiry needs no transaction.
    modifier onlyGuardian() {
        if (!guardianActive() || msg.sender != guardian) revert NotGuardian();
        _;
    }

    modifier sealed_() {
        if (!genesisSealed) revert GenesisOpen();
        _;
    }

    // ------------------------------------------------------------ constructor

    /// @param governor_          the initial governor (v1: a multisig)
    /// @param guardian_          the initial guardian, or 0 for none
    /// @param guardianExpiresAt_ when it lapses; within MAX_GUARDIAN_TERM of deployment
    /// @param token_             AxonToken, the bond's denomination
    /// @param treasury_          where slashed bonds go
    /// @param proposalBond_      initial bond; 0 is allowed (and is what a deployment
    ///                           must use while the token's supply is zero)
    /// @param schema1Spec        ContentIdentity of recordSchema version 1 (§11.6's
    ///                           DomainRecord set). A namespace must name a
    ///                           registered schema, so one must exist at birth.
    constructor(
        address governor_,
        address guardian_,
        uint64  guardianExpiresAt_,
        IERC20  token_,
        address treasury_,
        uint256 proposalBond_,
        bytes32 schema1Spec
    ) {
        if (governor_ == address(0) || treasury_ == address(0) || address(token_) == address(0)) {
            revert ZeroAddress();
        }
        if (schema1Spec == bytes32(0)) revert UnknownSchema(1);
        token = token_;
        treasury = treasury_;
        governor = governor_;
        emit GovernorAccepted(address(0), governor_);

        _setGuardian(guardian_, guardianExpiresAt_);

        _params = Params({
            proposalBond: proposalBond_,
            createDelay:  MIN_CREATE_DELAY,
            freezeDelay:  MIN_FREEZE_DELAY,
            retireNotice: MIN_RETIRE_NOTICE,
            listDelay:    MIN_LIST_DELAY,
            paramsDelay:  MIN_PARAMS_DELAY,
            schemaDelay:  MIN_SCHEMA_DELAY
        });
        emit ParamsSet(_params);

        schemaSpec[1] = schema1Spec;
        emit SchemaAdded(1, schema1Spec);
    }

    // ================================================================ views

    /// @inheritdoc ITLDRegistry
    /// @dev The RAW stored record, identical to what a storage proof yields. In
    /// particular a RETIRING namespace whose retiresAt has passed is still
    /// reported RETIRING until someone executes its RETIRE action; a resolver
    /// MUST treat `RETIRING && now >= retiresAt` as RETIRED, which is safe
    /// because a RETIRE action cannot be cancelled once retiresAt has passed
    /// (see `cancel`).
    function namespaceOf(bytes32 labelHash) external view returns (Namespace memory) {
        return _ns[labelHash];
    }

    /// @inheritdoc ITLDRegistry
    function isEligible(string calldata label) external view returns (bool) {
        return _eligibility(label) == Ineligibility.NONE;
    }

    /// @notice isEligible, with the reason.
    function eligibility(string calldata label) external view returns (Ineligibility) {
        return _eligibility(label);
    }

    /// @notice namehash(label.ROOT_SUFFIX). The `tldNode` an AxonRegistry for
    /// this namespace is deployed with, and the parent of every name in it.
    function namespaceNode(bytes32 labelHash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(ROOT_NODE, labelHash));
    }

    /// @notice nameHash of `label.namespace.ROOT_SUFFIX` (§11.3.2), from the two
    /// label hashes. The on-chain identifier a registrar keys the name by.
    /// Exposed so a client can check its own namehash against the contract's.
    function nameHashOf(bytes32 namespaceLabelHash, bytes32 labelHash) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(namespaceNode(namespaceLabelHash), labelHash));
    }

    function params() external view returns (Params memory) {
        return _params;
    }

    function actionOf(uint256 id) external view returns (Action memory) {
        return _actions[id];
    }

    function guardianActive() public view returns (bool) {
        return guardian != address(0) && block.timestamp < guardianExpiresAt;
    }

    // ================================================================ genesis

    /// @notice Seed the IANA snapshot and the reserved list, before anything else
    /// can happen.
    /// @dev Why a genesis phase rather than the constructor: the IANA list is
    /// ~1,000 eligible-shaped labels at ~25k gas each, above a single
    /// transaction's gas cap. Why not the 30-day path: until the snapshot is in,
    /// `com` is "eligible", and a 14-day create would beat a 30-day snapshot
    /// update. So proposals are refused until the governor seals genesis, and
    /// genesis can only ADD -- there is no namespace yet for an addition to
    /// harm, and no removal to abuse.
    function genesisSeed(string[] calldata iana, string[] calldata reserved, uint64 snapshotAt)
        external onlyGovernor
    {
        if (genesisSealed) revert GenesisClosed();
        for (uint256 i; i < iana.length; ++i) _setIana(iana[i], true);
        for (uint256 i; i < reserved.length; ++i) _setReserved(reserved[i], true);
        if (snapshotAt != 0) {
            ianaSnapshotAt = snapshotAt;
            emit IanaSnapshot(snapshotAt);
        }
    }

    /// @notice End genesis. One-way.
    function sealGenesis() external onlyGovernor {
        if (genesisSealed) revert GenesisClosed();
        genesisSealed = true;
        emit GenesisSealed();
    }

    // ================================================================ proposals

    /// @notice Propose a namespace, posting the bond (§12.0a "propose (slashable
    /// deposit)").
    ///
    /// [INTERPRETATION] §12.0 says root mutations are "callable ONLY by the
    /// governor, never by an EOA", and §12.0a's process begins with "propose
    /// (slashable deposit)" by a proposer. Both hold here: this is the one
    /// permissionless write, and what it writes is a PROPOSED record, which does
    /// not resolve. Every transition that changes what RESOLVES is the
    /// governor's, behind a timelock.
    ///
    /// The eligibility predicate runs here (§11.0.2 "the contract checks at
    /// proposal") and again at creation, because the IANA root does not stop
    /// moving during a 14-day timelock.
    ///
    /// A label whose status is anything but NONE is refused -- including
    /// RETIRED, permanently. [INTERPRETATION] §12.0a does not say whether a
    /// retired label may be re-created. Re-creating it would hand every stale
    /// cache, bookmark and NameAcceptance record that still says `x.lab.axon`
    /// to a different registrar's `x`; refusing costs a label.
    function proposeNamespace(
        string calldata label,
        address registrar,
        RegClass registrarClass,
        address steward,
        bytes32 charter,
        uint16 recordSchema
    ) external sealed_ returns (bytes32 labelHash) {
        Ineligibility why = _eligibility(label);
        if (why != Ineligibility.NONE) revert Ineligible(why);
        labelHash = keccak256(bytes(label));
        NsStatus st = _ns[labelHash].status;
        if (st != NsStatus.NONE) revert BadStatus(st);

        if (registrar.code.length == 0) revert NotAContract(registrar);
        bytes32 used = registrarNamespace[registrar];
        if (used != bytes32(0)) revert RegistrarInUse(registrar, used);
        // [INTERPRETATION] §12.0's class table: IMMUTABLE has "no steward";
        // STEWARDED is "a named address holds enumerated powers". UPGRADEABLE's
        // risk is the upgrade key, which lives in the registrar, not here. So a
        // steward is present exactly when the class says one is.
        if ((registrarClass == RegClass.STEWARDED) != (steward != address(0))) {
            revert StewardMismatch(registrarClass, steward);
        }
        // A namespace with no published policy is one voters cannot evaluate.
        if (charter == bytes32(0)) revert NoCharter();
        if (schemaSpec[recordSchema] == bytes32(0)) revert UnknownSchema(recordSchema);

        uint256 bond = _params.proposalBond;
        _ns[labelHash] = Namespace({
            registrar:      registrar,
            registrarClass: registrarClass,
            status:         NsStatus.PROPOSED,
            recordSchema:   recordSchema,
            activatedAt:    0,
            retiresAt:      0,
            frozenAt:       0,
            steward:        steward,
            charter:        charter,
            bond:           bond
        });
        proposals[labelHash] = Proposal(msg.sender, uint64(block.timestamp));
        emit NamespaceProposed(labelHash, label, msg.sender, registrar, registrarClass,
                               steward, charter, recordSchema, bond);

        if (bond != 0) token.safeTransferFrom(msg.sender, address(this), bond);
    }

    /// @notice The governor declines a proposal, slashing or returning the bond.
    /// @dev Immediate: it removes a record that never resolved, so there is no
    /// holder for a timelock to protect. Refused while a CREATE is queued --
    /// cancel that first -- so the queued action can never end up pointing at a
    /// different proposal.
    ///
    /// [INTERPRETATION] §12.0a: the bond is "slashable" and "returned on
    /// activation"; it does not say what triggers a slash. Here the governor
    /// decides per rejection (spam, an ineligible-by-IANA label, a hostile
    /// registrar: slash; a good-faith proposal voted down: return).
    function rejectProposal(bytes32 labelHash, bool slash) external onlyGovernor {
        NsStatus st = _ns[labelHash].status;
        if (st != NsStatus.PROPOSED) revert BadStatus(st);
        uint256 pending = pendingCreate[labelHash];
        if (pending != 0) revert CreatePending(pending);
        _closeProposal(labelHash, slash, true);
    }

    /// @notice A proposer reclaims the bond from a proposal the governor has
    /// neither queued nor rejected within PROPOSAL_STALE_AFTER.
    function withdrawProposal(bytes32 labelHash) external {
        NsStatus st = _ns[labelHash].status;
        if (st != NsStatus.PROPOSED) revert BadStatus(st);
        Proposal memory p = proposals[labelHash];
        if (msg.sender != p.proposer) revert NotProposer();
        uint256 pending = pendingCreate[labelHash];
        if (pending != 0) revert CreatePending(pending);
        uint64 at = p.proposedAt + PROPOSAL_STALE_AFTER;
        if (block.timestamp < at) revert NotStale(at);
        _closeProposal(labelHash, false, false);
    }

    // ================================================================ governor: queue

    /// @notice Queue the creation of a proposed namespace (14-day floor).
    /// @dev Takes the LABEL, not its hash, so the eligibility predicate can be
    /// re-run at execution against whatever the IANA snapshot says by then.
    function queueCreate(string calldata label) external onlyGovernor sealed_ returns (uint256 id) {
        bytes32 h = keccak256(bytes(label));
        NsStatus st = _ns[h].status;
        if (st != NsStatus.PROPOSED) revert BadStatus(st);
        uint256 pending = pendingCreate[h];
        if (pending != 0) revert CreatePending(pending);
        id = _queue(Kind.CREATE, h, _params.createDelay, abi.encode(label));
        pendingCreate[h] = id;
    }

    /// @notice Queue a freeze of new registrations by vote (7-day floor). The
    /// guardian's emergency path is `guardianFreeze`.
    function queueFreeze(bytes32 labelHash) external onlyGovernor sealed_ returns (uint256) {
        _requireStatus(labelHash, NsStatus.ACTIVE);
        return _queue(Kind.FREEZE, labelHash, _params.freezeDelay, abi.encode(labelHash));
    }

    /// @notice Queue an unfreeze (7-day floor).
    /// @dev [INTERPRETATION] §12.0a enumerates the freeze but not the unfreeze.
    /// Without one, a guardian's emergency freeze -- a VETO power -- would be
    /// permanent, which is an enactment. It takes the vote's freeze delay: the
    /// guardian can freeze, only the vote can unfreeze.
    ///
    /// Unfreezing clears frozenAt, so names registered DURING the freeze start
    /// resolving. A vote that unfreezes has accepted them. If the freeze was for
    /// a registrar exploit, the exit is retirement, not unfreeze.
    function queueUnfreeze(bytes32 labelHash) external onlyGovernor sealed_ returns (uint256) {
        _requireStatus(labelHash, NsStatus.FROZEN);
        return _queue(Kind.UNFREEZE, labelHash, _params.freezeDelay, abi.encode(labelHash));
    }

    /// @notice Begin retiring a namespace, giving `notice` seconds of warning
    /// (at least the retireNotice parameter, itself at least 90 days).
    ///
    /// [INTERPRETATION] §12.0a's table gives "Begin retiring" a timelock of
    /// "90 days minimum" and also says "a retiring namespace keeps resolving for
    /// the full 90-day notice". Read together: the 90 days IS the timelock, and
    /// the RETIRING status is how the notice is published. So the status flips
    /// to RETIRING now -- resolvers warn with retiresAt (§13.3a), names keep
    /// resolving -- and the enactment, RETIRED, is a queued action with
    /// eta == retiresAt that the guardian or governor may veto until then.
    ///
    /// "Shorten a retirement notice" is absent by construction: nothing writes
    /// retiresAt except this function, which refuses a namespace already
    /// RETIRING, and a cancelled retirement re-begins with a full notice from
    /// the new start. Every RETIRING period therefore lasts >= 90 days.
    /// (§12.0's "retiresAt >= activatedAt + 90 days" is implied: retiresAt >=
    /// now + 90 days >= activatedAt + 90 days.)
    function beginRetirement(bytes32 labelHash, uint64 notice)
        external onlyGovernor sealed_ returns (uint256 id)
    {
        Namespace storage ns = _ns[labelHash];
        NsStatus st = ns.status;
        if (st != NsStatus.ACTIVE && st != NsStatus.FROZEN) revert BadStatus(st);
        uint64 min = _params.retireNotice;
        if (notice < min || notice > MAX_DELAY) revert DelayOutOfRange(notice, min, MAX_DELAY);

        uint64 retiresAt = uint64(block.timestamp) + notice;
        ns.status = NsStatus.RETIRING;
        ns.retiresAt = retiresAt;
        id = _queue(Kind.RETIRE, labelHash, notice, abi.encode(labelHash));
        emit RetirementBegun(labelHash, retiresAt, id);
    }

    /// @notice Queue an update of the reserved-label list (30-day floor).
    /// @dev Labels, not hashes, so the queue event says in plain text what is
    /// being reserved. A hash-only list is one a captured governor could fill
    /// with labels nobody can read.
    function queueSetReserved(string[] calldata labels, bool reserved)
        external onlyGovernor sealed_ returns (uint256)
    {
        return _queue(Kind.SET_RESERVED, bytes32(0), _params.listDelay, abi.encode(labels, reserved));
    }

    /// @notice Queue an update of the IANA snapshot (30-day floor).
    /// @dev [INTERPRETATION] §12.0a does not enumerate "update the IANA
    /// snapshot" as a power; it is the same kind of list as the reserved list
    /// and takes the same delay. The 30 days are not the collision defence --
    /// the guardian's cancel (for a pending creation) and freeze (for a live
    /// namespace) are, per §11.0.2's "freeze new registrations immediately ...
    /// and start a retirement vote".
    function queueSetIana(string[] calldata labels, bool delegated, uint64 snapshotAt)
        external onlyGovernor sealed_ returns (uint256)
    {
        return _queue(Kind.SET_IANA, bytes32(0), _params.listDelay,
                      abi.encode(labels, delegated, snapshotAt));
    }

    /// @notice Queue new root parameters (30-day floor).
    function queueSetParams(Params calldata p) external onlyGovernor sealed_ returns (uint256) {
        _checkParams(p);
        return _queue(Kind.SET_PARAMS, bytes32(0), _params.paramsDelay, abi.encode(p));
    }

    /// @notice Queue registration of a recordSchema version (30-day floor).
    /// Additive only: a version is written once and never overwritten.
    function queueAddSchema(uint16 version, bytes32 spec)
        external onlyGovernor sealed_ returns (uint256)
    {
        if (spec == bytes32(0)) revert UnknownSchema(version);
        if (schemaSpec[version] != bytes32(0)) revert SchemaExists(version);
        return _queue(Kind.ADD_SCHEMA, bytes32(0), _params.schemaDelay, abi.encode(version, spec));
    }

    /// @notice Queue moving a namespace to a NEWER registered recordSchema
    /// (30-day floor).
    /// @dev [INTERPRETATION] §12.0a enumerates only "Register a new recordSchema
    /// version (additive only)", while §12.0 says recordSchema "lets namespaces
    /// evolve record formats independently" -- which a schema fixed at creation
    /// cannot do. The faithful middle: adoption is part of the same power, under
    /// the same delay, and is monotonic (never downgrades), so it stays additive.
    function queueAdoptSchema(bytes32 labelHash, uint16 version)
        external onlyGovernor sealed_ returns (uint256)
    {
        _checkAdopt(labelHash, version);
        return _queue(Kind.ADOPT_SCHEMA, labelHash, _params.schemaDelay, abi.encode(labelHash, version));
    }

    /// @notice Queue (re)authorisation of the guardian (params delay). Pass
    /// guardian = 0 to have none. expiresAt is checked at EXECUTION against
    /// MAX_GUARDIAN_TERM, so choose it as queue time + delay + term.
    function queueSetGuardian(address guardian_, uint64 expiresAt)
        external onlyGovernor sealed_ returns (uint256)
    {
        return _queue(Kind.SET_GUARDIAN, bytes32(0), _params.paramsDelay, abi.encode(guardian_, expiresAt));
    }

    /// @notice Queue handing the root to a new governor (params delay). After
    /// execution the new address must call `acceptGovernor`; until it does, the
    /// current governor remains in office.
    function queueGovernorHandover(address newGovernor)
        external onlyGovernor sealed_ returns (uint256)
    {
        if (newGovernor == address(0)) revert ZeroAddress();
        if (newGovernor == governor) revert SameGovernor();
        return _queue(Kind.SET_GOVERNOR, bytes32(0), _params.paramsDelay, abi.encode(newGovernor));
    }

    /// @notice The second step of the handover.
    function acceptGovernor() external {
        address p = pendingGovernor;
        if (p == address(0) || msg.sender != p) revert NotPendingGovernor();
        emit GovernorAccepted(governor, p);
        governor = p;
        pendingGovernor = address(0);
    }

    // ================================================================ guardian

    /// @notice Emergency freeze of new registrations, effective immediately.
    /// @dev Touches only this record's status and frozenAt. It does NOT call or
    /// otherwise affect the registrar (§12.0: the root calls nothing on it);
    /// existing names keep resolving, unchanged (§12.0a).
    function guardianFreeze(bytes32 labelHash) external onlyGuardian {
        _requireStatus(labelHash, NsStatus.ACTIVE);
        _freeze(labelHash, true);
    }

    /// @notice The guardian steps down. Reducing its own power needs no vote.
    function resignGuardian() external onlyGuardian {
        _setGuardian(address(0), 0);
    }

    /// @notice Veto a queued action. Callable by the governor or an unexpired
    /// guardian.
    /// @dev A RETIRE action cannot be cancelled once its eta (== retiresAt) has
    /// passed. Retirement is then final by TIME ALONE, which is what lets a
    /// resolver treat `RETIRING && now >= retiresAt` as RETIRED without waiting
    /// for someone to execute it, and without a later cancel reviving names
    /// that resolvers have already stopped serving.
    function cancel(uint256 id) external {
        if (msg.sender != governor && !(guardianActive() && msg.sender == guardian)) {
            revert NotGuardian();
        }
        Action storage a = _actions[id];
        if (a.state != ActionState.QUEUED) revert NotQueued(id);
        if (a.kind == Kind.RETIRE && block.timestamp >= a.eta) revert RetirementFinal(id);
        a.state = ActionState.CANCELLED;

        if (a.kind == Kind.CREATE) {
            // The proposal returns to PROPOSED with its bond still held; whether
            // to re-queue, slash or return it is the governor's call, not the
            // guardian's -- a veto does not move money.
            delete pendingCreate[a.subject];
        } else if (a.kind == Kind.RETIRE) {
            Namespace storage ns = _ns[a.subject];
            ns.status = ns.frozenAt != 0 ? NsStatus.FROZEN : NsStatus.ACTIVE;
            ns.retiresAt = 0;
            emit RetirementCancelled(a.subject);
        }
        emit ActionCancelled(id, msg.sender);
    }

    // ================================================================ execute

    /// @notice Execute a queued action whose delay has passed. Permissionless.
    /// @param payload the exact bytes emitted in ActionQueued for `id`.
    function execute(uint256 id, bytes calldata payload) external {
        Action storage a = _actions[id];
        if (a.state != ActionState.QUEUED) revert NotQueued(id);
        if (block.timestamp < a.eta) revert TooEarly(id, a.eta);
        if (keccak256(payload) != a.payloadHash) revert BadPayload(id);
        a.state = ActionState.EXECUTED;
        Kind k = a.kind;

        if (k == Kind.CREATE) {
            _executeCreate(abi.decode(payload, (string)));
        } else if (k == Kind.FREEZE) {
            bytes32 h = abi.decode(payload, (bytes32));
            _requireStatus(h, NsStatus.ACTIVE);
            _freeze(h, false);
        } else if (k == Kind.UNFREEZE) {
            bytes32 h = abi.decode(payload, (bytes32));
            _requireStatus(h, NsStatus.FROZEN);
            _ns[h].status = NsStatus.ACTIVE;
            _ns[h].frozenAt = 0;
            emit NamespaceUnfrozen(h);
        } else if (k == Kind.RETIRE) {
            bytes32 h = abi.decode(payload, (bytes32));
            // Status can only be RETIRING here: leaving RETIRING requires
            // cancelling this very action. Checked anyway.
            _requireStatus(h, NsStatus.RETIRING);
            _ns[h].status = NsStatus.RETIRED;
            emit NamespaceRetired(h);
        } else if (k == Kind.SET_RESERVED) {
            (string[] memory labels, bool reserved) = abi.decode(payload, (string[], bool));
            for (uint256 i; i < labels.length; ++i) _setReserved(labels[i], reserved);
        } else if (k == Kind.SET_IANA) {
            (string[] memory labels, bool delegated, uint64 snapshotAt) =
                abi.decode(payload, (string[], bool, uint64));
            for (uint256 i; i < labels.length; ++i) _setIana(labels[i], delegated);
            if (snapshotAt != 0) {
                ianaSnapshotAt = snapshotAt;
                emit IanaSnapshot(snapshotAt);
            }
        } else if (k == Kind.SET_PARAMS) {
            Params memory p = abi.decode(payload, (Params));
            _checkParams(p);
            _params = p;
            emit ParamsSet(p);
        } else if (k == Kind.ADD_SCHEMA) {
            (uint16 version, bytes32 spec) = abi.decode(payload, (uint16, bytes32));
            // Two queued adds for one version: the second must not overwrite.
            if (schemaSpec[version] != bytes32(0)) revert SchemaExists(version);
            schemaSpec[version] = spec;
            emit SchemaAdded(version, spec);
        } else if (k == Kind.ADOPT_SCHEMA) {
            (bytes32 h, uint16 version) = abi.decode(payload, (bytes32, uint16));
            _checkAdopt(h, version);
            uint16 from = _ns[h].recordSchema;
            _ns[h].recordSchema = version;
            emit SchemaAdopted(h, from, version);
        } else if (k == Kind.SET_GUARDIAN) {
            (address g, uint64 expiresAt) = abi.decode(payload, (address, uint64));
            _setGuardian(g, expiresAt);
        } else if (k == Kind.SET_GOVERNOR) {
            address next = abi.decode(payload, (address));
            pendingGovernor = next;
            emit GovernorPending(next);
        }
        emit ActionExecuted(id, k);
    }

    // ================================================================ internal

    function _queue(Kind kind, bytes32 subject, uint64 delay, bytes memory payload)
        internal returns (uint256 id)
    {
        id = ++actionCount;
        uint64 eta = uint64(block.timestamp) + delay;
        _actions[id] = Action({
            kind: kind,
            state: ActionState.QUEUED,
            eta: eta,
            subject: subject,
            payloadHash: keccak256(payload)
        });
        emit ActionQueued(id, kind, subject, eta, payload);
    }

    function _executeCreate(string memory label) internal {
        bytes32 h = keccak256(bytes(label));
        Namespace storage ns = _ns[h];
        if (ns.status != NsStatus.PROPOSED) revert BadStatus(ns.status);
        // Re-run the predicate: the IANA snapshot or the reserved list may have
        // changed during the timelock (§11.0.2: "the real root does not stop
        // moving").
        Ineligibility why = _eligibility(label);
        if (why != Ineligibility.NONE) revert Ineligible(why);
        address registrar = ns.registrar;
        if (registrar.code.length == 0) revert NotAContract(registrar);
        bytes32 used = registrarNamespace[registrar];
        if (used != bytes32(0)) revert RegistrarInUse(registrar, used);

        delete pendingCreate[h];
        ns.status = NsStatus.ACTIVE;
        ns.activatedAt = uint64(block.timestamp);
        registrarNamespace[registrar] = h;
        emit NamespaceActivated(h, label, registrar, ns.registrarClass, ns.recordSchema,
                                uint64(block.timestamp));

        // "Returned on activation" (§12.0a).
        uint256 bond = ns.bond;
        address proposer = proposals[h].proposer;
        ns.bond = 0;
        delete proposals[h];
        if (bond != 0) token.safeTransfer(proposer, bond);
    }

    function _closeProposal(bytes32 labelHash, bool slash, bool byGovernor) internal {
        uint256 bond = _ns[labelHash].bond;
        address proposer = proposals[labelHash].proposer;
        delete _ns[labelHash];
        delete proposals[labelHash];
        emit ProposalClosed(labelHash, proposer, bond, slash, byGovernor);
        if (bond != 0) token.safeTransfer(slash ? treasury : proposer, bond);
    }

    function _freeze(bytes32 labelHash, bool byGuardian) internal {
        Namespace storage ns = _ns[labelHash];
        ns.status = NsStatus.FROZEN;
        ns.frozenAt = uint64(block.timestamp);
        emit NamespaceFrozen(labelHash, uint64(block.timestamp), byGuardian);
    }

    function _requireStatus(bytes32 labelHash, NsStatus want) internal view {
        NsStatus st = _ns[labelHash].status;
        if (st != want) revert BadStatus(st);
    }

    function _checkAdopt(bytes32 labelHash, uint16 version) internal view {
        Namespace storage ns = _ns[labelHash];
        if (ns.status != NsStatus.ACTIVE && ns.status != NsStatus.FROZEN) revert BadStatus(ns.status);
        if (schemaSpec[version] == bytes32(0)) revert UnknownSchema(version);
        if (version <= ns.recordSchema) revert SchemaNotNewer(ns.recordSchema, version);
    }

    function _checkParams(Params memory p) internal pure {
        _checkDelay(p.createDelay,  MIN_CREATE_DELAY);
        _checkDelay(p.freezeDelay,  MIN_FREEZE_DELAY);
        _checkDelay(p.retireNotice, MIN_RETIRE_NOTICE);
        _checkDelay(p.listDelay,    MIN_LIST_DELAY);
        _checkDelay(p.paramsDelay,  MIN_PARAMS_DELAY);
        _checkDelay(p.schemaDelay,  MIN_SCHEMA_DELAY);
    }

    function _checkDelay(uint64 d, uint64 min) internal pure {
        if (d < min || d > MAX_DELAY) revert DelayOutOfRange(d, min, MAX_DELAY);
    }

    function _setGuardian(address g, uint64 expiresAt) internal {
        if (g == address(0)) {
            expiresAt = 0;
        } else if (expiresAt <= block.timestamp || expiresAt > block.timestamp + MAX_GUARDIAN_TERM) {
            revert BadGuardianTerm(expiresAt);
        }
        guardian = g;
        guardianExpiresAt = expiresAt;
        emit GuardianSet(g, expiresAt);
    }

    function _setReserved(string memory label, bool reserved) internal {
        bytes32 h = keccak256(bytes(label));
        reservedLabel[h] = reserved;
        emit ReservedSet(h, label, reserved);
    }

    function _setIana(string memory label, bool delegated) internal {
        bytes32 h = keccak256(bytes(label));
        ianaDelegated[h] = delegated;
        emit IanaSet(h, label, delegated);
    }

    // ------------------------------------------------------------ eligibility

    /// @dev §11.0.2 part 3 and §11.3.1, everything that is deterministic,
    /// checked on chain. What is DATA (the IANA snapshot) is a governor-updatable
    /// hashed set; what is fixed by standard or by AXON's own design is code.
    function _eligibility(string memory label) internal view returns (Ineligibility) {
        bytes memory b = bytes(label);
        uint256 n = b.length;
        if (n < MIN_NS_LEN || n > MAX_NS_LEN) return Ineligibility.LENGTH;
        for (uint256 i; i < n; ++i) {
            bytes1 c = b[i];
            if (!((c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39) || c == 0x2d)) {
                return Ineligibility.CHARSET;
            }
        }
        if (b[0] == 0x2d || b[n - 1] == 0x2d) return Ineligibility.HYPHEN;
        if (n >= 4 && b[2] == 0x2d && b[3] == 0x2d) return Ineligibility.IDNA_PREFIX;

        bytes32 h = keccak256(b);
        if (h == ROOT_LABEL_HASH) return Ineligibility.ROOT_SUFFIX;
        if (_isSpecialUse(h)) return Ineligibility.SPECIAL_USE;
        if (_isAxonReserved(h)) return Ineligibility.AXON_RESERVED;
        if (ianaDelegated[h]) return Ineligibility.IANA_DELEGATED;
        if (reservedLabel[h]) return Ineligibility.RESERVED_LIST;
        return Ineligibility.NONE;
    }

    /// @dev Single-label entries of the IANA Special-Use Domain Names registry
    /// (RFC 6761 example/invalid/localhost/test, RFC 6762 local, RFC 7686 onion,
    /// RFC 9476 alt), plus `arpa` (infrastructure TLD; every special-use name
    /// below it -- home.arpa, resolver.arpa, ... -- is multi-label and so
    /// collides through it) and `internal` (reserved by ICANN for private use in
    /// 2024; in neither the root zone nor the special-use registry, so neither
    /// the snapshot nor RFC 6761 would catch it).
    ///
    /// FIXED IN CODE, NO SETTER. A standard reservation does not stop being one
    /// because a governor says so. Additions go on the reserved list.
    function _isSpecialUse(bytes32 h) internal pure returns (bool) {
        return h == keccak256("alt")
            || h == keccak256("arpa")
            || h == keccak256("example")
            || h == keccak256("internal")
            || h == keccak256("invalid")
            || h == keccak256("local")
            || h == keccak256("localhost")
            || h == keccak256("onion")
            || h == keccak256("test");
    }

    /// @dev AXON's own reservations (§11.3.1): `key` holds the Layer 1
    /// self-certifying addresses (§11.9) and must never be shadowed by a
    /// governed namespace; `srv` is reserved alongside it. The root suffix is
    /// checked separately so its refusal says ROOT_SUFFIX. Fixed in code.
    function _isAxonReserved(bytes32 h) internal pure returns (bool) {
        return h == keccak256("key") || h == keccak256("srv");
    }
}
