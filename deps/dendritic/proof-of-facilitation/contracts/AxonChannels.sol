// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title AxonChannels — off-chain value transfer for AXON.
///
/// Bilateral payment channels, hash-locked routing, delegated signing and
/// checkpoints. Named for what it does rather than for its position in a
/// sequence: it was `AxonChannels`, and a version number in a type name
/// stops describing anything the moment the version it succeeded is gone.
///
/// TWO ADDRESSES THIS RENAME DOES NOT CHANGE
/// -----------------------------------------
/// A rename is a SOURCE change. It does not alter deployed bytecode, deployed
/// addresses, or the name either instance was verified under on a block
/// explorer.
///
///   0x2a2a1b58d5cdb1e89b385e51681658e663a1a03c   THIS contract, live on
///                                                Ethereum mainnet from block
///                                                25757314. Still there, still
///                                                called AxonChannels on
///                                                chain.
///
///   0xae70526931FF460894133201f6C8cA91bbA0E177   V1, ALSO STILL DEPLOYED. Its
///                                                source was removed from this
///                                                tree along with its tests.
///                                                Deleting source does not
///                                                close a channel: if anyone
///                                                holds funds in a V1 channel
///                                                they need V1's ABI to settle,
///                                                and it is recoverable from
///                                                git history, not gone.
///
/// WHAT V1 COULD NOT EXPRESS
/// -------------------------
/// V1 was a complete bilateral channel and nothing here replaces that
/// reasoning: a newer signed state must always beat an older one, both parties
/// sign every state, and a unilateral close opens a challenge window anyone can
/// answer.
///
/// What V1 cannot express is a payment that is not yet anybody's. A direct tip
/// does not need one — the two parties simply agree a new balance. A ROUTED tip
/// does, because the middle of a route must be able to forward value without
/// being able to keep it. That is what a hash lock buys: the hop is committed to
/// a secret it does not know, so it can neither steal the payment nor be left
/// out of pocket when the payment completes downstream.
///
/// THE DIGEST COMMITS TO THE LOCKS. THIS IS THE WHOLE POINT.
/// --------------------------------------------------------
/// V1's digest covers (chainid, contract, id, nonce, balanceA, balanceB). If
/// locks were carried alongside a digest that did not cover them, a party could
/// sign a state and then present it with the locks removed: the signature
/// verifies, conservation appears to hold against the two balances alone, and
/// the locked value is simply gone. Money destroyed by omission.
///
/// So there is exactly ONE digest here and it always includes htlcRoot. With no
/// locks the root is zero. There is deliberately no second, lock-free digest to
/// choose between, because a choice is a place to choose wrongly.
///
/// LOCKED VALUE BELONGS TO NEITHER PARTY
/// -------------------------------------
/// While a lock is live its amount is in neither balance. Conservation is
///     balanceA + balanceB + sum(locks) == depositA + depositB
/// Folding a lock into the payer's balance would let them sign it away twice —
/// once as a lock and once as a balance — and both signatures would verify.
///
/// WHY THE FULL LOCK SET IS PASSED RATHER THAN A MERKLE PROOF
/// ----------------------------------------------------------
/// A tipping channel holds no locks at all in the common case and one or two
/// during a routed payment. A Merkle tree would add a proof format, a second
/// hashing convention to keep in sync with the off-chain code, and a class of
/// bug where the tree and the leaf disagree. Passing the set and rehashing it is
/// simple enough to be obviously correct, and the cost is paid only on a force
/// close, which should be rare.
///
/// The set must arrive sorted by id and free of duplicates. That makes the
/// encoding canonical, so one lock set has one root — and it is the same order
/// the off-chain State.HTLCRoot() produces, deliberately, because a contract and
/// a node that disagree about ordering disagree about money.
contract AxonChannels {
    using SafeERC20 for IERC20;

    IERC20 public immutable token;

    /// @dev Challenge window. Long enough that an offline party (or their
    /// watchtower) can realistically notice and respond, short enough that
    /// closing is not a week-long ordeal. Immutable because changing it under
    /// open channels would alter the safety margin people opened under.
    uint256 public immutable challengePeriod;

    enum Status { None, Open, Closing, Settled }

    struct Channel {
        address partyA;
        address partyB;
        uint256 depositA;
        uint256 depositB;
        Status status;
        /// @dev Balances as of the best state seen so far.
        uint256 balanceA;
        uint256 balanceB;
        /// @dev Nonce of that state. Monotonic; a challenge must strictly beat it.
        uint64 nonce;
        uint256 challengeEnds;
        /// @dev Commitment to the locks live at that state. Zero when there are
        /// none, which is the ordinary case.
        bytes32 htlcRoot;
        /// @dev Value committed to those locks. Derived from the lock set when
        /// the state is admitted, never taken on trust from the signer.
        uint256 lockedTotal;
    }

    /// @dev A conditional payment in flight.
    struct Lock {
        /// @dev Distinguishes two locks sharing a hash, which happens whenever
        /// one payment is split across paths.
        bytes32 id;
        /// @dev H(preimage). Revealing the preimage claims the amount.
        bytes32 hash;
        uint256 amount;
        /// @dev After this, the payer may reclaim. Each hop of a route needs a
        /// SHORTER window than the hop before it, or an intermediary can be left
        /// having paid downstream with no way to claim upstream. This contract
        /// cannot check that — it sees one channel — so it is the router's job.
        uint256 expiry;
        /// @dev Which side is out of pocket while this lock is live.
        bool payerIsA;
    }

    mapping(bytes32 => Channel) public channels;

    /// @dev channel id => lock id => settled one way or the other. A lock is
    /// resolved exactly once, whether by preimage or by expiry.
    mapping(bytes32 => mapping(bytes32 => bool)) public lockResolved;

    // ---- operation domains ---------------------------------------------------
    //
    // WHAT THESE FIX. Before them, closeCooperative signed
    //     stateDigest(id, nonce, balanceA, balanceB, 0, 0, 0)
    // and closeUnilateral/challenge signed
    //     stateDigest(id, nonce, balanceA, balanceB, root, 0, 0)
    // which are THE SAME BYTES whenever there are no live locks. An ordinary
    // agreed state was therefore already a valid cooperative-close
    // authorization: nobody signed "close the channel", they signed a balance
    // split, and the contract could not tell the difference.
    //
    // With both parties honest that is only a timing surprise — the payout is
    // the agreed split either way. It becomes a real hole the moment a signature
    // may come from a DELEGATE, because an authority granted to countersign
    // payments would silently also authorise an immediate settlement.
    //
    // So the domain is the first word of every digest, and a signature made for
    // one operation cannot be presented as another.
    //
    // Numbering starts at 1. Zero is what an uninitialised variable holds, and
    // no uninitialised variable should ever name a valid operation.
    uint8 internal constant OP_STATE = 1;       // ordinary agreed state: pay, challenge, unilateral exit
    uint8 internal constant OP_COOP_CLOSE = 2;  // settle now, no challenge window
    uint8 internal constant OP_CHECKPOINT = 3;  // take value out, channel stays open

    // ---- delegated signing ---------------------------------------------------
    //
    // A DELEGATE IS AN AUTHORITY TO SIGN, NEVER A PARTY AND NEVER A PAYEE.
    //
    // The problem it solves: a bilateral payment needs the recipient's signature
    // at the moment it happens, so a recipient who is not online cannot be
    // tipped. Letting a volunteer node hold the recipient's own key would make
    // that volunteer the channel party — and therefore, because every payout
    // path pays the party, the person the money actually goes to.
    //
    // Here the party never changes. `Channel` gains no field, `_payout` and
    // `checkpoint` still transfer to ch.partyA/ch.partyB, and nothing in this
    // contract can be made to pay a signer. A compromised delegate can take part
    // in state transitions the counterparty also signs; it cannot become the
    // beneficiary, cannot open channels, and cannot touch this mapping.
    //
    // NOT IN Channel AND NOT IN THE DIGEST, deliberately. Delegation belongs to
    // a party, not to a state. Putting it in the digest would make one economic
    // state hash differently depending on who signed it — two valid digests at
    // one nonce, which is exactly the off-chain I4 failure mode — and would
    // invalidate every state a watchtower already holds.
    struct Delegation {
        /// @dev Who may sign for this party. Zero means no delegate, which is
        /// the state of every address that never opts in.
        address signer;
        /// @dev Hard stop. Expiry is the routine mechanism; revocation is for
        /// compromise. A delegation with no expiry is not offered.
        uint64 expiry;
        /// @dev Permitted operations. Only OP_STATE is grantable today.
        uint32 ops;
        /// @dev Bumped on every change, so an off-chain signer can tell that the
        /// authorization it is acting under has moved.
        uint64 epoch;
    }

    /// @dev party => its single delegation. ONE slot, not a list: two live
    /// delegates could sign two different states at one nonce, and the structure
    /// refuses that rather than a check having to catch it.
    mapping(address => Delegation) public delegations;

    /// @dev Grantable operation bits. Cooperative close is absent BY
    /// CONSTRUCTION — there is no bit to grant, so no argument to setDelegate
    /// can produce that authority. Checkpoint is withheld this iteration.
    uint32 internal constant DELEGABLE_OPS = uint32(1) << OP_STATE;

    event DelegationSet(
        address indexed party, address indexed signer, uint64 expiry, uint32 ops, uint64 epoch
    );
    event DelegationRevoked(address indexed party, address indexed signer, uint64 epoch);

    event ChannelOpened(bytes32 indexed id, address indexed partyA, address indexed partyB, uint256 depositA);
    event Deposited(bytes32 indexed id, address indexed who, uint256 amount);
    event ClosedCooperatively(bytes32 indexed id, uint256 balanceA, uint256 balanceB);
    event CloseStarted(bytes32 indexed id, address indexed by, uint64 nonce, uint256 challengeEnds);
    event Challenged(bytes32 indexed id, uint64 nonce);
    event Settled(bytes32 indexed id, uint256 balanceA, uint256 balanceB);
    event LockClaimed(bytes32 indexed id, bytes32 indexed lockId, bytes32 preimage);
    event LockExpired(bytes32 indexed id, bytes32 indexed lockId);
    event CheckpointApplied(bytes32 indexed id, uint64 nonce, uint256 withdrawA, uint256 withdrawB);

    error NotAParty();
    error WrongStatus();
    error BadSignature();
    error StaleNonce();
    error ChallengeOpen();
    error BalanceMismatch();
    error SamePartyTwice();
    error LocksUnsorted();
    error LocksMismatch();
    error LockAlreadyResolved();
    error LockNotExpired();
    error LockHasExpired();
    error BadPreimage();
    error LocksOutstanding();
    error IndexOutOfRange();
    error NothingToWithdraw();
    error BadDelegate();
    error BadDelegateOps();
    error BadDelegateExpiry();

    constructor(IERC20 token_, uint256 challengePeriod_) {
        require(address(token_) != address(0), "token");
        require(challengePeriod_ >= 1 hours, "challenge too short");
        token = token_;
        challengePeriod = challengePeriod_;
    }

    /// @notice Deterministic channel id for a pair.
    /// @dev Sorted, so channelId(a,b) == channelId(b,a). Without sorting a pair
    /// could open two channels and each party could settle the one that suited
    /// them. Unchanged from V1, and the off-chain DeriveChannelID matches it.
    function channelId(address a, address b) public pure returns (bytes32) {
        return a < b ? keccak256(abi.encode(a, b)) : keccak256(abi.encode(b, a));
    }

    function openChannel(address partner, uint256 deposit) external returns (bytes32 id) {
        if (partner == msg.sender) revert SamePartyTwice();
        id = channelId(msg.sender, partner);
        Channel storage ch = channels[id];
        if (ch.status != Status.None) revert WrongStatus();

        (address a, address b) = msg.sender < partner ? (msg.sender, partner) : (partner, msg.sender);
        ch.partyA = a;
        ch.partyB = b;
        ch.status = Status.Open;

        if (deposit > 0) {
            token.safeTransferFrom(msg.sender, address(this), deposit);
            if (msg.sender == a) ch.depositA = deposit; else ch.depositB = deposit;
        }
        emit ChannelOpened(id, a, b, deposit);
    }

    function deposit(bytes32 id, uint256 amount) external {
        Channel storage ch = channels[id];
        if (ch.status != Status.Open) revert WrongStatus();
        if (msg.sender != ch.partyA && msg.sender != ch.partyB) revert NotAParty();
        token.safeTransferFrom(msg.sender, address(this), amount);
        if (msg.sender == ch.partyA) ch.depositA += amount; else ch.depositB += amount;
        emit Deposited(id, msg.sender, amount);
    }

    /// @notice Canonical commitment to a set of locks.
    /// @dev Must agree byte-for-byte with the off-chain State.HTLCRoot(): each
    /// lock as id || hash || amount || expiry || payerIsA, concatenated in id
    /// order, hashed once. Sorting is REQUIRED rather than performed here, so
    /// that one lock set has exactly one valid encoding and a caller cannot
    /// present the same locks two ways.
    function htlcRoot(Lock[] calldata locks) public pure returns (bytes32) {
        if (locks.length == 0) return bytes32(0);
        bytes memory buf;
        for (uint256 i = 0; i < locks.length; i++) {
            if (i > 0 && uint256(locks[i - 1].id) >= uint256(locks[i].id)) revert LocksUnsorted();
            buf = abi.encodePacked(
                buf, locks[i].id, locks[i].hash, locks[i].amount, locks[i].expiry,
                locks[i].payerIsA ? bytes1(0x01) : bytes1(0x00)
            );
        }
        return keccak256(buf);
    }

    /// @dev The digest both parties sign.
    ///
    /// Includes this contract's address and the chain id, so a state signed for
    /// one deployment cannot be replayed against another. Includes htlcRoot, so
    /// a state cannot be separated from the locks it was agreed with. And
    /// includes the withdrawals, so a state cannot be separated from the value
    /// leaving the channel under it.
    ///
    /// THE WITHDRAWAL FIELDS ARE WHY THERE IS STILL ONLY ONE DIGEST. An ordinary
    /// payment signs withdrawA = withdrawB = 0, which is not a special case — it
    /// is the true statement that this state moves nothing out of the contract.
    /// A separate "checkpoint digest" would have meant two signature formats and
    /// a choice about which to use, and a choice is a place to choose wrongly.
    ///
    /// It also makes the attack impossible rather than merely checked: a caller
    /// cannot present a state signed for a 25 withdrawal and submit it asking
    /// for 75, because 75 is inside the digest the signatures are over.
    /// The FIRST field is the operation domain, so that the same balance split
    /// signed for a payment cannot be presented as a cooperative close. See the
    /// OP_* constants for what that collision was.
    function stateDigest(
        uint8 op,
        bytes32 id, uint64 nonce, uint256 balanceA, uint256 balanceB, bytes32 root,
        uint256 withdrawA, uint256 withdrawB
    ) public view returns (bytes32) {
        return keccak256(abi.encode(
            op, block.chainid, address(this), id, nonce, balanceA, balanceB, root,
            withdrawA, withdrawB
        ));
    }

    // ---- delegation management ----------------------------------------------
    //
    // OWNER-ONLY, AND THERE IS NO OTHER PATH. Both functions authorise on
    // msg.sender and take no signature, so a delegate cannot appoint a
    // successor, extend itself, widen its own mask or revoke anybody. That is
    // enforced by the ABSENCE of a signature-accepting variant rather than by a
    // check inside one — a check can be got round, a missing function cannot.

    /// @notice Authorize `signer` to co-sign this caller's states until `expiry`.
    /// @dev Replaces any existing delegation. One slot per party.
    function setDelegate(address signer, uint64 expiry, uint32 ops) external {
        if (signer == address(0)) revert BadDelegate();
        // A delegate that is also the party is meaningless; a delegate that is
        // this contract would be nonsense. Both are refused rather than left to
        // behave oddly.
        if (signer == msg.sender || signer == address(this)) revert BadDelegate();
        if (ops == 0 || ops & ~DELEGABLE_OPS != 0) revert BadDelegateOps();
        if (expiry <= block.timestamp) revert BadDelegateExpiry();

        Delegation storage d = delegations[msg.sender];
        d.signer = signer;
        d.expiry = expiry;
        d.ops = ops;
        d.epoch += 1;
        emit DelegationSet(msg.sender, signer, expiry, ops, d.epoch);
    }

    /// @notice Withdraw the caller's delegation immediately.
    ///
    /// States the delegate signed but nobody submitted become unusable. That is
    /// correct when the delegate is compromised — its signatures SHOULD die —
    /// and it is why routine rotation should let `expiry` do the work instead.
    /// The cost falls on the revoking party alone: a counterparty's fallback is
    /// an older state, in which this party received less.
    function revokeDelegate() external {
        Delegation storage d = delegations[msg.sender];
        address was = d.signer;
        d.signer = address(0);
        d.expiry = 0;
        d.ops = 0;
        d.epoch += 1;
        emit DelegationRevoked(msg.sender, was, d.epoch);
    }

    /// @notice Whether `signer` may sign operation `op` for `party` right now.
    /// @dev Public so a node can refuse to act under an authorization that has
    /// already lapsed, rather than discovering it when a transaction reverts.
    function canSign(address party, address signer, uint8 op) public view returns (bool) {
        return _maySign(party, signer, op);
    }

    function _maySign(address party, address signer, uint8 op) private view returns (bool) {
        // The party itself always may, delegation or not. Checked FIRST so that
        // nothing about delegation can ever lock an owner out of their own
        // channel.
        if (signer == party) return true;

        Delegation storage d = delegations[party];
        if (d.signer == address(0) || signer != d.signer) return false;
        if (block.timestamp >= d.expiry) return false;
        return d.ops & (uint32(1) << op) != 0;
    }

    /// @notice Take value out of a channel without closing it.
    ///
    /// WHY THIS EXISTS
    /// ---------------
    /// Without it, "settle every hour" means "close every hour": a close plus a
    /// fresh open and deposit, two transactions per interval, and a channel that
    /// keeps ceasing to exist. That breaks routing, in-flight locks, channel
    /// identity and every expectation built on a channel being long-lived — to
    /// achieve something channels exist to avoid.
    ///
    /// So a recipient can draw down accumulated tips and keep the channel open:
    ///
    ///     deposit 1,000, nonce 50            balances 900 / 100
    ///        │  checkpoint: recipient takes 75
    ///        ▼
    ///     deposit   925, nonce 51            balances 900 /  25
    ///                                        channel still Open
    ///
    /// WHAT THE CONTRACT ENFORCES
    /// --------------------------
    ///     old collateral  ==  new collateral  +  what actually left
    ///
    /// checked below as balanceA + balanceB + locked + withdrawA + withdrawB
    /// against the deposits it holds. There is no separate withdrawal ledger and
    /// no way to move value except by both parties signing a state that says so
    /// — which is the whole point. A withdrawal that is not part of an agreed
    /// state is not expressible here.
    ///
    /// Value goes to the channel's own parties, the same destinations a close
    /// pays. A separate payout address would have to be committed to and
    /// authenticated, and is deliberately not a feature.
    /// @dev Checkpoint arguments, bundled.
    ///
    /// A struct because the flat form put this function over Solidity's stack
    /// limit — and because six related numbers that must be signed together
    /// read better as one thing that was agreed than as six that happen to
    /// arrive in order.
    struct CheckpointArgs {
        bytes32 id;
        uint64 nonce;
        uint256 balanceA;
        uint256 balanceB;
        uint256 withdrawA;
        uint256 withdrawB;
    }

    function checkpoint(
        CheckpointArgs calldata a, Lock[] calldata locks,
        bytes calldata sigA, bytes calldata sigB
    ) external {
        Channel storage ch = channels[a.id];
        if (ch.status != Status.Open) revert WrongStatus();
        if (a.withdrawA == 0 && a.withdrawB == 0) revert NothingToWithdraw();
        // Strictly greater, exactly as a challenge must be: a checkpoint moves
        // the channel forward, and reusing a nonce would let one be replayed.
        if (a.nonce <= ch.nonce) revert StaleNonce();

        bytes32 root = htlcRoot(locks);
        _requireSigned(ch, _checkpointDigest(a, root), sigA, sigB, OP_CHECKPOINT);

        uint256 locked = _lockedTotal(locks);
        // old collateral == new collateral + what actually leaves
        if (a.balanceA + a.balanceB + locked + a.withdrawA + a.withdrawB
            != ch.depositA + ch.depositB) {
            revert BalanceMismatch();
        }

        ch.balanceA = a.balanceA;
        ch.balanceB = a.balanceB;
        ch.nonce = a.nonce;
        ch.htlcRoot = root;
        ch.lockedTotal = locked;
        _reduceCollateral(ch, a.withdrawA + a.withdrawB);

        // State written before the transfers, for the same reason _payout does
        // it: the token is trusted, and writing after an external call is the
        // habit that produces reentrancy bugs the one time it is not.
        emit CheckpointApplied(a.id, a.nonce, a.withdrawA, a.withdrawB);
        if (a.withdrawA > 0) token.safeTransfer(ch.partyA, a.withdrawA);
        if (a.withdrawB > 0) token.safeTransfer(ch.partyB, a.withdrawB);
    }

    /// @dev The digest for a checkpoint, in its own frame.
    ///
    /// Inlining this put checkpoint() over the stack limit: seven arguments
    /// pushed while the channel, the locks, both signatures and the root are
    /// still live. Same digest function, one frame further down.
    function _checkpointDigest(CheckpointArgs calldata a, bytes32 root)
        private view returns (bytes32)
    {
        return stateDigest(OP_CHECKPOINT, a.id, a.nonce, a.balanceA, a.balanceB, root, a.withdrawA, a.withdrawB);
    }

    /// @dev Take `out` off the channel's collateral.
    ///
    /// Deliberately NOT "reduce each party's deposit by their own withdrawal".
    /// After any payment the money has moved, so a party can be owed more than
    /// they funded — A deposits nothing, earns 100 from B, and withdraws it.
    /// Subtracting from depositA there would underflow on a perfectly legitimate
    /// withdrawal.
    ///
    /// Only the SUM is ever used: conservation reads depositA + depositB and
    /// nothing reads them apart. So this keeps the total honest and treats the
    /// split as bookkeeping. After a checkpoint the two fields no longer record
    /// who funded what, and nothing depends on them doing so.
    function _reduceCollateral(Channel storage ch, uint256 out) private {
        if (out <= ch.depositA) {
            ch.depositA -= out;
        } else {
            ch.depositB -= (out - ch.depositA);
            ch.depositA = 0;
        }
    }

    /// @notice Settle immediately when both parties agree.
    /// @dev The fast path, and the one that should be taken almost always.
    ///
    /// Requires no locks outstanding. That is not a limitation: two parties who
    /// agree can always resolve a lock into their balances off chain first,
    /// which is what a cooperating pair does anyway. Refusing here keeps the
    /// common path free of lock accounting entirely.
    function closeCooperative(
        bytes32 id, uint64 nonce, uint256 balanceA, uint256 balanceB,
        bytes calldata sigA, bytes calldata sigB
    ) external {
        Channel storage ch = channels[id];
        if (ch.status != Status.Open) revert WrongStatus();
        _requireSigned(ch, stateDigest(OP_COOP_CLOSE, id, nonce, balanceA, balanceB, bytes32(0), 0, 0), sigA, sigB, OP_COOP_CLOSE);
        if (balanceA + balanceB != ch.depositA + ch.depositB) revert BalanceMismatch();

        ch.balanceA = balanceA;
        ch.balanceB = balanceB;
        ch.nonce = nonce;
        ch.status = Status.Settled;
        emit ClosedCooperatively(id, balanceA, balanceB);
        _payout(ch);
    }

    /// @notice Close alone, opening a challenge window.
    /// @dev The function that makes the design trustless: it needs no
    /// cooperation. The submitter may well be submitting an old state, which is
    /// exactly why the window exists.
    ///
    /// The lock set is passed rather than trusted: the contract recomputes the
    /// root and DERIVES the locked total from it. A signer who claimed a locked
    /// total that did not match their own locks would otherwise strand the
    /// difference forever.
    function closeUnilateral(
        bytes32 id, uint64 nonce, uint256 balanceA, uint256 balanceB,
        Lock[] calldata locks, bytes calldata sigA, bytes calldata sigB
    ) external {
        Channel storage ch = channels[id];
        if (ch.status != Status.Open) revert WrongStatus();
        if (msg.sender != ch.partyA && msg.sender != ch.partyB) revert NotAParty();

        bytes32 root = htlcRoot(locks);
        _requireSigned(ch, stateDigest(OP_STATE, id, nonce, balanceA, balanceB, root, 0, 0), sigA, sigB, OP_STATE);
        uint256 locked = _lockedTotal(locks);
        _requireConserved(ch, balanceA, balanceB, locked);

        ch.balanceA = balanceA;
        ch.balanceB = balanceB;
        ch.nonce = nonce;
        ch.htlcRoot = root;
        ch.lockedTotal = locked;
        ch.status = Status.Closing;
        ch.challengeEnds = block.timestamp + challengePeriod;
        emit CloseStarted(id, msg.sender, nonce, ch.challengeEnds);
    }

    /// @notice Replace a submitted state with a newer one.
    /// @dev Deliberately callable by ANYONE, not just the counterparty. A
    /// watchtower holds the newer state and needs no other authority to use it,
    /// which is what lets a party go offline safely.
    function challenge(
        bytes32 id, uint64 nonce, uint256 balanceA, uint256 balanceB,
        Lock[] calldata locks, bytes calldata sigA, bytes calldata sigB
    ) external {
        Channel storage ch = channels[id];
        if (ch.status != Status.Closing) revert WrongStatus();
        if (block.timestamp >= ch.challengeEnds) revert WrongStatus();
        // STRICTLY greater. Equal nonces with different balances would let the
        // last submitter win a coin flip over which state is real.
        if (nonce <= ch.nonce) revert StaleNonce();

        bytes32 root = htlcRoot(locks);
        _requireSigned(ch, stateDigest(OP_STATE, id, nonce, balanceA, balanceB, root, 0, 0), sigA, sigB, OP_STATE);
        uint256 locked = _lockedTotal(locks);
        _requireConserved(ch, balanceA, balanceB, locked);

        ch.balanceA = balanceA;
        ch.balanceB = balanceB;
        ch.nonce = nonce;
        ch.htlcRoot = root;
        ch.lockedTotal = locked;
        emit Challenged(id, nonce);
    }

    /// @notice Claim a locked payment by revealing its preimage.
    /// @dev Callable by anyone holding the secret, which is the payee or someone
    /// acting for them. Only during Closing and only before the lock expires:
    /// after expiry the value is the payer's and handing it to the payee would
    /// be taking it from someone who is already entitled to it back.
    function claimLock(
        bytes32 id, Lock[] calldata locks, uint256 index, bytes32 preimage
    ) external {
        Channel storage ch = channels[id];
        if (ch.status != Status.Closing) revert WrongStatus();
        if (index >= locks.length) revert IndexOutOfRange();
        if (htlcRoot(locks) != ch.htlcRoot) revert LocksMismatch();

        Lock calldata lock = locks[index];
        if (lockResolved[id][lock.id]) revert LockAlreadyResolved();
        if (block.timestamp >= lock.expiry) revert LockHasExpired();
        if (keccak256(abi.encodePacked(preimage)) != lock.hash) revert BadPreimage();

        lockResolved[id][lock.id] = true;
        ch.lockedTotal -= lock.amount;
        // To the party who is NOT the payer.
        if (lock.payerIsA) ch.balanceB += lock.amount; else ch.balanceA += lock.amount;
        emit LockClaimed(id, lock.id, preimage);
    }

    /// @notice Return an expired lock to whoever put it up.
    /// @dev Separate from settle so a long-dated lock does not hold up the rest,
    /// and callable by anyone because a refund takes nothing from anybody.
    function expireLock(bytes32 id, Lock[] calldata locks, uint256 index) external {
        Channel storage ch = channels[id];
        if (ch.status != Status.Closing) revert WrongStatus();
        if (index >= locks.length) revert IndexOutOfRange();
        if (htlcRoot(locks) != ch.htlcRoot) revert LocksMismatch();

        Lock calldata lock = locks[index];
        if (lockResolved[id][lock.id]) revert LockAlreadyResolved();
        if (block.timestamp < lock.expiry) revert LockNotExpired();

        lockResolved[id][lock.id] = true;
        ch.lockedTotal -= lock.amount;
        if (lock.payerIsA) ch.balanceA += lock.amount; else ch.balanceB += lock.amount;
        emit LockExpired(id, lock.id);
    }

    /// @notice Pay out after the window closes.
    /// @dev Refuses while any lock is unresolved. It cannot simply hand them
    /// back: a lock whose expiry has not arrived may still be claimed with the
    /// preimage, and paying it to the payer early would steal a payment that is
    /// legitimately in flight. Call expireLock (or claimLock) first — both are
    /// open to anyone, so nobody can be held hostage by an absent counterparty.
    function settle(bytes32 id) external {
        Channel storage ch = channels[id];
        if (ch.status != Status.Closing) revert WrongStatus();
        if (block.timestamp < ch.challengeEnds) revert ChallengeOpen();
        if (ch.lockedTotal != 0) revert LocksOutstanding();

        ch.status = Status.Settled;
        emit Settled(id, ch.balanceA, ch.balanceB);
        _payout(ch);
    }

    function _lockedTotal(Lock[] calldata locks) private pure returns (uint256 total) {
        for (uint256 i = 0; i < locks.length; i++) {
            total += locks[i].amount;
        }
    }

    /// @dev Total out must equal total in, with locked value counted outside
    /// both balances. Without this a forged pair of signatures could mint from
    /// the contract's other channels — the funds are pooled in one balance, so
    /// one channel over-paying is another channel's deposit disappearing.
    function _requireConserved(
        Channel storage ch, uint256 balanceA, uint256 balanceB, uint256 locked
    ) private view {
        if (balanceA + balanceB + locked != ch.depositA + ch.depositB) revert BalanceMismatch();
    }

    /// @dev Takes the DIGEST rather than its seven components.
    ///
    /// Partly because ten parameters put this over Solidity's stack limit, and
    /// partly because it is the honest shape: this function's job is "do these
    /// two signatures belong to this channel's parties", and what was signed is
    /// the caller's business. Every caller builds it with stateDigest, so there
    /// is still exactly one place the digest is defined.
    function _requireSigned(
        Channel storage ch, bytes32 digest, bytes calldata sigA, bytes calldata sigB, uint8 op
    ) private view {
        // The ONE seam where signer identity is decided, for every path. A
        // delegate is accepted only where _maySign says so; the parties
        // themselves are always accepted. Note what does NOT happen here: the
        // recovered address is never remembered, never written to the channel
        // and never reaches a payout. It answers "may this state be admitted",
        // and nothing else.
        if (!_maySign(ch.partyA, _recover(digest, sigA), op)) revert BadSignature();
        if (!_maySign(ch.partyB, _recover(digest, sigB), op)) revert BadSignature();
    }

    /// @dev Recovers the signer of an EIP-191 prefixed message.
    ///
    /// The prefix is not cosmetic. Recovering from a RAW 32-byte digest is the
    /// pattern that lets a malicious site get a user to sign something which is
    /// simultaneously a valid transaction hash — the signature is then replayable
    /// as a transaction they never agreed to. Prefixing makes a signed channel
    /// state structurally incapable of being anything else, and it is also what
    /// every wallet produces by default, so honest clients need no special path.
    ///
    /// Also carries the malleability guard: without the s-value bound every
    /// signature has a second valid form, so one state could be presented twice
    /// under different bytes.
    function _recover(bytes32 rawDigest, bytes calldata sig) private pure returns (address) {
        bytes32 digest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", rawDigest)
        );
        if (sig.length != 65) revert BadSignature();
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert BadSignature();
        }
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert BadSignature();
        return signer;
    }

    function _payout(Channel storage ch) private {
        uint256 a = ch.balanceA;
        uint256 b = ch.balanceB;
        // Zeroed BEFORE transferring: the token is trusted here, but writing
        // state after an external call is the habit that produces reentrancy
        // bugs the one time the token is not.
        ch.balanceA = 0;
        ch.balanceB = 0;
        ch.depositA = 0;
        ch.depositB = 0;
        if (a > 0) token.safeTransfer(ch.partyA, a);
        if (b > 0) token.safeTransfer(ch.partyB, b);
    }
}
