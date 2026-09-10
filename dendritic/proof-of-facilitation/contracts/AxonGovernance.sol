// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @notice The subset of AxonRegistry this contract is the governor of.
interface IAxonRegistryGovernance {
    function prune(bytes32 nameHash, uint256 proposalId) external;
    function seize(bytes32 nameHash, uint256 proposalId) external;
    function restore(bytes32 nameHash, uint256 proposalId) external;
}

/// @notice A source of one component of voting weight.
///
/// Separate from this contract because three of the four are not measurable yet
/// (F-94.1) and the two that will be — infrastructure contribution and §88
/// reputation — are produced by systems that do not exist. An interface lets
/// them arrive later without redeploying governance; `available()` lets this
/// contract tell "measured zero" from "not measurable", which is the whole
/// difference F-94.1 turns on.
interface IWeightSource {
    function weightOf(address account) external view returns (uint256);
    function available() external view returns (bool);
}

/// @title AxonGovernance — the DAO vote, on chain (G8, §94).
///
/// WHY THIS EXISTS AT ALL. F-94.1: `DaoProposal` and `DaoVote` are tables in one
/// web server's Postgres, and `onchain_ref` is nullable with the comment "Set
/// once the Governance contract exists". It did not exist. That is load-bearing
/// for §93: if chain state is authoritative and the vote producing it is a row
/// in one server's database, then "the blockchain is authoritative" means
/// "whatever that server writes is authoritative" — a centralised oracle in a
/// blockchain costume.
///
/// E-G8 IS THE DESIGN CONSTRAINT: a tally must be reconstructible from chain
/// state alone, with the web server stopped. So every vote is a storage write
/// here and a tally is a pure read of `proposals[id]`. Nothing off-chain is
/// consulted, and there is no admin path that adjusts a tally.
///
/// R-94.1 IS ENFORCED, NOT DOCUMENTED. Global prunes on jurisdictional grounds —
/// ILLEGAL, EXTREMIST, COPYRIGHT — are permanently out of scope, because those
/// are conflicts of laws and a majority vote does not resolve one, it exports
/// one jurisdiction's answer to everybody. `propose()` REVERTS on those
/// categories rather than relying on voters to decline: a rule that lives only
/// in prose is a rule that holds until the first motivated majority.
///
/// F-94.1 IS ENFORCED TOO, AND THIS IS THE PART THAT WILL SURPRISE. Only
/// `participation` is measurable today, so the deployed weighting is
/// one-member-one-vote — the Sybil-bait case §94 warned about. A governance
/// contract that shipped anyway, with power to seize names, would look correct
/// and be trivially captured. So execution of a REGISTRY ACTION requires the
/// live weight sources to cover at least `minCoverageBps` of SCORE_WEIGHTS.
/// With only participation live, coverage is 2000 bps; a deployment demanding
/// more simply cannot prune until A4 and §88 land. Voting still works, tallies
/// still accrue, and the authority is what is withheld.
contract AxonGovernance is Ownable {
    // ------------------------------------------------------------------ types

    /// @notice What a proposal asks for.
    ///
    /// SIGNAL exists so the DAO can decide things that are not registry writes —
    /// parameters, procedure, category definitions (§94's in-scope list). Most
    /// governance is not a seizure and should not have to pretend to be one.
    enum Action { SIGNAL, PRUNE, SEIZE, RESTORE }

    enum Status { ACTIVE, PASSED, REJECTED, EXECUTED, CANCELLED }

    /// @notice §86's categories, as the vote sees them.
    ///
    /// Only the ones governance may act on are named; the jurisdictional three
    /// are named ONLY so `propose()` can refuse them by name. An enum that
    /// omitted them would make the refusal impossible to express and the rule
    /// unenforceable — the failure R-94.1 is guarding against.
    enum Category {
        UNSPECIFIED,
        MALWARE,
        FRAUD,
        SPAM,
        // ---- permanently out of scope (R-94.1) ----
        ILLEGAL,
        EXTREMIST,
        COPYRIGHT
    }

    struct Proposal {
        address proposer;
        Action  action;
        Category category;
        bytes32 subject;        // nameHash for registry actions; free for SIGNAL
        bytes32 evidence;       // CID of the §89 report set, content-addressed
        uint64  opensAt;
        uint64  closesAt;
        Status  status;
        uint256 forWeight;
        uint256 againstWeight;
        uint256 voterCount;
    }

    // ---------------------------------------------------------------- storage

    /// @notice §94's SCORE_WEIGHTS, on chain and immutable, so the split is
    /// auditable by anyone rather than by whoever can read `model/Dao.py`.
    ///
    /// Stake is deliberately the SMALLEST term: the wealthiest party does not
    /// decide what the network suppresses.
    uint16 public constant W_INFRA         = 40;
    uint16 public constant W_REPUTATION    = 30;
    uint16 public constant W_PARTICIPATION = 20;
    uint16 public constant W_STAKE         = 10;
    uint16 public constant W_TOTAL         = 100;

    /// @notice The four sources, in SCORE_WEIGHTS order. Unset ones are dark.
    IWeightSource public infraSource;
    IWeightSource public reputationSource;
    IWeightSource public participationSource;
    IWeightSource public stakeSource;

    /// @notice Minimum share of SCORE_WEIGHTS that must be LIVE before a
    /// registry action may execute, in basis points of W_TOTAL.
    ///
    /// Immutable, and the constructor refuses a value that would let a
    /// participation-only deployment seize names. See the constructor.
    uint16 public immutable minCoverageBps;

    IAxonRegistryGovernance public registry;

    uint64 public votingPeriod;
    /// @notice Weight that must vote FOR, in bps of total weight cast.
    uint16 public passThresholdBps;
    /// @notice Minimum total weight cast for a vote to count at all.
    uint256 public quorumWeight;

    Proposal[] public proposals;

    /// @notice proposalId => voter => weight recorded. E-G8's storage: a tally
    /// is reconstructible from here with nothing else running.
    mapping(uint256 => mapping(address => uint256)) public weightCast;
    mapping(uint256 => mapping(address => bool)) public votedFor;

    // ----------------------------------------------------------------- events

    event ProposalCreated(uint256 indexed id, address indexed proposer, Action action, Category category, bytes32 subject, bytes32 evidence, uint64 closesAt);
    event VoteCast(uint256 indexed id, address indexed voter, bool support, uint256 weight);
    event ProposalFinalised(uint256 indexed id, Status status, uint256 forWeight, uint256 againstWeight);
    event ProposalExecuted(uint256 indexed id, Action action, bytes32 subject);
    event WeightSourceSet(uint8 indexed slot, address source);
    event RegistrySet(address registry);

    // ----------------------------------------------------------------- errors

    error JurisdictionalCategoryOutOfScope(Category category);
    error RegistryActionNeedsSubject();
    error RegistryActionNeedsEvidence();
    error NoRegistry();
    error VotingClosed();
    error VotingOpen();
    error AlreadyVoted();
    error NoWeight();
    error NotPassed();
    error AlreadyFinalised();
    error CoverageTooLow(uint16 liveBps, uint16 requiredBps);
    error BadThreshold();
    error BadCoverage();
    error BadPeriod();

    // ------------------------------------------------------------ constructor

    constructor(
        address initialOwner,
        uint64  votingPeriod_,
        uint16  passThresholdBps_,
        uint256 quorumWeight_,
        uint16  minCoverageBps_
    ) Ownable(initialOwner) {
        // A zero voting period closes a proposal in the block it opens, which is
        // a governance system with one voter: the proposer.
        if (votingPeriod_ == 0) revert BadPeriod();
        // Below half, a proposal passes that most weight opposed.
        if (passThresholdBps_ < 5000 || passThresholdBps_ > 10000) revert BadThreshold();
        // REFUSED IN THE CONSTRUCTOR, for the same reason AxonRegistry refuses a
        // zero SEIZE_QUARANTINE: a deployment carrying it would look correct.
        // W_PARTICIPATION alone is 2000 bps, and it is the ONLY source live
        // today (F-94.1), so anything at or below 2000 permits a
        // one-member-one-vote DAO to seize names. That is the exact capture
        // §94 warned about, and it must not be reachable by configuration.
        if (minCoverageBps_ <= 2000 || minCoverageBps_ > 10000) revert BadCoverage();
        votingPeriod = votingPeriod_;
        passThresholdBps = passThresholdBps_;
        quorumWeight = quorumWeight_;
        minCoverageBps = minCoverageBps_;
    }

    // ------------------------------------------------------------------ admin

    function setRegistry(address registry_) external onlyOwner {
        registry = IAxonRegistryGovernance(registry_);
        emit RegistrySet(registry_);
    }

    /// @notice Wire a weight source. Slot order is SCORE_WEIGHTS order.
    function setWeightSource(uint8 slot, address source) external onlyOwner {
        if (slot == 0) infraSource = IWeightSource(source);
        else if (slot == 1) reputationSource = IWeightSource(source);
        else if (slot == 2) participationSource = IWeightSource(source);
        else stakeSource = IWeightSource(source);
        emit WeightSourceSet(slot, source);
    }

    // ----------------------------------------------------------------- weight

    /// @notice How much of SCORE_WEIGHTS is actually measurable right now.
    ///
    /// PUBLIC AND PURE-READ ON PURPOSE. F-94.1's finding is that 75 % of the
    /// scheme is dark, and the honest thing is not a comment but a number
    /// anybody can query from chain state.
    function liveCoverageBps() public view returns (uint16 bps) {
        uint256 live;
        if (_sourceLive(infraSource))         live += W_INFRA;
        if (_sourceLive(reputationSource))    live += W_REPUTATION;
        if (_sourceLive(participationSource)) live += W_PARTICIPATION;
        if (_sourceLive(stakeSource))         live += W_STAKE;
        return uint16((live * 10000) / W_TOTAL);
    }

    function _sourceLive(IWeightSource s) internal view returns (bool) {
        if (address(s) == address(0)) return false;
        // A source that reverts is DARK, not zero. Treating a broken oracle as
        // "everyone scores 0" would silently drop a live component out of the
        // denominator and change every tally without anyone noticing.
        try s.available() returns (bool ok) { return ok; } catch { return false; }
    }

    function _componentWeight(IWeightSource s, address account) internal view returns (uint256) {
        if (!_sourceLive(s)) return 0;
        try s.weightOf(account) returns (uint256 w) { return w; } catch { return 0; }
    }

    /// @notice One account's voting weight under §94's scheme.
    ///
    /// NORMALISED BY LIVE WEIGHT, NOT BY W_TOTAL. Dividing by 100 while three
    /// sources are dark would scale everybody down by the same 4x and change no
    /// outcome, while making the numbers look like a full scheme was running.
    /// Dividing by what is live says plainly that this is a partial scheme.
    function weightOf(address account) public view returns (uint256) {
        uint256 acc;
        uint256 denom;
        if (_sourceLive(infraSource))         { acc += _componentWeight(infraSource, account) * W_INFRA; denom += W_INFRA; }
        if (_sourceLive(reputationSource))    { acc += _componentWeight(reputationSource, account) * W_REPUTATION; denom += W_REPUTATION; }
        if (_sourceLive(participationSource)) { acc += _componentWeight(participationSource, account) * W_PARTICIPATION; denom += W_PARTICIPATION; }
        if (_sourceLive(stakeSource))         { acc += _componentWeight(stakeSource, account) * W_STAKE; denom += W_STAKE; }
        if (denom == 0) return 0;
        return acc / denom;
    }

    // -------------------------------------------------------------- proposing

    function proposalCount() external view returns (uint256) { return proposals.length; }

    /// @notice Open a proposal.
    ///
    /// R-94.1's out-of-scope categories are refused HERE, at creation, so an
    /// out-of-scope proposal never exists to be voted on. Refusing at execution
    /// instead would let a majority record a passed vote to suppress content on
    /// jurisdictional grounds and leave the refusal looking like a technicality.
    function propose(
        Action action,
        Category category,
        bytes32 subject,
        bytes32 evidence
    ) external returns (uint256 id) {
        if (category == Category.ILLEGAL || category == Category.EXTREMIST || category == Category.COPYRIGHT) {
            revert JurisdictionalCategoryOutOfScope(category);
        }
        if (action != Action.SIGNAL) {
            if (subject == bytes32(0)) revert RegistryActionNeedsSubject();
            // R-89.1, one layer up: a registry action must name content-addressed
            // evidence. Evidence at a URL can be withdrawn after the vote,
            // leaving a governance record that says a thing happened with
            // nothing behind it.
            if (evidence == bytes32(0)) revert RegistryActionNeedsEvidence();
        }

        id = proposals.length;
        proposals.push(Proposal({
            proposer: msg.sender,
            action: action,
            category: category,
            subject: subject,
            evidence: evidence,
            opensAt: uint64(block.timestamp),
            closesAt: uint64(block.timestamp) + votingPeriod,
            status: Status.ACTIVE,
            forWeight: 0,
            againstWeight: 0,
            voterCount: 0
        }));
        emit ProposalCreated(id, msg.sender, action, category, subject, evidence, uint64(block.timestamp) + votingPeriod);
    }

    // ----------------------------------------------------------------- voting

    /// @notice Cast a vote. Weight is read AT THE MOMENT OF VOTING and stored.
    ///
    /// Stored rather than recomputed at tally time, because a source whose
    /// answer moves would otherwise let weight shift after the fact — and a
    /// tally that changes without anybody voting is not reconstructible in the
    /// sense E-G8 requires.
    function castVote(uint256 id, bool support) external {
        Proposal storage p = proposals[id];
        if (p.status != Status.ACTIVE) revert AlreadyFinalised();
        if (block.timestamp >= p.closesAt) revert VotingClosed();
        if (weightCast[id][msg.sender] != 0) revert AlreadyVoted();

        uint256 w = weightOf(msg.sender);
        if (w == 0) revert NoWeight();

        weightCast[id][msg.sender] = w;
        votedFor[id][msg.sender] = support;
        if (support) p.forWeight += w; else p.againstWeight += w;
        p.voterCount += 1;
        emit VoteCast(id, msg.sender, support, w);
    }

    /// @notice Close voting and record the outcome. Permissionless.
    ///
    /// Permissionless because requiring a privileged call to notice a deadline
    /// had passed would let inaction hold a proposal open indefinitely — the
    /// same reason AxonRegistry's makeRecyclable() is permissionless.
    function finalise(uint256 id) external {
        Proposal storage p = proposals[id];
        if (p.status != Status.ACTIVE) revert AlreadyFinalised();
        if (block.timestamp < p.closesAt) revert VotingOpen();

        uint256 cast = p.forWeight + p.againstWeight;
        bool passed = cast >= quorumWeight
            && cast > 0
            && (p.forWeight * 10000) / cast >= passThresholdBps;

        p.status = passed ? Status.PASSED : Status.REJECTED;
        emit ProposalFinalised(id, p.status, p.forWeight, p.againstWeight);
    }

    // --------------------------------------------------------------- executing

    /// @notice Carry a passed proposal into the registry.
    ///
    /// THE COVERAGE GATE LIVES HERE. A SIGNAL proposal executes regardless — it
    /// changes no state and withholding it would be pointless — but anything
    /// that touches a name requires the weighting behind the vote to be more
    /// than participation counting. See minCoverageBps.
    function execute(uint256 id) external {
        Proposal storage p = proposals[id];
        if (p.status != Status.PASSED) revert NotPassed();

        p.status = Status.EXECUTED;

        if (p.action == Action.SIGNAL) {
            emit ProposalExecuted(id, p.action, p.subject);
            return;
        }

        uint16 live = liveCoverageBps();
        if (live < minCoverageBps) revert CoverageTooLow(live, minCoverageBps);
        if (address(registry) == address(0)) revert NoRegistry();

        if (p.action == Action.PRUNE)        registry.prune(p.subject, id);
        else if (p.action == Action.SEIZE)   registry.seize(p.subject, id);
        else                                 registry.restore(p.subject, id);

        emit ProposalExecuted(id, p.action, p.subject);
    }

    /// @notice The proposer may withdraw their own ACTIVE proposal.
    function cancel(uint256 id) external {
        Proposal storage p = proposals[id];
        if (p.proposer != msg.sender) revert NotPassed();
        if (p.status != Status.ACTIVE) revert AlreadyFinalised();
        p.status = Status.CANCELLED;
        emit ProposalFinalised(id, p.status, p.forWeight, p.againstWeight);
    }

    /// @notice The full tally, from chain state alone. E-G8.
    function tally(uint256 id) external view returns (
        Status status, uint256 forWeight, uint256 againstWeight, uint256 voterCount, bool executable
    ) {
        Proposal storage p = proposals[id];
        return (
            p.status, p.forWeight, p.againstWeight, p.voterCount,
            p.status == Status.PASSED
                && (p.action == Action.SIGNAL || liveCoverageBps() >= minCoverageBps)
        );
    }
}
