// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

interface IAxonToken is IERC20 {
    function mint(address to, uint256 amount) external;
    function burn(uint256 amount) external;
}

interface IEpochRewards {
    function epochs(uint64 epoch)
        external
        view
        returns (
            bytes32 receiptRoot,
            bytes32 rewardRoot,
            bytes32 nodeStateRoot,
            bytes32 randomness,
            uint256 totalRewards,
            uint64 submittedAt,
            uint64 challengeDeadline,
            uint32 openDisputes,
            bool finalized
        );
}

/// @title Treasury — the only address that can change AXON supply.
/// @notice `AxonToken` names a Treasury as its sole minter and refuses to mint
/// for anybody else. Until now that address was nothing: the contract did not
/// exist, so the token's entire supply was whatever had been genesis-minted by
/// hand and nodes could not be paid even after an epoch settled, because there
/// was nothing to pay them from.
///
/// This is it. It does exactly two things with supply, and the split between
/// them is the whole design:
///
///   MINTING is permissionless and bounded. Anyone may call `fundEpoch` for a
///   settled epoch; the amount is fixed by that epoch's own `totalRewards`, and
///   refused outright if it exceeds the per-epoch budget or the supply cap.
///
///   SPENDING is owner-only and cannot mint. `release` moves tokens this
///   contract already holds. Sales, grants and airdrops come out of a
///   pre-allocated balance, never out of new supply.
///
/// That split is what makes the cap mean something. If the owner could mint for
/// sales, "a fixed per-epoch budget" would describe only the part of issuance
/// nobody was tempted to exceed, and every holder's share would be dilutable at
/// will by whoever held the key.
contract Treasury is Ownable {
    using SafeERC20 for IERC20;

    IAxonToken public immutable token;
    IEpochRewards public immutable epochManager;

    /// @notice Where epoch rewards are minted to. Nodes claim from here against
    /// the epoch's Merkle root; this contract never pays a node directly.
    address public immutable rewardDistributor;

    /// @notice Hard ceiling on total supply. Immutable — a cap the owner can
    /// raise is not a cap, it is a preference.
    uint256 public immutable maxSupply;

    /// @notice The most that may be minted for any single epoch.
    /// @dev Owner-settable because the right emission rate is not knowable in
    /// advance, and bounded by `maxSupply` regardless of what it is set to.
    uint256 public epochBudget;

    /// @notice How much has been minted for each epoch. Zero means unfunded.
    mapping(uint64 => uint256) public fundedAmount;

    /// @notice A delivered purchase order.
    /// @dev `filledAt` doubles as the existence flag: a non-zero timestamp means
    /// this order has been delivered, which is what makes `releaseOrder`
    /// idempotent. A separate bool would be a second thing to keep in step.
    struct Order {
        address buyer;
        uint256 amount;
        uint64 filledAt;
    }

    /// @notice orderId => what was delivered for it.
    /// @dev orderId is a hash of the off-chain payment reference (a Stripe
    /// session id), never the reference itself. The chain is public and
    /// permanent; a raw session id here would tie a wallet to a payment for
    /// everyone to read, forever. A hash filters exactly as well.
    mapping(bytes32 => Order) public orders;

    event EpochFunded(uint64 indexed epoch, uint256 amount, address indexed caller);
    event EpochBudgetSet(uint256 budget);
    event Released(address indexed to, uint256 amount);
    event Burned(uint256 amount);

    /// @notice A purchase delivered against a specific order.
    /// @dev Distinct from `Released` on purpose. `release` serves three
    /// different intents — a purchase, a grant, seeding liquidity — and emitted
    /// one event for all of them, so nothing on chain could tell them apart.
    /// This event means a purchase and only a purchase.
    ///
    /// `to` and `orderId` are both indexed: those are the two questions anyone
    /// asks of this log ("what did this wallet buy", "was order X filled") and
    /// an indexed topic is filterable by any node without scanning bodies.
    ///
    /// `day` is the third indexed field and exists ONLY to make date queries
    /// possible, because nothing else in the EVM does.
    ///
    /// `eth_getLogs` filters on three things: address, indexed topics, and a
    /// block range. It has no notion of dates, and topics match by EXACT
    /// EQUALITY — there is no >= or <=. So indexing `filledAt` would buy
    /// nothing: it would let a caller ask for the log at exactly one unix
    /// second and nothing else.
    ///
    /// What topics CAN do is match a LIST. Each topic position in an
    /// eth_getLogs filter accepts an array of values, meaning OR. So a
    /// coarse-grained bucket is filterable as a range in a way a raw timestamp
    /// is not: bucket by day, and "1 March to 30 April" becomes an array of 61
    /// day numbers in one call. Exact, complete, and no scanning.
    ///
    /// Days rather than hours or months on purpose. Hours would need 24x the
    /// topic values for the same span and RPC providers cap filter array
    /// length; months would make the narrowest possible query a whole month of
    /// logs to sift client-side. A day is the coarsest bucket somebody would
    /// still call "query by date".
    ///
    /// `filledAt` is kept as well, unindexed, so a reader has the exact second
    /// without fetching a block header per log.
    event PurchaseDelivered(
        address indexed to,
        uint256 amount,
        bytes32 indexed orderId,
        uint32 indexed day,
        uint64 filledAt
    );

    /// @notice The exact second a purchase was delivered, as a searchable topic.
    ///
    /// @dev A second event purely because an event gets THREE indexed slots and
    /// `PurchaseDelivered` already spends them on `to`, `orderId` and `day`.
    /// The alternative was making that event anonymous, which buys a fourth
    /// slot by giving up topic 0 — the event signature. That would cost
    /// signature filtering and stop block explorers decoding a purchase log
    /// people may need to audit, to save roughly 1.1k gas. Not worth it.
    ///
    /// Costs two topics and no data, so it is about as cheap as a log gets.
    /// Join it to the full record on `orderId`, which is indexed on both.
    ///
    /// Note what an exact-second index can and cannot do: topics match by
    /// equality, so this answers "the purchase at exactly this second" and
    /// never "between these two seconds". A range over seconds is what `day`
    /// is for — the two indexes answer different questions, which is why both
    /// exist rather than one replacing the other.
    event PurchaseAt(uint64 indexed filledAt, bytes32 indexed orderId);

    /// @notice Where a purchase came from, as a searchable topic.
    ///
    /// @dev `originHash` is keccak256(pepper, ip) — NEVER the address itself,
    /// and this is not a style preference.
    ///
    /// An IP address is personal data, and a public chain is permanent and
    /// un-deletable: a raw address written here could never be erased on
    /// request, and would link a wallet to a person's connection for every
    /// indexer and explorer, forever, on a site whose premise is anonymity.
    ///
    /// The decisive part is that hashing costs NOTHING in capability. An
    /// indexed topic matches by equality and nothing else, so the only query
    /// either form supports is "purchases from this exact address" — answered
    /// by hashing the address you are looking for and matching the topic. The
    /// raw value buys no extra search and all of the exposure.
    ///
    /// The pepper is a server-side secret, not a public constant. Without one,
    /// the whole IPv4 space is 2^32 keccaks — an afternoon on a laptop — so an
    /// unsalted hash is a raw address wearing a hat. Two consequences worth
    /// stating: only the operator can compute a lookup, and rotating the pepper
    /// makes older purchases unsearchable by origin. Both are the correct trade
    /// against publishing the address itself.
    event PurchaseOrigin(bytes32 indexed originHash, bytes32 indexed orderId);

    /// @notice The day bucket a timestamp falls in — whole days since the unix
    /// epoch, UTC.
    /// @dev Exposed as a pure function so the backend computes the same bucket
    /// the contract does, from one definition. Two implementations of "which
    /// day is this" drift the moment somebody thinks about timezones.
    function dayOf(uint64 timestamp) public pure returns (uint32) {
        return uint32(timestamp / 1 days);
    }

    error NotFinalized();
    error NothingToFund();
    error AlreadyFunded();
    error BudgetExceeded(uint256 requested, uint256 budget);
    error CapExceeded(uint256 requested, uint256 remaining);
    error ZeroAddress();
    error ZeroOrderId();
    error OrderAlreadyFilled(bytes32 orderId, uint64 filledAt);

    constructor(
        address initialOwner,
        address tokenAddress,
        address epochManagerAddress,
        address rewardDistributorAddress,
        uint256 initialEpochBudget,
        uint256 supplyCap
    ) Ownable(initialOwner) {
        if (tokenAddress == address(0) || rewardDistributorAddress == address(0)) revert ZeroAddress();
        token = IAxonToken(tokenAddress);
        epochManager = IEpochRewards(epochManagerAddress);
        rewardDistributor = rewardDistributorAddress;
        maxSupply = supplyCap;
        epochBudget = initialEpochBudget;
        emit EpochBudgetSet(initialEpochBudget);
    }

    // --- supply: minting, permissionless and bounded ------------------------

    /// @notice How much `fundEpoch` would mint right now. Zero if it would fail.
    /// @dev A view so the answer costs nothing to learn. Deliberately returns 0
    /// rather than reverting, so a caller polling many epochs is not forced to
    /// catch reverts to find the one that needs funding.
    function fundableAmount(uint64 epoch) public view returns (uint256) {
        if (fundedAmount[epoch] != 0) return 0;
        (, bytes32 rewardRoot,,, uint256 totalRewards,,,, bool finalized) = epochManager.epochs(epoch);
        // An unfinalized epoch may still be disputed, and an invalidated one has
        // had its root zeroed — minting for either would create tokens against
        // rewards that nobody can ever claim.
        if (!finalized || rewardRoot == bytes32(0) || totalRewards == 0) return 0;
        if (totalRewards > epochBudget) return 0;
        uint256 supply = token.totalSupply();
        if (supply + totalRewards > maxSupply) return 0;
        return totalRewards;
    }

    /// @notice Mint a settled epoch's rewards into the RewardDistributor.
    /// @dev PERMISSIONLESS, for the same reason `finalize` is: a payment only
    /// the operator can release is a payment the operator can withhold. Nobody
    /// gains anything by calling it — the amount is fixed by the epoch, it can
    /// happen once, and the tokens land where only Merkle-proof holders can
    /// claim them. The caller pays gas to pay somebody else.
    function fundEpoch(uint64 epoch) external returns (uint256) {
        if (fundedAmount[epoch] != 0) revert AlreadyFunded();

        (, bytes32 rewardRoot,,, uint256 totalRewards,,,, bool finalized) = epochManager.epochs(epoch);
        if (!finalized) revert NotFinalized();
        // Invalidated epochs are finalized with a zeroed root, and empty epochs
        // owe nobody anything. Both are refused rather than minted-and-stranded.
        if (rewardRoot == bytes32(0) || totalRewards == 0) revert NothingToFund();

        // Refused, not truncated. Minting less than the epoch promises would
        // leave the reward tree over-subscribed: early claimants would be paid
        // in full and whoever claimed last would hit a bare "transfer exceeds
        // balance" with no way to tell why. Failing here is loud, and the fix
        // — raise the budget, call again — is available to the owner.
        if (totalRewards > epochBudget) revert BudgetExceeded(totalRewards, epochBudget);

        uint256 remaining = maxSupply - token.totalSupply();
        if (totalRewards > remaining) revert CapExceeded(totalRewards, remaining);

        fundedAmount[epoch] = totalRewards;
        emit EpochFunded(epoch, totalRewards, msg.sender);
        token.mint(rewardDistributor, totalRewards);
        return totalRewards;
    }

    function setEpochBudget(uint256 newBudget) external onlyOwner {
        epochBudget = newBudget;
        emit EpochBudgetSet(newBudget);
    }

    // --- spending: owner-only, and never mints ------------------------------

    /// @notice Send tokens this contract already holds — delivering a purchase,
    /// funding a grant, seeding liquidity.
    /// @dev Cannot mint. Everything sold or granted comes out of an allocation
    /// that was minted once, at genesis, in public. That is the difference
    /// between an owner who distributes a fixed share and an owner who prints.
    function release(address to, uint256 amount) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        emit Released(to, amount);
        IERC20(address(token)).safeTransfer(to, amount);
    }

    /// @notice Deliver a purchase against an off-chain order, exactly once.
    /// @param to The buyer's wallet.
    /// @param amount Tokens to send, in wei.
    /// @param orderId keccak256 of the payment reference. NOT the reference.
    ///
    /// @dev Reverts if this order has already been filled, and that is the main
    /// reason the mapping exists rather than an event alone. A card payment
    /// webhook is retried — by Stripe, deliberately, on any non-2xx or timeout —
    /// so "deliver order X" WILL arrive more than once in normal operation. An
    /// event-only design cannot refuse the second one, and the difference
    /// between a retry and a double delivery is not visible from inside the
    /// transaction. Here the chain itself refuses it, so the delivery path is
    /// safe to retry blindly, which is what a payment integration needs.
    ///
    /// Deliberately does NOT mint, exactly as `release` does not: a purchase is
    /// filled from an allocation minted once, at genesis, in public.
    /// @param originHash keccak256(pepper, ip) of the buyer, or zero if not
    /// recorded. See `PurchaseOrigin` for why this is a hash.
    function releaseOrder(address to, uint256 amount, bytes32 orderId, bytes32 originHash)
        external
        onlyOwner
    {
        if (to == address(0)) revert ZeroAddress();
        // A zero id is what an uninitialised variable looks like, and it would
        // collide with every other caller who also forgot to set one — turning
        // the idempotency guard into a lock that blocks all future orders.
        if (orderId == bytes32(0)) revert ZeroOrderId();

        Order storage existing = orders[orderId];
        if (existing.filledAt != 0) {
            revert OrderAlreadyFilled(orderId, existing.filledAt);
        }

        uint64 nowTs = uint64(block.timestamp);
        orders[orderId] = Order({buyer: to, amount: amount, filledAt: nowTs});

        emit PurchaseDelivered(to, amount, orderId, dayOf(nowTs), nowTs);
        emit PurchaseAt(nowTs, orderId);
        // Skipped when absent rather than logged as zero: a zero topic is a
        // value somebody can filter FOR, and it would gather every purchase
        // whose origin was simply never captured into one searchable bucket
        // that looks like a finding.
        if (originHash != bytes32(0)) {
            emit PurchaseOrigin(originHash, orderId);
        }
        IERC20(address(token)).safeTransfer(to, amount);
    }

    /// @notice Whether an order has already been delivered.
    /// @dev Lets the backend check before sending a transaction, rather than
    /// paying gas to learn it from a revert.
    function orderFilled(bytes32 orderId) external view returns (bool) {
        return orders[orderId].filledAt != 0;
    }

    /// @notice Burn tokens this contract holds — retiring an unsold allocation,
    /// or fees that were transferred in.
    function burn(uint256 amount) external onlyOwner {
        emit Burned(amount);
        token.burn(amount);
    }

    /// @notice Recover some other token sent here by mistake. Cannot touch AXON,
    /// which has its own accounted paths in and out.
    function rescue(address other, address to, uint256 amount) external onlyOwner {
        if (other == address(token)) revert ZeroAddress();
        IERC20(other).safeTransfer(to, amount);
    }
}
