// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

interface IEpochManager {
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

    function finalize(uint64 epoch) external;
}

/// @title SettlementKeeper — pays whoever finalizes an epoch nobody else did.
/// @notice `EpochManager.finalize` takes no permission, which is deliberate: a
/// settlement only its author can complete is one its author can also withhold.
/// The cost of that design is that it can also be completed by nobody, and it
/// was — epoch 0 sat a full day past its window because making the call was
/// somebody's chore and nobody's job.
///
/// This contract makes it a job. First caller finalizes the epoch, covers the
/// gas, and keeps the bounty.
///
/// WHY THIS IS SEPARATE FROM EpochManager
/// Changing EpochManager means deploying a new one, and every epoch on record
/// lives in the existing deployment. Migrating that history is a far larger and
/// riskier job than this feature justifies. So nothing here touches it: this
/// contract only calls the same public function anybody else can.
///
/// AND finalize() STAYS PERMISSIONLESS
/// A keeper that became the ONLY route to finalization would reintroduce
/// exactly the withholding the permissionless design exists to prevent — it
/// would just be this contract doing the withholding instead of an operator.
/// Anyone can still bypass it entirely and call EpochManager directly, which is
/// the property that makes it safe to have a preferred path at all.
///
/// THE BOUNTY IS ETH, AND FLAT, AND THAT IS NOT AN ACCIDENT
/// An earlier version of this contract paid a basis-point share of the epoch's
/// `totalRewards`. That was wrong, because the two are different assets:
/// rewards are CREDIT, an ERC-20 that RewardDistributor transfers, while this
/// pays native ETH. Taking 5% of a CREDIT amount and sending that many wei is
/// arithmetic across an exchange rate that appears nowhere in this contract —
/// an epoch distributing 1,000 CREDIT (1e21) would have computed a 50 ETH
/// bounty, immediately clamped to the cap, every time. The "incentive scales
/// with what is at stake" property was decorative; the cap did all the work.
///
/// So: a flat ETH amount, because what the bounty compensates is GAS, and gas
/// is priced in ETH regardless of how large the epoch is. Finalizing a huge
/// epoch and a tiny one cost the same, so they pay the same.
contract SettlementKeeper is Ownable {
    IEpochManager public immutable epochManager;

    /// @notice Flat ETH paid to whoever finalizes an epoch that pays somebody.
    /// @dev Sized against gas, not against the epoch. On Ethereum mainnet a finalize
    /// call costs a fraction of a cent, so this only has to beat that by enough
    /// to be worth somebody's automation.
    uint256 public bountyWei;

    /// @notice Hard ceiling on `bountyWei`, enforced at set time.
    /// @dev Not a policy limit — a typo limit. The difference between 1e15 and
    /// 1e18 is three keystrokes and three orders of magnitude, and the owner
    /// funding this contract is the one who eats the difference.
    uint256 public constant MAX_BOUNTY_WEI = 0.05 ether;

    event BountyPaid(uint64 indexed epoch, address indexed keeper, uint256 amount);
    event BountyUnavailable(uint64 indexed epoch, address indexed keeper, uint256 owed);
    event ParametersSet(uint256 bountyWei);
    event Funded(address indexed from, uint256 amount);
    event Withdrawn(address indexed to, uint256 amount);

    error NothingToFinalize();
    error BountyTooLarge();

    constructor(address initialOwner, address epochManagerAddress, uint256 initialBountyWei)
        Ownable(initialOwner)
    {
        epochManager = IEpochManager(epochManagerAddress);
        _setBounty(initialBountyWei);
    }

    receive() external payable {
        emit Funded(msg.sender, msg.value);
    }

    function setBounty(uint256 newBountyWei) external onlyOwner {
        _setBounty(newBountyWei);
    }

    function _setBounty(uint256 newBountyWei) internal {
        if (newBountyWei > MAX_BOUNTY_WEI) revert BountyTooLarge();
        bountyWei = newBountyWei;
        emit ParametersSet(newBountyWei);
    }

    /// @notice What this contract would pay for finalizing `epoch` right now.
    /// @dev A view, so a keeper can decide whether the call is worth its gas
    /// BEFORE spending any. Without this, competing keepers discover an empty
    /// bounty by paying for a transaction that pays them nothing.
    function bountyFor(uint64 epoch) public view returns (uint256) {
        (,,,, uint256 totalRewards,,,, bool finalized) = epochManager.epochs(epoch);
        if (finalized || totalRewards == 0) return 0;
        uint256 available = address(this).balance;
        return bountyWei > available ? available : bountyWei;
    }

    /// @notice Whether calling `finalizeAndClaim` would succeed right now.
    /// @dev Every condition EpochManager.finalize enforces, checked without
    /// spending gas to learn the answer.
    function isClaimable(uint64 epoch) external view returns (bool) {
        (,,,,, uint64 submittedAt, uint64 challengeDeadline, uint32 openDisputes, bool finalized) =
            epochManager.epochs(epoch);
        return submittedAt != 0 && !finalized && openDisputes == 0 && block.timestamp >= challengeDeadline;
    }

    /// @notice Finalize `epoch` and take the bounty.
    /// @dev The finalize call comes FIRST. If the epoch cannot be finalized —
    /// unknown, already done, still in its window, disputed — EpochManager
    /// reverts and this whole transaction reverts with it, so no bounty is paid
    /// for a no-op. That ordering is the only thing preventing a caller from
    /// draining the balance by repeatedly "finalizing" an epoch that is already
    /// finalized.
    function finalizeAndClaim(uint64 epoch) external {
        (,,,, uint256 totalRewards,,,, bool finalizedBefore) = epochManager.epochs(epoch);
        if (finalizedBefore) revert NothingToFinalize();

        // Read BEFORE the external call, so the amount cannot depend on state a
        // reentrant caller changed. Nothing here is reentrant today —
        // EpochManager makes no external calls — but a bounty that is read
        // after an external call is a bug waiting for the day it is.
        //
        // An epoch that pays nobody is still finalized, because closing it is
        // worth doing, and pays no bounty, because paying to close a worthless
        // epoch turns a harmless no-op into a standing invitation to spend the
        // balance. Every epoch on this network is currently empty, so this
        // contract correctly does nothing until that changes.
        uint256 owed = totalRewards > 0 ? bountyWei : 0;

        epochManager.finalize(epoch);

        if (owed == 0) return;

        uint256 available = address(this).balance;
        if (available == 0) {
            // The epoch IS finalized — that already happened and is what
            // matters. Announcing the unpaid bounty rather than reverting is
            // deliberate: reverting would undo a settlement the network needs
            // because this contract happens to be empty.
            emit BountyUnavailable(epoch, msg.sender, owed);
            return;
        }
        if (owed > available) owed = available;

        emit BountyPaid(epoch, msg.sender, owed);
        // Paid last, after every state change and event, and with call rather
        // than transfer: a keeper may well be a contract, and a 2300-gas stipend
        // would exclude anything more sophisticated than an EOA from competing.
        (bool sent,) = payable(msg.sender).call{value: owed}("");
        require(sent, "bounty transfer failed");
    }

    /// @notice Recover funds. Does not touch anything owed for work done —
    /// bounties are paid within the same transaction that earns them, so there
    /// is never an unpaid claim sitting here to be swept out from under.
    function withdraw(address payable to, uint256 amount) external onlyOwner {
        emit Withdrawn(to, amount);
        (bool sent,) = to.call{value: amount}("");
        require(sent, "withdraw failed");
    }
}
