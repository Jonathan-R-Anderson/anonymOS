// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

interface IEpochDisputes {
    function openDispute(uint64 epoch) external;
    function closeDispute(uint64 epoch) external;
    function invalidateEpoch(uint64 epoch) external;
}

interface ISlasher {
    function slash(address who, uint256 amount, address beneficiary) external;
}

/// @title DisputeManager — optimistic fraud challenges against an epoch.
/// @notice A challenger bonds CREDIT and names a fraudulent epoch (+ the offending
/// receipt hash as evidence pointer); the epoch is frozen so it cannot finalize.
/// An arbiter resolves: UPHELD invalidates the epoch, slashes the aggregator's
/// bond to the challenger, and refunds the challenger's bond; REJECTED lifts the
/// freeze and forfeits the challenger's bond (anti-griefing).
///
/// Phase 1 resolution is arbiter-driven (owner / governance multisig). The
/// evidence pointer + receipt Merkle proofs make automated on-chain fraud proofs
/// a later drop-in (Phase 7), without changing this interface.
contract DisputeManager is Ownable {
    using SafeERC20 for IERC20;

    IERC20 public immutable credit;
    IEpochDisputes public immutable epochManager;
    ISlasher public immutable stakeVault;
    uint256 public challengerBond;

    struct Dispute {
        uint64 epoch;
        address challenger;
        address aggregator;
        uint256 bond;
        bytes32 receiptHash;
        bool resolved;
        bool upheld;
    }

    Dispute[] public disputes;

    event ChallengerBondSet(uint256 amount);
    event Challenged(uint256 indexed id, uint64 indexed epoch, address indexed challenger, bytes32 receiptHash);
    event Resolved(uint256 indexed id, bool upheld, uint256 slashAmount);

    error AlreadyResolved();

    constructor(
        address initialOwner,
        IERC20 axonToken,
        IEpochDisputes em,
        ISlasher sv,
        uint256 bondAmount
    ) Ownable(initialOwner) {
        credit = axonToken;
        epochManager = em;
        stakeVault = sv;
        challengerBond = bondAmount;
    }

    function setChallengerBond(uint256 amount) external onlyOwner {
        challengerBond = amount;
        emit ChallengerBondSet(amount);
    }

    /// @notice Open a bonded fraud challenge against `epoch`, freezing it. The
    /// `aggregator` is the account whose bond is at risk if the challenge is upheld.
    function challenge(uint64 epoch, address aggregator, bytes32 receiptHash) external returns (uint256 id) {
        credit.safeTransferFrom(msg.sender, address(this), challengerBond);
        epochManager.openDispute(epoch);
        disputes.push(Dispute(epoch, msg.sender, aggregator, challengerBond, receiptHash, false, false));
        id = disputes.length - 1;
        emit Challenged(id, epoch, msg.sender, receiptHash);
    }

    /// @notice Resolve a dispute. Arbiter-only.
    function resolve(uint256 id, bool upheld, uint256 slashAmount) external onlyOwner {
        Dispute storage d = disputes[id];
        if (d.resolved) revert AlreadyResolved();
        d.resolved = true;
        d.upheld = upheld;
        if (upheld) {
            epochManager.invalidateEpoch(d.epoch);
            if (slashAmount > 0) {
                stakeVault.slash(d.aggregator, slashAmount, d.challenger);
            }
            credit.safeTransfer(d.challenger, d.bond); // refund the honest challenger
        } else {
            epochManager.closeDispute(d.epoch); // lift the freeze
            // challenger bond forfeited: retained here, owner may sweep.
        }
        emit Resolved(id, upheld, slashAmount);
    }

    function disputeCount() external view returns (uint256) {
        return disputes.length;
    }

    function sweep(address to, uint256 amount) external onlyOwner {
        credit.safeTransfer(to, amount);
    }
}
