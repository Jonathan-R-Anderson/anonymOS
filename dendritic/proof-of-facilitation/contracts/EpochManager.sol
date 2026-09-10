// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title EpochManager — records each epoch's Merkle commitments and enforces an
/// optimistic challenge window before finalization.
/// @notice The aggregator submits the receipt/reward/state roots + the epoch
/// randomness (used off-chain for witness selection) and the epoch's total
/// reward budget. A DisputeManager can freeze an epoch (open dispute) or
/// invalidate it (fraud upheld). After the challenge window with no open
/// dispute, anyone may finalize, which unlocks reward claims.
contract EpochManager is Ownable {
    struct Epoch {
        bytes32 receiptRoot;
        bytes32 rewardRoot;
        bytes32 nodeStateRoot;
        bytes32 randomness;
        uint256 totalRewards;
        uint64 submittedAt;
        uint64 challengeDeadline;
        uint32 openDisputes;
        bool finalized;
    }

    mapping(uint64 => Epoch) public epochs;
    mapping(address => bool) public isAggregator;
    mapping(address => bool) public isDisputeManager;
    uint64 public challengeWindow; // seconds
    uint64 public latestEpoch;

    event AggregatorSet(address indexed who, bool enabled);
    event DisputeManagerSet(address indexed who, bool enabled);
    event EpochSubmitted(
        uint64 indexed epoch, bytes32 receiptRoot, bytes32 rewardRoot, uint256 totalRewards, uint64 challengeDeadline
    );
    event EpochFinalized(uint64 indexed epoch);
    event EpochInvalidated(uint64 indexed epoch);
    event DisputeOpened(uint64 indexed epoch, uint32 open);
    event DisputeClosed(uint64 indexed epoch, uint32 open);

    error NotAggregator();
    error NotDisputeManager();
    error EpochExists();
    error UnknownEpoch();
    error WindowNotPassed();
    error AlreadyFinalized();
    error DisputesOpen();

    constructor(address initialOwner, uint64 challengeWindowSeconds) Ownable(initialOwner) {
        challengeWindow = challengeWindowSeconds;
    }

    function setAggregator(address who, bool enabled) external onlyOwner {
        isAggregator[who] = enabled;
        emit AggregatorSet(who, enabled);
    }

    function setDisputeManager(address who, bool enabled) external onlyOwner {
        isDisputeManager[who] = enabled;
        emit DisputeManagerSet(who, enabled);
    }

    function setChallengeWindow(uint64 seconds_) external onlyOwner {
        challengeWindow = seconds_;
    }

    function submitEpoch(
        uint64 epoch,
        bytes32 receiptRoot,
        bytes32 rewardRoot,
        bytes32 nodeStateRoot,
        bytes32 randomness,
        uint256 totalRewards
    ) external {
        if (!isAggregator[msg.sender]) revert NotAggregator();
        if (epochs[epoch].submittedAt != 0) revert EpochExists();
        uint64 deadline = uint64(block.timestamp) + challengeWindow;
        epochs[epoch] = Epoch(
            receiptRoot, rewardRoot, nodeStateRoot, randomness, totalRewards,
            uint64(block.timestamp), deadline, 0, false
        );
        if (epoch > latestEpoch) latestEpoch = epoch;
        emit EpochSubmitted(epoch, receiptRoot, rewardRoot, totalRewards, deadline);
    }

    function openDispute(uint64 epoch) external {
        if (!isDisputeManager[msg.sender]) revert NotDisputeManager();
        Epoch storage e = epochs[epoch];
        if (e.submittedAt == 0) revert UnknownEpoch();
        if (e.finalized) revert AlreadyFinalized();
        e.openDisputes += 1;
        emit DisputeOpened(epoch, e.openDisputes);
    }

    function closeDispute(uint64 epoch) external {
        if (!isDisputeManager[msg.sender]) revert NotDisputeManager();
        Epoch storage e = epochs[epoch];
        if (e.openDisputes > 0) e.openDisputes -= 1;
        emit DisputeClosed(epoch, e.openDisputes);
    }

    /// @notice Fraud upheld: zero the reward root so nothing can be claimed and
    /// mark the epoch finalized (settled). DisputeManager only.
    function invalidateEpoch(uint64 epoch) external {
        if (!isDisputeManager[msg.sender]) revert NotDisputeManager();
        Epoch storage e = epochs[epoch];
        if (e.submittedAt == 0) revert UnknownEpoch();
        e.rewardRoot = bytes32(0);
        e.openDisputes = 0;
        e.finalized = true;
        emit EpochInvalidated(epoch);
    }

    function finalize(uint64 epoch) external {
        Epoch storage e = epochs[epoch];
        if (e.submittedAt == 0) revert UnknownEpoch();
        if (e.finalized) revert AlreadyFinalized();
        if (block.timestamp < e.challengeDeadline) revert WindowNotPassed();
        if (e.openDisputes > 0) revert DisputesOpen();
        e.finalized = true;
        emit EpochFinalized(epoch);
    }

    // --- views the RewardDistributor / aggregator read ----------------------

    function rewardRootOf(uint64 epoch) external view returns (bytes32) {
        Epoch storage e = epochs[epoch];
        return e.finalized ? e.rewardRoot : bytes32(0);
    }

    function isFinalized(uint64 epoch) external view returns (bool) {
        return epochs[epoch].finalized;
    }

    function randomnessOf(uint64 epoch) external view returns (bytes32) {
        return epochs[epoch].randomness;
    }
}
