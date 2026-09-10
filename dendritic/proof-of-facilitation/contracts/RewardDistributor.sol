// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

interface IEpochRewards {
    function rewardRootOf(uint64 epoch) external view returns (bytes32);
    function isFinalized(uint64 epoch) external view returns (bool);
}

/// @title RewardDistributor — a node claims its epoch reward with a Merkle proof
/// against the finalized epoch's rewardRoot.
/// @notice Rewards are paid from this contract's CREDIT balance, funded per epoch
/// by the Treasury (Phase 2), so Phase 1 needs no minting rights. Each (epoch,
/// nodeId) can be claimed exactly once. The leaf is an OpenZeppelin double-hashed
/// leaf; the aggregator MUST build the tree identically:
///   leaf = keccak256(bytes.concat(keccak256(abi.encode(
///            nodeId, recipient, amount, serviceBreakdownHash))))
contract RewardDistributor is Ownable {
    using SafeERC20 for IERC20;

    IERC20 public immutable credit;
    IEpochRewards public immutable epochManager;

    mapping(uint64 => mapping(bytes32 => bool)) public claimed; // epoch => nodeId => claimed
    mapping(uint64 => uint256) public claimedTotal; // per-epoch accounting

    event Claimed(uint64 indexed epoch, bytes32 indexed nodeId, address indexed recipient, uint256 amount);

    error NotFinalized();
    error AlreadyClaimed();
    error BadProof();

    constructor(address initialOwner, IERC20 axonToken, IEpochRewards em) Ownable(initialOwner) {
        credit = axonToken;
        epochManager = em;
    }

    function leafHash(bytes32 nodeId, address recipient, uint256 amount, bytes32 serviceBreakdownHash)
        public
        pure
        returns (bytes32)
    {
        return keccak256(bytes.concat(keccak256(abi.encode(nodeId, recipient, amount, serviceBreakdownHash))));
    }

    function claim(
        uint64 epoch,
        bytes32 nodeId,
        address recipient,
        uint256 amount,
        bytes32 serviceBreakdownHash,
        bytes32[] calldata proof
    ) external {
        if (!epochManager.isFinalized(epoch)) revert NotFinalized();
        bytes32 root = epochManager.rewardRootOf(epoch);
        if (root == bytes32(0)) revert NotFinalized(); // invalidated epoch => no claims
        if (claimed[epoch][nodeId]) revert AlreadyClaimed();
        if (!MerkleProof.verify(proof, root, leafHash(nodeId, recipient, amount, serviceBreakdownHash))) {
            revert BadProof();
        }
        claimed[epoch][nodeId] = true;
        claimedTotal[epoch] += amount;
        credit.safeTransfer(recipient, amount);
        emit Claimed(epoch, nodeId, recipient, amount);
    }

    /// @notice Reclaim unclaimed AXON after an epoch is long settled. Owner-only
    /// (intended to be the Treasury/governance).
    function sweep(address to, uint256 amount) external onlyOwner {
        credit.safeTransfer(to, amount);
    }
}
