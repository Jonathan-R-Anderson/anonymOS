// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title ServicePolicyRegistry — the versioned scoring/budget policy the
/// aggregator reads when scoring an epoch.
/// @notice A policy fixes the epoch budget, the per-capability reward split, the
/// witness thresholds per service, a per-node reward cap, and the hash of the
/// off-chain scoring-formula spec. New versions activate only at an epoch
/// boundary, so a policy can never change the meaning of an epoch mid-flight.
/// Index order for the 7-slot arrays matches NodeRegistry's capability bits:
///   [0]=DHT [1]=Gateway [2]=Storage [3]=LoadBalance [4]=DockerWorker
///   [5]=DockerController [6]=Witness
contract ServicePolicyRegistry is Ownable {
    struct Policy {
        uint256 epochBudget; // total CREDIT minted/funded per epoch
        uint16[7] serviceSplitBps; // per-capability share in basis points (should sum ~10000)
        uint8[7] witnessThreshold; // required witness attestations per service type
        uint256 perNodeCapBps; // max share of an epoch a single node can earn (bps)
        bytes32 formulaHash; // hash of the published off-chain scoring spec
        bool exists;
    }

    mapping(uint32 => Policy) private _policies;
    uint32 public activeVersion;
    uint32 public pendingVersion;
    uint64 public pendingActivationEpoch;

    event PolicySet(uint32 indexed version);
    event PolicyActivated(uint32 indexed version);
    event PolicyScheduled(uint32 indexed version, uint64 activationEpoch);

    error UnknownPolicy();
    error NotDue();

    constructor(address initialOwner) Ownable(initialOwner) {}

    function setPolicy(
        uint32 version,
        uint256 epochBudget,
        uint16[7] calldata serviceSplitBps,
        uint8[7] calldata witnessThreshold,
        uint256 perNodeCapBps,
        bytes32 formulaHash
    ) external onlyOwner {
        _policies[version] =
            Policy(epochBudget, serviceSplitBps, witnessThreshold, perNodeCapBps, formulaHash, true);
        emit PolicySet(version);
    }

    /// @notice Activate a policy immediately (bootstrap / emergency). Owner-only.
    function activateNow(uint32 version) external onlyOwner {
        if (!_policies[version].exists) revert UnknownPolicy();
        activeVersion = version;
        emit PolicyActivated(version);
    }

    /// @notice Schedule a policy to take effect at an epoch boundary.
    function schedule(uint32 version, uint64 activationEpoch) external onlyOwner {
        if (!_policies[version].exists) revert UnknownPolicy();
        pendingVersion = version;
        pendingActivationEpoch = activationEpoch;
        emit PolicyScheduled(version, activationEpoch);
    }

    /// @notice Roll a scheduled policy in once its activation epoch has arrived.
    /// Permissionless (anyone can trigger the boundary transition).
    function activateIfDue(uint64 currentEpoch) external {
        if (pendingActivationEpoch == 0 || currentEpoch < pendingActivationEpoch) revert NotDue();
        activeVersion = pendingVersion;
        pendingActivationEpoch = 0;
        emit PolicyActivated(activeVersion);
    }

    function policy(uint32 version) external view returns (Policy memory) {
        return _policies[version];
    }

    function active() external view returns (Policy memory) {
        return _policies[activeVersion];
    }
}
