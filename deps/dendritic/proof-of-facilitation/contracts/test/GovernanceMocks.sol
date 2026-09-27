// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Test doubles for AxonGovernance. Never deployed; they exist so the weight
/// sources -- none of which are built yet (F-94.1) -- can be simulated, and so
/// the coverage gate can be exercised at coverage levels that do not exist on
/// any real deployment today.

contract MockWeightSource {
    bool private _available;
    uint256 private _weight;
    constructor(bool a, uint256 w) { _available = a; _weight = w; }
    function setWeight(uint256 w) external { _weight = w; }
    function setAvailable(bool a) external { _available = a; }
    function available() external view returns (bool) { return _available; }
    function weightOf(address) external view returns (uint256) { return _weight; }
}

contract SelectiveWeightSource {
    mapping(address => uint256) private _w;
    function setWeight(address who, uint256 w) external { _w[who] = w; }
    function available() external pure returns (bool) { return true; }
    function weightOf(address who) external view returns (uint256) { return _w[who]; }
}

/// A source that reverts. AxonGovernance must read this as DARK, not as
/// "everyone scores zero" -- the latter silently moves the denominator and
/// changes every tally without anybody noticing.
contract RevertingWeightSource {
    function available() external pure returns (bool) { revert("down"); }
    function weightOf(address) external pure returns (uint256) { revert("down"); }
}

contract MockRegistry {
    bytes32 public lastPruned;
    bytes32 public lastSeized;
    bytes32 public lastRestored;
    uint256 public lastProposalId;
    function prune(bytes32 n, uint256 id) external { lastPruned = n; lastProposalId = id; }
    function seize(bytes32 n, uint256 id) external { lastSeized = n; lastProposalId = id; }
    function restore(bytes32 n, uint256 id) external { lastRestored = n; lastProposalId = id; }
}
