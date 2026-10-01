// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Test double for TLDRegistry. Never deployed.
///
/// A registrar that reverts on EVERY call, including plain value transfers.
/// §12.0 says "the root calls nothing on it", and §12.0a's invariant is that
/// governance never acts on a name -- the root reaching into a registrar is the
/// only way it could. A namespace whose registrar is a TrapRegistrar can be
/// taken through its whole lifecycle only if the root never calls it, so the
/// lifecycle test passing IS the proof.
contract TrapRegistrar {
    fallback() external payable {
        revert("TLDRegistry called its registrar");
    }
}
