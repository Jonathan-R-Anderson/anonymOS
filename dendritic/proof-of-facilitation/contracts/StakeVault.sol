// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title StakeVault — bonds posted by providers, witnesses, and aggregators,
/// slashable for fraud. Stake is in CREDIT; withdrawals have a delay so a bond
/// cannot be pulled the instant fraud is about to be reported. An authorized
/// slasher (the DisputeManager) can burn a bond to a beneficiary.
contract StakeVault is Ownable {
    using SafeERC20 for IERC20;

    IERC20 public immutable credit;
    uint64 public withdrawDelay;

    mapping(address => uint256) public bonded; // active, slashable
    mapping(address => uint256) public pendingWithdraw; // in the delay window, still slashable
    mapping(address => uint64) public withdrawableAt;
    mapping(address => bool) public isSlasher;

    event Bonded(address indexed who, uint256 amount);
    event WithdrawRequested(address indexed who, uint256 amount, uint64 at);
    event Withdrawn(address indexed who, uint256 amount);
    event Slashed(address indexed who, uint256 amount, address indexed beneficiary);
    event SlasherSet(address indexed who, bool enabled);

    error NotSlasher();
    error InsufficientBond();
    error TooEarly();
    error NothingPending();

    constructor(address initialOwner, IERC20 axonToken, uint64 withdrawDelaySeconds) Ownable(initialOwner) {
        credit = axonToken;
        withdrawDelay = withdrawDelaySeconds;
    }

    function setSlasher(address who, bool enabled) external onlyOwner {
        isSlasher[who] = enabled;
        emit SlasherSet(who, enabled);
    }

    function setWithdrawDelay(uint64 seconds_) external onlyOwner {
        withdrawDelay = seconds_;
    }

    function bond(uint256 amount) external {
        credit.safeTransferFrom(msg.sender, address(this), amount);
        bonded[msg.sender] += amount;
        emit Bonded(msg.sender, amount);
    }

    function requestWithdraw(uint256 amount) external {
        if (amount > bonded[msg.sender]) revert InsufficientBond();
        bonded[msg.sender] -= amount;
        pendingWithdraw[msg.sender] += amount;
        withdrawableAt[msg.sender] = uint64(block.timestamp) + withdrawDelay;
        emit WithdrawRequested(msg.sender, amount, withdrawableAt[msg.sender]);
    }

    function withdraw() external {
        uint256 amount = pendingWithdraw[msg.sender];
        if (amount == 0) revert NothingPending();
        if (block.timestamp < withdrawableAt[msg.sender]) revert TooEarly();
        pendingWithdraw[msg.sender] = 0;
        credit.safeTransfer(msg.sender, amount);
        emit Withdrawn(msg.sender, amount);
    }

    /// @notice Slash up to `amount` from `who`, active bond first then any pending
    /// (delayed) withdrawal — so requesting a withdrawal cannot dodge a slash.
    function slash(address who, uint256 amount, address beneficiary) external {
        if (!isSlasher[msg.sender]) revert NotSlasher();
        uint256 taken = amount > bonded[who] ? bonded[who] : amount;
        bonded[who] -= taken;
        uint256 remaining = amount - taken;
        if (remaining > 0) {
            uint256 fromPending = remaining > pendingWithdraw[who] ? pendingWithdraw[who] : remaining;
            pendingWithdraw[who] -= fromPending;
            taken += fromPending;
        }
        if (taken > 0 && beneficiary != address(0)) {
            credit.safeTransfer(beneficiary, taken);
        }
        emit Slashed(who, taken, beneficiary);
    }

    function totalStaked(address who) external view returns (uint256) {
        return bonded[who] + pendingWithdraw[who];
    }
}
