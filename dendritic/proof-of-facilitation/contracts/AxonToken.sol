// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title AxonToken — the Syndichan network's utility token.
/// @notice Named Axon on-chain, ticker AXON, and called AXON everywhere a
/// person reads it — the site, the store, the ledger. It was briefly called
/// "credits" in the interface while the contract was called something else;
/// that split is gone, and one name for one balance is the point.
///
/// Supply is controlled SOLELY by the Treasury. No node, user, or admin can
/// mint: nodes earn a share of a bounded per-epoch budget the Treasury releases
/// against a settled epoch, and they never mint their own rewards. The owner
/// (intended to be handed to governance / a timelock) wires the Treasury address
/// once; from then on only the Treasury may change supply.
contract AxonToken is ERC20, Ownable {
    /// @notice The only address allowed to mint/burn (the Treasury contract).
    address public treasury;
    /// @notice Once true, the owner can no longer genesis-mint; supply is then
    /// governed solely by the Treasury under the monetary policy.
    bool public genesisClosed;
    /// @notice Running total minted during genesis (for transparency).
    uint256 public genesisMinted;

    event TreasurySet(address indexed previous, address indexed treasury);
    event GenesisMint(address indexed to, uint256 amount);
    event GenesisClosed();

    error NotTreasury();
    error ZeroAddress();
    error GenesisIsClosed();

    constructor(address initialOwner) ERC20("Axon", "AXON") Ownable(initialOwner) {}

    modifier onlyTreasury() {
        if (msg.sender != treasury) revert NotTreasury();
        _;
    }

    /// @notice Kick-start the economy: the owner mints an initial supply (e.g.
    /// into the treasury / reward pool) BEFORE the autonomous Treasury takes over.
    /// Owner-only, and permanently disabled once closeGenesis() is called — so the
    /// bootstrap can never be used to inflate supply behind the monetary policy.
    function mintGenesis(address to, uint256 amount) external onlyOwner {
        if (genesisClosed) revert GenesisIsClosed();
        if (to == address(0)) revert ZeroAddress();
        genesisMinted += amount;
        _mint(to, amount);
        emit GenesisMint(to, amount);
    }

    /// @notice Permanently end the genesis window. After this, only the Treasury
    /// can change supply. Irreversible.
    function closeGenesis() external onlyOwner {
        genesisClosed = true;
        emit GenesisClosed();
    }

    /// @notice Wire (or rotate) the Treasury — the sole minter/burner. Owner-only.
    function setTreasury(address newTreasury) external onlyOwner {
        if (newTreasury == address(0)) revert ZeroAddress();
        emit TreasurySet(treasury, newTreasury);
        treasury = newTreasury;
    }

    /// @notice Mint reward AXON. Treasury-only.
    function mint(address to, uint256 amount) external onlyTreasury {
        _mint(to, amount);
    }

    /// @notice Burn AXON the Treasury itself holds (fees, buybacks, retiring
    /// an unsold allocation). Treasury-only.
    /// @dev Deliberately burns only from the caller's OWN balance. The previous
    /// version took a `from` address, which handed whoever controlled the
    /// Treasury the power to destroy any holder's tokens at will — a power that
    /// makes every other guarantee here conditional on the operator's goodwill.
    /// Nothing needed it: fees reach the Treasury by transfer first, and burning
    /// what it then holds is the same operation without the power.
    function burn(uint256 amount) external onlyTreasury {
        _burn(msg.sender, amount);
    }
}
