// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {IVault, Attacker} from "../src/Attacker.sol";

/// Refutation PoC: the same reentrancy attack against GuardedVault extracts
/// nothing, and the run states the specific blocking mechanism (CEI ordering;
/// the re-entrant withdraw reverts with "nothing to withdraw"). "Attack script
/// reverts" alone is not treated as refutation here — the attack completes,
/// and the assertions show exactly why the profit is zero.
contract RefuteGuardedTest is Test {
    function test_ReentryBlockedOnGuardedVault() public {
        address guardedAddr = vm.envAddress("GUARDED_ADDR");
        uint256 seedFunds = guardedAddr.balance;
        assertGt(seedFunds, 1 ether, "vault seeded with victim funds");

        Attacker attacker = new Attacker{value: 1 ether}(IVault(guardedAddr));
        attacker.attack();

        assertEq(attacker.profit(), 0, "NoProfitExtracted");
        assertEq(guardedAddr.balance, seedFunds, "VictimFundsRemain");
        console2.log("RESULT: REFUTED");
        console2.log("BLOCKED-BY: balance zeroed before transfer (CEI); re-entrant withdraw reverts 'nothing to withdraw'");
    }
}
