// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title GuardedVault — same shape as VulnerableVault, hardened.
/// The false-positive claim ("reentrancy drains GuardedVault") is refuted
/// against this contract: CEI ordering plus a reentrancy guard block the
/// attack with a concrete mechanism, not just a reverting script.
contract GuardedVault {
    error ReentrantCall();

    mapping(address => uint256) public balances;
    bool private _entered;

    constructor() payable {}

    modifier nonReentrant() {
        if (_entered) revert ReentrantCall();
        _entered = true;
        _;
        _entered = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");
        balances[msg.sender] = 0; // state cleared BEFORE the external call
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
