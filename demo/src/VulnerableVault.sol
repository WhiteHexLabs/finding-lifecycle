// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableVault — deliberately vulnerable demo target.
/// The demo "protocol" seeds 10 ETH of victim funds at deployment.
/// withdraw() sends ETH before clearing the caller's balance, so a
/// reentrant receiver drains every deposit plus the seed.
contract VulnerableVault {
    mapping(address => uint256) public balances;

    constructor() payable {}

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0; // state cleared AFTER the external call
    }
}
