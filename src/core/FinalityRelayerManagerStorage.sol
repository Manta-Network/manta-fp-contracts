// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";

import "../interfaces/IBLSApkRegistry.sol";

abstract contract FinalityRelayerManagerStorage is Initializable {
    address public operatorWhitelistManager;

    mapping(address => bool) public operatorWhitelist;

    IBLSApkRegistry public blsApkRegistry;

    address public l2OutputOracle;

    address public disputeGameFactory;

    bool public isDisputeGameFactory;

    uint256 public confirmBatchId;
}
