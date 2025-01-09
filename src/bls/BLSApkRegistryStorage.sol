// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IBLSApkRegistry} from "../interfaces/IBLSApkRegistry.sol";
import {BN254} from "../libraries/BN254.sol";
import {Initializable} from "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";

abstract contract BLSApkRegistryStorage is Initializable, IBLSApkRegistry {
    // Constants
    bytes32 internal constant ZERO_PK_HASH = hex"ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5";
    bytes32 public constant PUBKEY_REGISTRATION_TYPEHASH = keccak256("BN254PubkeyRegistration(address operator)");

    /// @notice the registry finality relayer manager contract
    address public finalityRelayerManager;

    /// @notice the registry relayer manager address
    address public relayerManager;

    // Storage state variables
    mapping(address => bytes32) public operatorToPubkeyHash;
    mapping(bytes32 => address) public pubkeyHashToOperator;
    mapping(address => BN254.G1Point) public operatorToPubkey;

    BN254.G1Point public currentApk;
    ApkUpdate[] public apkHistory;

    mapping(address => bool) public blsRegisterWhitelist;


}
