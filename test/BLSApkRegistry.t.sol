// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {BLSApkRegistry} from "../src/bls/BLSApkRegistry.sol";
import "../src/libraries/BN254.sol";

contract BLSApkRegistryTest is Test {
    using BN254 for BN254.G1Point;

    ERC1967Proxy proxy;
    BLSApkRegistry internal blsApkRegistry;

    Account internal owner = makeAccount("owner");
    Account internal finalityRelayerManager = makeAccount("finalityRelayerManager");
    Account internal relayerManager = makeAccount("relayerManager");
    Account internal operator = makeAccount("operator");

    function setUp() public {
        BLSApkRegistry implementation = new BLSApkRegistry();
        proxy = new ERC1967Proxy(
            address(implementation),
            abi.encodeCall(implementation.initialize, (owner.addr, finalityRelayerManager.addr, relayerManager.addr))
        );
        blsApkRegistry = BLSApkRegistry(address(proxy));
        emit log_address(owner.addr);
    }

    function testAddBlsRegisterWhitelist() public {
        vm.prank(relayerManager.addr);
        blsApkRegistry.addOrRemoveBlsRegisterWhitelist(operator.addr, true);
        assertEq(blsApkRegistry.blsRegisterWhitelist(operator.addr), true);
    }

    function testRemoveBlsRegisterWhitelist() public {
        vm.prank(relayerManager.addr);
        blsApkRegistry.addOrRemoveBlsRegisterWhitelist(operator.addr, true);
        vm.prank(relayerManager.addr);
        blsApkRegistry.addOrRemoveBlsRegisterWhitelist(operator.addr, false);
        assertEq(blsApkRegistry.blsRegisterWhitelist(operator.addr), false);
    }

    function testAddBlsRegisterWhitelistWithZeroAddress() public {
        vm.prank(relayerManager.addr);
        vm.expectRevert("BLSApkRegistry.addOrRemoverBlsRegisterWhitelist: operator address is zero");
        blsApkRegistry.addOrRemoveBlsRegisterWhitelist(address(0), true);
    }

    function testNonRelayerManagerCannotAddBlsRegisterWhitelist() public {
        address nonRelayerManager = address(0x2);
        vm.prank(nonRelayerManager);
        vm.expectRevert(bytes("BLSApkRegistry.onlyRelayerManager: caller is not the relayer manager address"));
        blsApkRegistry.addOrRemoveBlsRegisterWhitelist(operator.addr, true);
    }
}
