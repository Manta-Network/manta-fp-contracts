// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Vm.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {EmptyContract} from "../src/utils/EmptyContract.sol";
import {BLSApkRegistry} from "../src/bls/BLSApkRegistry.sol";
import {FinalityRelayerManager} from "../src/core/FinalityRelayerManager.sol";
import {console, Script} from "forge-std/Script.sol";

contract deployFinalityRelayerScript is Script {
    EmptyContract public emptyContract;
    ProxyAdmin public blsApkRegistryProxyAdmin;
    ProxyAdmin public finalityRelayerManagerAdmin;
    BLSApkRegistry public blsApkRegistry;
    BLSApkRegistry public blsApkRegistryImplementation;
    FinalityRelayerManager public finalityRelayerManager;
    FinalityRelayerManager public finalityRelayerManagerImplementation;

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address fpAdmin =  vm.envAddress("FP_ADMIN");
        address relayerManagerAddr =  vm.envAddress("RELAYER_MANAGER");
        address l2OutputOracleAddr =  vm.envAddress("L2OUTPUT_ORACLE");
        address disputeGameFactoryAddr = vm.envAddress("DISPUTE_GAME_FACTORY");

        address deployerAddress = vm.addr(deployerPrivateKey);
        vm.startBroadcast(deployerPrivateKey);

        emptyContract = new EmptyContract();
        TransparentUpgradeableProxy proxyBlsApkRegistry = new TransparentUpgradeableProxy(address(emptyContract), fpAdmin, "");
        blsApkRegistry = BLSApkRegistry(address(proxyBlsApkRegistry));
        blsApkRegistryImplementation = new BLSApkRegistry();
        blsApkRegistryProxyAdmin = ProxyAdmin(getProxyAdminAddress(address(proxyBlsApkRegistry)));

        TransparentUpgradeableProxy proxyFinalityRelayerManager = new TransparentUpgradeableProxy(address(emptyContract), fpAdmin, "");
        finalityRelayerManager = FinalityRelayerManager(address(proxyFinalityRelayerManager));
        finalityRelayerManagerImplementation = new FinalityRelayerManager();
        finalityRelayerManagerAdmin = ProxyAdmin(getProxyAdminAddress(address(proxyFinalityRelayerManager)));

        blsApkRegistryProxyAdmin.upgradeAndCall(
            ITransparentUpgradeableProxy(address(blsApkRegistry)),
            address(blsApkRegistryImplementation),
            abi.encodeWithSelector(
                BLSApkRegistry.initialize.selector,
                deployerAddress,
                proxyFinalityRelayerManager,
                relayerManagerAddr
            )
        );

        finalityRelayerManagerAdmin.upgradeAndCall(
            ITransparentUpgradeableProxy(address(finalityRelayerManager)),
            address(finalityRelayerManagerImplementation),
            abi.encodeWithSelector(
                FinalityRelayerManager.initialize.selector,
                fpAdmin,
                false,
                proxyBlsApkRegistry,
                l2OutputOracleAddr,
                disputeGameFactoryAddr,
                deployerAddress
            )
        );

        console.log("deploy proxyBlsApkRegistry:", address(proxyBlsApkRegistry));
        console.log("deploy proxyFinalityRelayerManager:", address(proxyFinalityRelayerManager));
        vm.stopBroadcast();
    }

    function getProxyAdminAddress(address proxy) internal view returns (address) {
        address CHEATCODE_ADDRESS = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;
        Vm vm = Vm(CHEATCODE_ADDRESS);

        bytes32 adminSlot = vm.load(proxy, ERC1967Utils.ADMIN_SLOT);
        return address(uint160(uint256(adminSlot)));
    }
}
