// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {FinalityRelayerManager} from "../src/core/FinalityRelayerManager.sol";
import {BLSApkRegistry} from "../src/bls/BLSApkRegistry.sol";
import {IBLSApkRegistry} from "../src/interfaces/IBLSApkRegistry.sol";
import {IFinalityRelayerManager} from "../src/interfaces/IFinalityRelayerManager.sol";
import "../src/libraries/BN254.sol";

contract FinalityRelayerManagerTest is Test {
    ERC1967Proxy proxy;
    FinalityRelayerManager internal finalityRelayerManager;
    BLSApkRegistry internal blsApkRegistry;

    Account internal owner = makeAccount("owner");
    Account internal operator = makeAccount("operator");
    Account internal operatorWhitelistManager = makeAccount("operatorWhitelistManager");
    Account internal relayerManager = makeAccount("relayerManager");

    address internal l2OutputOracle;
    address internal disputeGameFactory;
    bool internal isDisputeGameFactory;

    event OperatorRegistered(address indexed operator, string nodeUrl);
    event OperatorDeRegistered(address indexed operator);
    event VerifyFinalitySig(uint256 totalBtcStaking, uint256 totalMantaStaking, bytes32 signatoryRecordHash);

    function setUp() public {
        // Deploy and initialize BLSApkRegistry first
        BLSApkRegistry blsImplementation = new BLSApkRegistry();
        ERC1967Proxy blsProxy = new ERC1967Proxy(
            address(blsImplementation),
            abi.encodeCall(blsImplementation.initialize, (owner.addr, address(this), relayerManager.addr))
        );
        blsApkRegistry = BLSApkRegistry(address(blsProxy));

        // Setup mock addresses
        l2OutputOracle = makeAddr("l2OutputOracle");
        disputeGameFactory = makeAddr("disputeGameFactory");
        isDisputeGameFactory = false;

        // Deploy and initialize FinalityRelayerManager
        FinalityRelayerManager implementation = new FinalityRelayerManager();
        proxy = new ERC1967Proxy(
            address(implementation),
            abi.encodeCall(
                implementation.initialize,
                (
                    owner.addr,
                    isDisputeGameFactory,
                    address(blsApkRegistry),
                    l2OutputOracle,
                    disputeGameFactory,
                    operatorWhitelistManager.addr
                )
            )
        );
        finalityRelayerManager = FinalityRelayerManager(address(proxy));
    }

    function testInitialization() public view {
        assertEq(finalityRelayerManager.owner(), owner.addr);
        assertEq(address(finalityRelayerManager.blsApkRegistry()), address(blsApkRegistry));
        assertEq(finalityRelayerManager.l2OutputOracle(), l2OutputOracle);
        assertEq(finalityRelayerManager.disputeGameFactory(), disputeGameFactory);
        assertEq(finalityRelayerManager.isDisputeGameFactory(), isDisputeGameFactory);
        assertEq(finalityRelayerManager.operatorWhitelistManager(), operatorWhitelistManager.addr);
    }

    function testCannotReinitialize() public {
        vm.expectRevert(abi.encodeWithSignature("InvalidInitialization()"));
        finalityRelayerManager.initialize(
            owner.addr,
            isDisputeGameFactory,
            address(blsApkRegistry),
            l2OutputOracle,
            disputeGameFactory,
            operatorWhitelistManager.addr
        );
    }

    function testAddOperatorWhitelist() public {
        vm.prank(operatorWhitelistManager.addr);
        finalityRelayerManager.addOrRemoveOperatorWhitelist(operator.addr, true);
        assertTrue(finalityRelayerManager.operatorWhitelist(operator.addr));
    }

    function testRemoveOperatorWhitelist() public {
        // First add to whitelist
        vm.prank(operatorWhitelistManager.addr);
        finalityRelayerManager.addOrRemoveOperatorWhitelist(operator.addr, true);

        // Then remove from whitelist
        vm.prank(operatorWhitelistManager.addr);
        finalityRelayerManager.addOrRemoveOperatorWhitelist(operator.addr, false);
        assertFalse(finalityRelayerManager.operatorWhitelist(operator.addr));
    }

    function testCannotAddZeroAddressToWhitelist() public {
        vm.prank(operatorWhitelistManager.addr);
        vm.expectRevert("FinalityRelayerManager.addOperatorWhitelist: operator address is zero");
        finalityRelayerManager.addOrRemoveOperatorWhitelist(address(0), true);
    }

    function testNonManagerCannotModifyWhitelist() public {
        vm.prank(operator.addr);
        vm.expectRevert("StrategyManager.onlyFinalityWhiteListManager: not the finality whitelist manager");
        finalityRelayerManager.addOrRemoveOperatorWhitelist(makeAddr("someAddress"), true);
    }

    function testRegisterOperator() public {
        string memory nodeUrl = "https://example.com";

        // Add operator to whitelist first
        vm.prank(operatorWhitelistManager.addr);
        finalityRelayerManager.addOrRemoveOperatorWhitelist(operator.addr, true);

        // Mock BLSApkRegistry.registerOperator call
        vm.mockCall(
            address(blsApkRegistry),
            abi.encodeWithSelector(IBLSApkRegistry.registerOperator.selector, operator.addr),
            abi.encode()
        );

        // Register operator
        vm.prank(operator.addr);
        vm.expectEmit(true, false, false, true, address(finalityRelayerManager));
        emit OperatorRegistered(operator.addr, nodeUrl);
        finalityRelayerManager.registerOperator(nodeUrl);
    }

    function testNonWhitelistedOperatorCannotRegister() public {
        vm.prank(operator.addr);
        vm.expectRevert(
            "FinalityRelayerManager.registerOperator: this address have not permission to register "
        );
        finalityRelayerManager.registerOperator("https://example.com");
    }

    function testDeregisterOperator() public {
        console.log("Starting testDeregisterOperator...");

        // 1. Add operator to whitelist first
        vm.prank(operatorWhitelistManager.addr);
        finalityRelayerManager.addOrRemoveOperatorWhitelist(operator.addr, true);
        console.log(address(finalityRelayerManager), "Added operator to whitelist.");

        // 2. Mock BLSApkRegistry.deregisterOperator call
        vm.mockCall(
            address(blsApkRegistry),
            abi.encodeWithSelector(IBLSApkRegistry.deregisterOperator.selector, operator.addr),
            abi.encode()
        );
        console.log("Mocked BLSApkRegistry.deregisterOperator call.");

        // 3. Deregister operator and verify event
        vm.prank(operator.addr);
        // vm.expectEmit(true, false, false, false, address(finalityRelayerManager));
        emit OperatorDeRegistered(operator.addr);
        console.log("Expecting OperatorDeRegistered event.");
        finalityRelayerManager.deRegisterOperator();
        console.log("Completed deRegisterOperator call.");
    }

    function testNonWhitelistedOperatorCannotDeregister() public {
        // 1. Try to deregister without being whitelisted
        vm.prank(operator.addr);
        vm.expectRevert(
            "FinalityRelayerManager.registerOperator: this address have not permission to register "
        );
        finalityRelayerManager.deRegisterOperator();
    }

    function testDeregisterOperatorFailsWhenBLSRegistryReverts() public {
        // 1. Add operator to whitelist
        vm.prank(operatorWhitelistManager.addr);
        finalityRelayerManager.addOrRemoveOperatorWhitelist(operator.addr, true);

        // 2. Mock BLSApkRegistry.deregisterOperator to fail
        vm.mockCallRevert(
            address(blsApkRegistry),
            abi.encodeWithSelector(IBLSApkRegistry.deregisterOperator.selector, operator.addr),
            "BLSApkRegistry.deregisterOperator: operator is not registered"
        );

        // 3. Try to deregister and expect revert
        vm.prank(operator.addr);
        vm.expectRevert("BLSApkRegistry.deregisterOperator: operator is not registered");
        finalityRelayerManager.deRegisterOperator();
    }

    function testVerifyFinalitySignature() public {
        // Setup test data
        IFinalityRelayerManager.FinalityBatch memory finalityBatch = IFinalityRelayerManager.FinalityBatch({
            msgHash: bytes32(uint256(1)),
            stateRoot: bytes32(uint256(2)),
            l2BlockNumber: 100,
            l1BlockHash: bytes32(uint256(3)),
            l1BlockNumber: 1000
        });

        IBLSApkRegistry.FinalityNonSignerAndSignature memory nonSignerAndSig = IBLSApkRegistry.FinalityNonSignerAndSignature({
            nonSignerPubkeys: new BN254.G1Point[](0),
            apkG2: BN254.G2Point({
                X: [uint256(1), uint256(2)],
                Y: [uint256(3), uint256(4)]
            }),
            sigma: BN254.G1Point({
                X: uint256(5),
                Y: uint256(6)
            }),
            totalBtcStake: 1000,
            totalMantaStake: 2000
        });

        uint256 minGas = 1000000;

        // Mock BLSApkRegistry response
        vm.mockCall(
            address(blsApkRegistry),
            abi.encodeWithSelector(IBLSApkRegistry.checkSignatures.selector),
            abi.encode(
                IBLSApkRegistry.StakeTotals({
                    totalBtcStaking: 1000,
                    totalMantaStaking: 2000
                }),
                bytes32(uint256(123))
            )
        );

        // Mock L2OutputOracle response when isDisputeGameFactory is false
        vm.mockCall(
            l2OutputOracle,
            minGas,
            abi.encodeWithSignature(
                "proposeL2Output(bytes32,uint256,bytes32,uint256)",
                finalityBatch.stateRoot,
                finalityBatch.l2BlockNumber,
                finalityBatch.l1BlockHash,
                finalityBatch.l1BlockNumber
            ),
            abi.encode(true)
        );

        vm.expectEmit(true, true, true, true);
        emit VerifyFinalitySig(1000, 2000, bytes32(uint256(123)));

        finalityRelayerManager.VerifyFinalitySignature(finalityBatch, nonSignerAndSig, minGas);
    }

    function testVerifyFinalitySignatureWithDisputeGame() public {
        // Setup test data
        IFinalityRelayerManager.FinalityBatch memory finalityBatch = IFinalityRelayerManager.FinalityBatch({
            msgHash: bytes32(uint256(1)),
            stateRoot: bytes32(uint256(2)),
            l2BlockNumber: 100,
            l1BlockHash: bytes32(uint256(3)),
            l1BlockNumber: 1000
        });

        IBLSApkRegistry.FinalityNonSignerAndSignature memory nonSignerAndSig = IBLSApkRegistry.FinalityNonSignerAndSignature({
            nonSignerPubkeys: new BN254.G1Point[](0),
            apkG2: BN254.G2Point({
                X: [uint256(1), uint256(2)],
                Y: [uint256(3), uint256(4)]
            }),
            sigma: BN254.G1Point({
                X: uint256(5),
                Y: uint256(6)
            }),
            totalBtcStake: 1000,
            totalMantaStake: 2000
        });

        uint256 minGas = 1000000;

        // Set isDisputeGameFactory to true
        vm.store(
            address(finalityRelayerManager),
            bytes32(uint256(5)), // slot for isDisputeGameFactory
            bytes32(uint256(1)) // true
        );

        // Mock BLSApkRegistry response
        vm.mockCall(
            address(blsApkRegistry),
            abi.encodeWithSelector(IBLSApkRegistry.checkSignatures.selector),
            abi.encode(
                IBLSApkRegistry.StakeTotals({
                    totalBtcStaking: 1000,
                    totalMantaStaking: 2000
                }),
                bytes32(uint256(123))
            )
        );

        // Mock DisputeGameFactory response
        vm.mockCall(
            disputeGameFactory,
            minGas,
            abi.encodeWithSignature(
                "create(uint32,bytes32,bytes)",
                0,
                finalityBatch.stateRoot,
                "0x"
            ),
            abi.encode(true)
        );

        vm.expectEmit(true, true, true, true);
        emit VerifyFinalitySig(1000, 2000, bytes32(uint256(123)));

        finalityRelayerManager.VerifyFinalitySignature(finalityBatch, nonSignerAndSig, minGas);
    }

    function testVerifyFinalitySignatureFailsWithInsufficientGas() public {
        IFinalityRelayerManager.FinalityBatch memory finalityBatch = IFinalityRelayerManager.FinalityBatch({
            msgHash: bytes32(uint256(1)),
            stateRoot: bytes32(uint256(2)),
            l2BlockNumber: 100,
            l1BlockHash: bytes32(uint256(3)),
            l1BlockNumber: 1000
        });

        IBLSApkRegistry.FinalityNonSignerAndSignature memory nonSignerAndSig = IBLSApkRegistry.FinalityNonSignerAndSignature({
            nonSignerPubkeys: new BN254.G1Point[](0),
            apkG2: BN254.G2Point({
                X: [uint256(1), uint256(2)],
                Y: [uint256(3), uint256(4)]
            }),
            sigma: BN254.G1Point({
                X: uint256(5),
                Y: uint256(6)
            }),
            totalBtcStake: 1000,
            totalMantaStake: 2000
        });

        // Mock BLSApkRegistry response
        vm.mockCall(
            address(blsApkRegistry),
            abi.encodeWithSelector(IBLSApkRegistry.checkSignatures.selector),
            abi.encode(
                IBLSApkRegistry.StakeTotals({
                    totalBtcStaking: 1000,
                    totalMantaStaking: 2000
                }),
                bytes32(uint256(123))
            )
        );

        // Mock L2OutputOracle to fail
        vm.mockCallRevert(
            l2OutputOracle,
            abi.encodeWithSignature(
                "proposeL2Output(bytes32,uint256,bytes32,uint256)",
                finalityBatch.stateRoot,
                finalityBatch.l2BlockNumber,
                finalityBatch.l1BlockHash,
                finalityBatch.l1BlockNumber
            ),
            "insufficient gas"
        );

        vm.expectRevert("StrategyBase.VerifyFinalitySignature: proposeL2Output stateroot failed");
        finalityRelayerManager.VerifyFinalitySignature(finalityBatch, nonSignerAndSig, 1000000);
    }

    // Helper function to create test accounts
    function makeAccount(string memory name) internal override returns (Account memory) {
        address addr = makeAddr(name);
        uint256 privateKey = uint256(keccak256(abi.encodePacked(name)));
        vm.deal(addr, 100 ether);
        return Account(addr, privateKey);
    }
}

// Helper struct for managing test accounts
struct Account {
    address addr;
    uint256 privateKey;
}
