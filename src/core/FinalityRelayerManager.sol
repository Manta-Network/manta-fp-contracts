// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";

import "../libraries/SafeCall.sol";

import "../interfaces/IFinalityRelayerManager.sol";
import "../interfaces/IBLSApkRegistry.sol";

import "./FinalityRelayerManagerStorage.sol";

contract FinalityRelayerManager is OwnableUpgradeable, FinalityRelayerManagerStorage, IFinalityRelayerManager {

    uint256 internal constant TOTAL_CHALLENGE_PERIOD = 259200; // 3 days

    uint256 internal constant MANTA_REDUCE_PERIOD = 86400;  // 1 days

    uint256 internal constant BITCOIN_REDUCE_PERIOD = 86400; // 1 days

    uint256 internal constant MIN_CHALLENGE_PERIOD = 43200 ; // 0.5 days

    uint256 internal constant TARGET_MANTA =  1000000 * 10e17;

    uint256 internal constant TARGET_BITCOIN = 1000 * 10e7;

    modifier onlyOperatorWhitelistManager() {
        require(
            msg.sender == operatorWhitelistManager,
            "StrategyManager.onlyFinalityWhiteListManager: not the finality whitelist manager"
        );
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _initialOwner,
        bool _isDisputeGameFactory,
        address _blsApkRegistry,
        address _l2OutputOracle,
        address _disputeGameFactory,
        address _operatorWhitelistManager
    ) external initializer {
        _transferOwnership(_initialOwner);
        blsApkRegistry = IBLSApkRegistry(_blsApkRegistry);
        l2OutputOracle = _l2OutputOracle;
        disputeGameFactory = _disputeGameFactory;
        isDisputeGameFactory = _isDisputeGameFactory;
        operatorWhitelistManager = _operatorWhitelistManager;
    }

    function registerOperator(string calldata nodeUrl) external {
        require(
            operatorWhitelist[msg.sender],
            "FinalityRelayerManager.registerOperator: this address have not permission to register "
        );
        blsApkRegistry.registerOperator(msg.sender);
        emit OperatorRegistered(msg.sender, nodeUrl);
    }

    function deRegisterOperator() external {
        require(
            operatorWhitelist[msg.sender],
            "FinalityRelayerManager.registerOperator: this address have not permission to register "
        );
        blsApkRegistry.deregisterOperator(msg.sender);
        emit OperatorDeRegistered(msg.sender);
    }

    function VerifyFinalitySignature(
        FinalityBatch calldata finalityBatch,
        IBLSApkRegistry.FinalityNonSignerAndSignature memory finalityNonSignerAndSignature,
        uint256 minGas
    ) external {
        (
            IBLSApkRegistry.StakeTotals memory stakeTotals,
            bytes32 signatoryRecordHash
        ) = blsApkRegistry.checkSignatures(finalityBatch.msgHash, finalityBatch.l2BlockNumber, finalityNonSignerAndSignature);


        uint256 reduciblePeriod = reducibleChallengePeriod(finalityNonSignerAndSignature.totalMantaStake, finalityNonSignerAndSignature.totalBtcStake);

        // call l2output oracle contacts
        if (!isDisputeGameFactory) {
            bool success = SafeCall.callWithMinGas(
                l2OutputOracle,
                minGas,
                0,
                abi.encodeWithSignature("proposalChangeFinalizationPeriodSeconds(bytes32,uint256)", finalityBatch.stateRoot, reduciblePeriod)
            );
            require(success, "StrategyBase.VerifyFinalitySignature: change finalized periods in l2output oracle seconds fail");
        } else {
            // todo: After manta upgrade to fraud proof will use it.
            bool success = SafeCall.callWithMinGas(
                disputeGameFactory,
                minGas,
                0,
                abi.encodeWithSignature("proposalChangeFinalizationPeriodSeconds(bytes32,uint256)", finalityBatch.stateRoot, reduciblePeriod)
            );
            require(success, "StrategyBase.VerifyFinalitySignature: change finalized periods in dispute game factory seconds fail");
        }
        emit VerifyFinalitySig(stakeTotals.totalBtcStaking, stakeTotals.totalMantaStaking, signatoryRecordHash);
    }

    function addOrRemoveOperatorWhitelist(address operator, bool isAdd) external onlyOperatorWhitelistManager {
        require(
            operator != address (0),
            "FinalityRelayerManager.addOperatorWhitelist: operator address is zero"
        );
        operatorWhitelist[operator] = isAdd;
    }

    // ==============================internal function====================================
    function reducibleChallengePeriod(uint256 votedManta, uint256 votedBitcoin) internal pure returns(uint256) {
        uint256 reduciblePeriod =  (votedManta / TARGET_MANTA) * MANTA_REDUCE_PERIOD + (votedBitcoin / TARGET_BITCOIN) * BITCOIN_REDUCE_PERIOD;
        if (reduciblePeriod < MIN_CHALLENGE_PERIOD) {
            return MIN_CHALLENGE_PERIOD;
        }
        return reduciblePeriod;
    }
}
