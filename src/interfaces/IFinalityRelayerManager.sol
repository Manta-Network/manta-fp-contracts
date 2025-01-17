// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../libraries/BN254.sol";
import "./IBLSApkRegistry.sol";

interface IFinalityRelayerManager {

    event OperatorRegistered(address indexed operator, string nodeUrl);
    event OperatorDeRegistered(address operator);

    event VerifyFinalitySig(
        uint256 batchId,
        uint256 totalBtcStaking,
        uint256 totalMantaStaking,
        bytes32 signatoryRecordHash
    );

    struct FinalityBatch {
        bytes32 stateRoot;
        uint256 l2BlockNumber;
        bytes32 l1BlockHash;
        uint256 l1BlockNumber;
        bytes32 msgHash;
        uint32  disputeGameType;
    }

    struct PubkeyRegistrationParams {
        BN254.G1Point pubkeyRegistrationSignature;
        BN254.G1Point pubkeyG1;
        BN254.G2Point pubkeyG2;
    }

    function registerOperator(string calldata nodeUrl) external;

    function deRegisterOperator() external;

    function VerifyFinalitySignature(
        FinalityBatch calldata finalityBatch,
        IBLSApkRegistry.FinalityNonSignerAndSignature memory finalityNonSignerAndSignature,
        uint256 minGas
    ) external;

    function addOrRemoveOperatorWhitelist(address operator, bool isAdd) external;
}
