// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IImuaCapsule} from "../interfaces/IImuaCapsule.sol";
import {INativeRestakingController} from "../interfaces/INativeRestakingController.sol";
import {BeaconChainProofs} from "../libraries/BeaconChainProofs.sol";
import {ValidatorContainer} from "../libraries/ValidatorContainer.sol";

import {Action} from "../storage/GatewayStorage.sol";
import {BaseRestakingController} from "./BaseRestakingController.sol";

import {Errors} from "../libraries/Errors.sol";

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

/// @title NativeRestakingController
/// @author imua-xyz
/// @notice This is the implementation of INativeRestakingController. It allows Ethereum validators
/// to stake, deposit and withdraw from the Ethereum beacon chain.
/// @dev This contract is abstract because it does not call the base constructor.
abstract contract NativeRestakingController is
    PausableUpgradeable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    INativeRestakingController,
    BaseRestakingController
{

    using ValidatorContainer for bytes32[];

    /// @notice Stakes 32 ETH on behalf of the validators in the Ethereum beacon chain, and
    /// points the withdrawal credentials to the capsule contract, creating it if necessary.
    /// @param pubkey The validator's BLS12-381 public key.
    /// @param signature Value signed by the @param pubkey.
    /// @param depositDataRoot The SHA-256 hash of the SSZ-encoded DepositData object.
    function stake(bytes calldata pubkey, bytes calldata signature, bytes32 depositDataRoot)
        external
        payable
        whenNotPaused
        nonReentrant
        nativeRestakingEnabled
    {
        IImuaCapsule capsule = ownerToCapsule[msg.sender];
        if (address(capsule) == address(0)) {
            capsule = IImuaCapsule(createImuaCapsule());
        }

        if (capsule.isPectraMode()) {
            if (
                msg.value < AFTER_PECTRA_MIN_ACTIVATION_BALANCE_ETH_PER_VALIDATOR
                    || msg.value > AFTER_PECTRA_MAX_EFFECTIVE_BALANCE_ETH_PER_VALIDATOR
            ) {
                revert Errors.NativeRestakingControllerInvalidStakeValue();
            }
        } else {
            if (msg.value != AFTER_PECTRA_MIN_ACTIVATION_BALANCE_ETH_PER_VALIDATOR) {
                revert Errors.NativeRestakingControllerInvalidStakeValue();
            }
        }

        if (msg.value % 1 gwei != 0) {
            revert Errors.NativeRestakingControllerInvalidStakeValue();
        }

        ETH_POS.deposit{value: msg.value}(pubkey, capsule.capsuleWithdrawalCredentials(), signature, depositDataRoot);
        emit StakedWithCapsule(msg.sender, address(capsule), msg.value);
    }

    /// @notice Creates a new ImuaCapsule contract for the message sender.
    /// @notice The message sender must be payable
    /// @return The address of the newly created ImuaCapsule contract.
    // The bytecode returned by `BEACON_PROXY_BYTECODE` and `IMUA_CAPSULE_BEACON` address are actually fixed size of
    // byte
    // array, so it would not cause collision for encodePacked
    // slither-disable-next-line encode-packed-collision
    function createImuaCapsule() public whenNotPaused nativeRestakingEnabled returns (address) {
        if (address(ownerToCapsule[msg.sender]) != address(0)) {
            revert Errors.NativeRestakingControllerCapsuleAlreadyCreated();
        }
        IImuaCapsule capsule = IImuaCapsule(
            Create2.deploy(
                0,
                bytes32(uint256(uint160(msg.sender))),
                // set the beacon address for beacon proxy
                abi.encodePacked(BEACON_PROXY_BYTECODE.getBytecode(), abi.encode(address(IMUA_CAPSULE_BEACON), ""))
            )
        );

        // we follow check-effects-interactions pattern to write state before external call
        ownerToCapsule[msg.sender] = capsule;
        capsule.initialize(address(this), payable(msg.sender), BEACON_ORACLE_ADDRESS);

        emit CapsuleCreated(msg.sender, address(capsule));

        return address(capsule);
    }

    /// @notice Verifies a deposit proof from the beacon chain and forwards the information to Imuachain.
    /// @param validatorContainer The validator container which made the deposit.
    /// @param proof The proof of the validator container.
    function verifyAndDepositNativeStake(
        bytes32[] calldata validatorContainer,
        BeaconChainProofs.ValidatorContainerProof calldata proof
    ) external payable whenNotPaused nonReentrant nativeRestakingEnabled {
        IImuaCapsule capsule = _getCapsule(msg.sender);
        uint256 depositValue = capsule.verifyDepositProof(validatorContainer, proof);

        bytes memory actionArgs = abi.encodePacked(bytes32(bytes20(msg.sender)), depositValue, proof.validatorIndex);

        // deposit NST is a must-succeed action, so we don't need to check the response
        _processRequest(Action.REQUEST_DEPOSIT_NST, actionArgs, bytes(""));
    }

    /// @notice Deposits native stake for non-Ethereum NST chains (e.g. BNB on BSC).
    /// @dev This method is NOT using beacon-chain proofs. Instead, it forwards `msg.value` into the capsule
    /// and lets the capsule perform chain-specific locking/delegation (e.g. StakeHub delegation).
    /// The `validatorID` is forwarded to Imuachain as the NST identifier.
    /// @param validatorID Chain-specific validator identifier. For BNB, we typically pass the validator EVM address bytes.
    function depositNativeStake(bytes calldata validatorID)
        external
        payable
        whenNotPaused
        nonReentrant
        nativeRestakingEnabled
    {
        // Generic NST flows are not supported for now.
        // For BNBNST, use `depositBNBNST(address validator)` so that Imuachain's validatorID == capsule address.
        validatorID;
        revert Errors.NotYetSupported();
    }

    /// @notice BNBNST deposit on BSC-like chains.
    /// @dev Flow:
    /// - create capsule if first time
    /// - capsule delegates BNB (capsule address becomes the on-chain "delegator")
    /// - Imuachain depositNST uses validatorID = capsule address (oracle will later query lockedBNBs+pooledBNBs by capsule)
    function depositBNBNST(address validator)
        external
        payable
        whenNotPaused
        nonReentrant
        nativeRestakingEnabled
    {
        if (msg.value == 0) revert Errors.ZeroValue();
        if (validator == address(0)) revert Errors.ZeroValue();

        IImuaCapsule capsule = ownerToCapsule[msg.sender];
        if (address(capsule) == address(0)) {
            capsule = IImuaCapsule(createImuaCapsule());
        }

        (bool ok,) =
            address(capsule).call{value: msg.value}(abi.encodeWithSignature("depositAndDelegate(address)", validator));
        if (!ok) revert Errors.NativeRestakingControllerUnsupportedNativeDeposit();

        // For BNB: validatorID on Imuachain is the delegator capsule address.
        bytes memory actionArgs = abi.encodePacked(bytes32(bytes20(msg.sender)), uint256(msg.value), bytes20(address(capsule)));
        _processRequest(Action.REQUEST_DEPOSIT_NST, actionArgs, bytes(""));
    }

    /// @notice Send request to Imuachain to claim the NST principal.
    /// @notice This would not result in ETH transfer even if result is successful because it only unlocks the NST.
    /// @dev This function requests claim approval from Imuachain. If approved, the assets are
    /// unlocked and can be withdrawn by the user. Otherwise, they remain locked.
    /// @param claimAmount The amount of NST the user intends to claim, cannot be greater than the
    /// staker's capsule's balance and staker's staking position's withdrawable balance.
    function claimNSTFromImuachain(uint256 claimAmount)
        external
        payable
        whenNotPaused
        nonReentrant
        nativeRestakingEnabled
    {
        IImuaCapsule capsule = _getCapsule(msg.sender);
        capsule.startClaimNST(claimAmount);
        bytes memory actionArgs = abi.encodePacked(bytes32(bytes20(msg.sender)), claimAmount);
        bytes memory encodedRequest = abi.encode(VIRTUAL_NST_ADDRESS, msg.sender, claimAmount);

        // any claim might succeed or fail, so we need to cache the request to handle response
        _processRequest(Action.REQUEST_WITHDRAW_NST, actionArgs, encodedRequest);
    }

    /// @notice Request partial withdrawal from a validator via beacon chain (Pectra mode only)
    /// @param pubkey The validator's BLS public key (48 bytes)
    /// @param amountInGwei The amount to withdraw in Gwei
    function requestBeaconPartialWithdrawal(bytes calldata pubkey, uint64 amountInGwei)
        external
        payable
        override
        whenNotPaused
        nonReentrant
        nativeRestakingEnabled
    {
        IImuaCapsule capsule = _getCapsule(msg.sender);
        capsule.requestPartialWithdrawal{value: msg.value}(pubkey, amountInGwei);
    }

    /// @notice Request full withdrawal from a validator via beacon chain (Pectra mode only)
    /// @param pubkey The validator's BLS public key (48 bytes)
    function requestBeaconFullWithdrawal(bytes calldata pubkey)
        external
        payable
        override
        whenNotPaused
        nonReentrant
        nativeRestakingEnabled
    {
        IImuaCapsule capsule = _getCapsule(msg.sender);
        capsule.requestFullWithdrawal{value: msg.value}(pubkey);
    }

}
