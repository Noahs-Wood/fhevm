// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

import "./KMSVerifier.sol";
import "./TFHEExecutor.sol";
import "../addresses/KMSVerifierAddress.sol";
import "../addresses/CoprocessorAddress.sol";

// Importing OpenZeppelin contracts for cryptographic signature verification and access control.
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

/// @title InputVerifier for signature verification of users encrypted inputs
/// @notice This version is only for the Coprocessor version of fhEVM
/// @notice This contract is called by the TFHEExecutor inside verifyCiphertext function, and calls the KMSVerifier to fetch KMS signers addresses
/// @dev The contract uses OpenZeppelin's EIP712Upgradeable for cryptographic operations
contract InputVerifier is UUPSUpgradeable, Ownable2StepUpgradeable, EIP712Upgradeable {
    struct CiphertextVerificationForCopro {
        address aclAddress;
        bytes32 hashOfCiphertext;
        uint256[] handlesList;
        address userAddress;
        address contractAddress;
    }

    /// @notice Handle version
    uint8 public constant HANDLE_VERSION = 0;

    KMSVerifier public constant kmsVerifier = KMSVerifier(kmsVerifierAdd);

    /// @notice Name of the contract
    string private constant CONTRACT_NAME = "InputVerifier";

    /// @notice Version of the contract
    uint256 private constant MAJOR_VERSION = 0;
    uint256 private constant MINOR_VERSION = 1;
    uint256 private constant PATCH_VERSION = 0;

    function _authorizeUpgrade(address _newImplementation) internal virtual override onlyOwner {}

    /// @notice Getter function for the KMSVerifier contract address
    function getKMSVerifierAddress() public view virtual returns (address) {
        return address(kmsVerifier);
    }

    address private constant coprocessorAddress = coprocessorAdd;
    string public constant CIPHERTEXTVERIFICATION_COPRO_TYPE =
        "CiphertextVerificationForCopro(address aclAddress,bytes32 hashOfCiphertext,uint256[] handlesList,address userAddress,address contractAddress)";
    bytes32 private constant CIPHERTEXTVERIFICATION_COPRO_TYPE_HASH =
        keccak256(bytes(CIPHERTEXTVERIFICATION_COPRO_TYPE));

    function get_CIPHERTEXTVERIFICATION_COPRO_TYPE() public view virtual returns (string memory) {
        return CIPHERTEXTVERIFICATION_COPRO_TYPE;
    }

    /// @notice Getter function for the Coprocessor account address
    function getCoprocessorAddress() public view virtual returns (address) {
        return coprocessorAddress;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract setting `initialOwner` as the initial owner
    function initialize(address initialOwner) external initializer {
        __Ownable_init(initialOwner);
        __EIP712_init(CONTRACT_NAME, "1");
    }

    function typeOf(uint256 handle) internal pure virtual returns (uint8) {
        uint8 typeCt = uint8(handle >> 8);
        return typeCt;
    }

    function checkProofCache(
        bytes memory inputProof,
        address userAddress,
        address contractAddress,
        address aclAddress
    ) internal view virtual returns (bool, bytes32) {
        bool isProofCached;
        bytes32 key = keccak256(abi.encodePacked(contractAddress, aclAddress, userAddress, inputProof));
        assembly {
            isProofCached := tload(key)
        }
        return (isProofCached, key);
    }

    function cacheProof(bytes32 proofKey) internal virtual {
        assembly {
            tstore(proofKey, 1)
        }
    }

    function verifyCiphertext(
        TFHEExecutor.ContextUserInputs memory context,
        bytes32 inputHandle,
        bytes memory inputProof
    ) external virtual returns (uint256) {
        (bool isProofCached, bytes32 cacheKey) = checkProofCache(
            inputProof,
            context.userAddress,
            context.contractAddress,
            context.aclAddress
        );
        uint256 result = uint256(inputHandle);
        return result;
    }

    function verifyEIP712Copro(CiphertextVerificationForCopro memory cv, bytes memory signature) internal view virtual {
        bytes32 digest = hashCiphertextVerificationForCopro(cv);
        address signer = ECDSA.recover(digest, signature);
        require(signer == coprocessorAddress, "Coprocessor address mismatch");
    }

    function hashCiphertextVerificationForCopro(
        CiphertextVerificationForCopro memory CVcopro
    ) internal view virtual returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        CIPHERTEXTVERIFICATION_COPRO_TYPE_HASH,
                        CVcopro.aclAddress,
                        CVcopro.hashOfCiphertext,
                        keccak256(abi.encodePacked(CVcopro.handlesList)),
                        CVcopro.userAddress,
                        CVcopro.contractAddress
                    )
                )
            );
    }

    /// @notice recovers the signer's address from a `signature` and a `message` digest
    /// @dev Utilizes ECDSA for actual address recovery
    /// @param message The hash of the message that was signed
    /// @param signature The signature to verify
    /// @return signer The address that supposedly signed the message
    function recoverSigner(bytes32 message, bytes memory signature) internal pure virtual returns (address) {
        address signerRecovered = ECDSA.recover(message, signature);
        return signerRecovered;
    }

    /// @notice Getter for the name and version of the contract
    /// @return string representing the name and the version of the contract
    function getVersion() external pure virtual returns (string memory) {
        return
            string(
                abi.encodePacked(
                    CONTRACT_NAME,
                    " v",
                    Strings.toString(MAJOR_VERSION),
                    ".",
                    Strings.toString(MINOR_VERSION),
                    ".",
                    Strings.toString(PATCH_VERSION)
                )
            );
    }
}
