// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IEIP721 {
    struct Schema {
        string id;
        string typeSchema;
    }

    // requiered field
    struct EIP712Domain {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
    }

    /**
     * @dev Validate EIP712 signature
     * @return address signer
     */
    function recoverSignerFromBytes(
        bytes memory _identity,
        bytes memory _signature
    ) external view returns (address);

    /**
     * @dev Split signature to get digest (v,r,s)
     * @return address signer
     */
    function splitSignatureFromBytes(bytes memory _signature)
        external
        view
        returns (
            uint8,
            bytes32,
            bytes32
        );
}

/**
 * @dev Based VC by w3c
 */
interface IEIP721Metadata is IEIP721 {
    /**
     * @dev The entity hat issued the credential
     */
    function issuer() external view returns (string memory);

    /**
     * @dev Set the context which stablishes e special terms e will  using.
     */
    function context() external view returns (string[] memory);

    /**
     * @dev Specify e identifier for the credenttial.
     */
    function id() external view returns (string memory);

    /**
     * @dev The credential types which declare at datao expect in this credential.
     */
    function typeCredential() external view returns (string[] memory);

    /**
     * @dev https://www.w3.org/TR/vc-data-model/#data-schemas
     */
    function schema() external view returns (Schema memory);

    /**
     * @dev the identifier that  verify e signature
     */
    function verificationMethod() external view returns (string memory);

    /**
     * @dev protect against replay atack
     */
    function domain() external view returns (EIP712Domain memory);
}