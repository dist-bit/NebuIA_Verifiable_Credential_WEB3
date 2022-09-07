// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

pragma experimental ABIEncoderV2;

interface IEIP721 {
    struct Schema {
        string id;
        string typeSchema;
    }

    struct EIP712Domain {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
    }

    function recoverSignerFromBytes(
        bytes memory _identity,
        bytes memory _signature
    ) external view returns (address);

    // metadata??
    function issuer() external view returns (string memory);

    function context() external view returns (string[] memory);

    function id() external view returns (string memory);

    function typeCredential() external view returns (string[] memory);

    function schema() external view returns (Schema memory);

    function domain() external view returns (EIP712Domain memory);

    // added if only subject can generate cv
    function owner() external view returns (address);
}

contract NebuVC {
    mapping(address => StoreCredential[]) private _credentials;

    struct Proof {
        string typeSignature;
        uint256 created;
        string proofPurpose;
        string verificationMethod;
        IEIP721.EIP712Domain domain;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    struct StoreCredential {
        uint256 index;
        string[] context;
        string[] typeCredential;
        uint256 issuanceDate;
        uint256 expirationDate;
        Proof proof;
        bool revoke;
        address issuer; // contract subject address
        bytes signature;
        bytes credentialSubject; // store credential as bytes
    }
/*
    struct VerifiableCredential {
        string[] context;
        string id;
        string[] typeCredential;
        string issuer; // vc propertie
        uint256 issuanceDate;
        uint256 expirationDate;
        bytes credentialSubject;
        Proof proof;
        IEIP721.Schema credentialSchema;
    }
*/

    /**
     * @dev Create proof object - https://www.w3.org/TR/vc-data-model/#proofs-signatures
     */
    function cresteProof(IEIP721 vc, bytes memory signature_)
        internal
        view
        returns (Proof memory)
    {
        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = splitSignature(signature_);
        // create proof
        return
            Proof(
                "secp256k1", // default eip712 https://eips.ethereum.org/EIPS/eip-712#signatures-and-hashing-overview
                block.timestamp, //creates
                "assertionMethod", //proofPurpose
                "https://example.edu/issuers/14#key-1", //verificationMethod
                domain(vc),
                v,
                r,
                s
            );
    }

    /**
     * @dev Check if exist credentials with same signature that new
     */
    function duplicate(address filter_, bytes memory signature_)
        internal
        view
        returns (bool)
    {
        StoreCredential[] memory credentials = _credentials[filter_];

        uint256 arrayLength = credentials.length;
        for (uint256 i = 0; i < arrayLength; i++) {
            if (keccak256(signature_) == keccak256(credentials[i].signature)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @dev Verify credential by signature and claim
     */
      function verifyVC(
        address owner_,
        uint index_,
        bytes memory signature_
    ) public view returns (bool) {
        // get credential by index
        StoreCredential memory credential = _credentials[owner_][index_];
        // init subject contract
        IEIP721 vc = IEIP721(credential.issuer);
        // check signature
        require(
            owner_ == vc.recoverSignerFromBytes(credential.credentialSubject, signature_),
            "signer not match"
        );

        return true;
    }

    /**
     * @dev Create credential in minimal form
     */
    function createVC(
        address service_,
        address to_,
        bytes memory identity_,
        bytes memory signature_,
        uint256 expiration_
    ) public {
        // init subject contract
        IEIP721 vc = IEIP721(service_);

        // check for subject deploy
        require(msg.sender == owner(vc), "subject creator not match");

        // reject duplicate credential with same signature
        require(!duplicate(to_, signature_), "duplicate signature found");

        // check signature
        require(
            to_ == vc.recoverSignerFromBytes(identity_, signature_),
            "signer not match"
        );

        Proof memory proof = cresteProof(vc, signature_);

        uint256 index = _credentials[to_].length;

        StoreCredential memory storeCredential = StoreCredential(
            index + 1, // index store
            context(vc),
            types(vc),
            block.timestamp, //issuanceDate,
            expiration_, // expiration
            proof,
            false,
            service_, // contract subject
            signature_, // signatur,
            identity_ //credentialSubject
        );

        _credentials[to_].push(storeCredential);
    }

    /** 
     * @dev Get all credentials from user - alny callable from owner
     */
    function getVCs()
        public
        view
        returns (StoreCredential[] memory)
    {
        return _credentials[msg.sender];
    }

    /**
     * @dev Get contract subject domain - replay attacks
     */
    function domain(IEIP721 vc)
        public
        view
        returns (IEIP721.EIP712Domain memory)
    {
        return vc.domain();
    }

    /**
     * @dev Get contract subject context - https://www.w3.org/TR/vc-data-model/#contexts 
     */
    function context(IEIP721 vc)
        public
        view
        returns (string[] memory)
    {
        return vc.context();
    }

    /**
     * @dev Get contract subject types -https://www.w3.org/TR/vc-data-model/#types
     */
    function types(IEIP721 vc)
        public
        view
        returns (string[] memory)
    {
        return vc.typeCredential();
    }


    /**
     * @dev Get contract subject owner
     */
    function owner(IEIP721 vc) public view returns (address) {
        return vc.owner();
    }

    /**
     * @dev Return r, s, v => digest
     */
    function splitSignature(bytes memory sig)
        internal
        pure
        returns (
            uint8,
            bytes32,
            bytes32
        )
    {
        require(sig.length == 65);

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        return (v, r, s);
    }
}
