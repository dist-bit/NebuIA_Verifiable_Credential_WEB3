// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

pragma experimental ABIEncoderV2;

import "./libs/ZeroCopySink.sol";
import "./libs/ZeroCopySource.sol";

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

    function verificationMethod() external view returns (string memory);

    // added if only subject can generate cv
    function owner() external view returns (address);
}

contract NebuVC {
    /**
     * @dev map containing the credentials referenced by a user's address.
     */
    mapping(address => StoreCredential[]) private credentialsUsers_;

    /**
     * @dev proof structure based on https://www.w3.org/TR/vc-data-model/#proofs-signatures.
     */
    struct Proof {
        string typeSignature;
        string proofPurpose;
        string verificationMethod;
        IEIP721.EIP712Domain domain;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 created;
    }

    /**
     * @dev minmal credential structure based
     * on https://www.w3.org/TR/vc-data-model/#basic-concepts.
     */
    struct VerifiableCredential {
        string[] context;
        string[] typeCredential;
        Proof proof;
        address issuer; // contract subject address
        bytes signature;
        bytes credentialSubject; // store credential as bytes
        uint256 issuanceDate;
        uint256 expirationDate;
        IEIP721.Schema credentialSchema;
    }

    struct StoreCredential {
        uint256 index;
        bytes credential;
        bool revoke;
    }

    function serializeStringArray(string[] memory _array)
        internal
        pure
        returns (bytes memory contentsLenBytes, bytes memory contentsBytes)
    {
        contentsLenBytes = ZeroCopySink.WriteUint255(_array.length);
        contentsBytes = new bytes(0);
        for (uint256 i = 0; i < _array.length; i++) {
            contentsBytes = abi.encodePacked(
                contentsBytes,
                ZeroCopySink.WriteVarBytes(bytes(_array[i]))
            );
        }
    }

    function derializeStringArray(bytes memory _data, uint256 _offset)
        internal
        pure
        returns (string[] memory, uint256)
    {
        uint256 contentsLen;
        (contentsLen, _offset) = ZeroCopySource.NextUint255(_data, _offset);
        string[] memory contents = new string[](contentsLen);

        for (uint256 i = 0; i < contentsLen; i++) {
            bytes memory ctrl;
            (ctrl, _offset) = ZeroCopySource.NextVarBytes(_data, _offset);
            contents[i] = string(ctrl);
        }

        return (contents, _offset);
    }

    function serializeSchema(IEIP721.Schema memory _schema)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory idBytes = ZeroCopySink.WriteVarBytes(bytes(_schema.id));

        bytes memory typeSchemaBytes = ZeroCopySink.WriteVarBytes(
            bytes(_schema.typeSchema)
        );

        return abi.encodePacked(idBytes, typeSchemaBytes);
    }

    function deserializeSchema(bytes memory _data, uint256 _offset)
        internal
        pure
        returns (IEIP721.Schema memory, uint256)
    {
        bytes memory id;
        (id, _offset) = ZeroCopySource.NextVarBytes(_data, _offset);

        bytes memory typeSchema;
        (typeSchema, _offset) = ZeroCopySource.NextVarBytes(_data, _offset);

        return (IEIP721.Schema(string(id), string(typeSchema)), _offset);
    }

    function serializeDomain(IEIP721.EIP712Domain memory _domain)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory nameBytes = ZeroCopySink.WriteVarBytes(
            bytes(_domain.name)
        );
        bytes memory versionBytes = ZeroCopySink.WriteVarBytes(
            bytes(_domain.version)
        );

        bytes memory chainIdBytes = ZeroCopySink.WriteUint255(_domain.chainId);
        bytes memory verifyingContractBytes = ZeroCopySink.WriteVarBytes(
            abi.encodePacked(_domain.verifyingContract)
        );

        return
            abi.encodePacked(
                nameBytes,
                versionBytes,
                chainIdBytes,
                verifyingContractBytes
            );
    }

    function deserializeDomain(bytes memory _data, uint256 _offset)
        internal
        pure
        returns (IEIP721.EIP712Domain memory, uint256)
    {
        bytes memory name;
        (name, _offset) = ZeroCopySource.NextVarBytes(_data, _offset);

        bytes memory version;
        (version, _offset) = ZeroCopySource.NextVarBytes(_data, _offset);

        uint256 chainId;
        (chainId, _offset) = ZeroCopySource.NextUint255(_data, _offset);

        bytes memory source = new bytes(0);
        (source, _offset) = ZeroCopySource.NextVarBytes(_data, _offset);

        address addr;
        assembly {
            addr := mload(add(source, 0x14))
        }

        return (
            IEIP721.EIP712Domain(string(name), string(version), chainId, addr),
            _offset
        );
    }

    function serializeProof(Proof memory _proof)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory typeSignatureBytes = ZeroCopySink.WriteVarBytes(
            bytes(_proof.typeSignature)
        );
        bytes memory proofPurposeBytes = ZeroCopySink.WriteVarBytes(
            bytes(_proof.proofPurpose)
        );
        bytes memory verificationMethodBytes = ZeroCopySink.WriteVarBytes(
            bytes(_proof.verificationMethod)
        );

        // serialize domain
        bytes memory domainEncode = serializeDomain(_proof.domain);

        bytes memory vBytes = ZeroCopySink.WriteUint8(_proof.v);
        bytes memory rBytes = ZeroCopySink.WriteVarBytes(
            abi.encodePacked(_proof.r)
        );
        bytes memory sBytes = ZeroCopySink.WriteVarBytes(
            abi.encodePacked(_proof.s)
        );

        bytes memory createdBytes = ZeroCopySink.WriteUint255(_proof.created);

        return
            abi.encodePacked(
                typeSignatureBytes,
                proofPurposeBytes,
                verificationMethodBytes,
                domainEncode,
                vBytes,
                rBytes,
                sBytes,
                createdBytes
            );
    }

    function deserializeProof(bytes memory _data, uint256 _offset)
        internal
        pure
        returns (Proof memory, uint256)
    {
        bytes memory typeSignature;
        (typeSignature, _offset) = ZeroCopySource.NextVarBytes(_data, _offset);

        bytes memory proofPurpose;
        (proofPurpose, _offset) = ZeroCopySource.NextVarBytes(_data, _offset);

        bytes memory verificationMethodCredential;
        (verificationMethodCredential, _offset) = ZeroCopySource.NextVarBytes(
            _data,
            _offset
        );

        IEIP721.EIP712Domain memory domainProof;
        (domainProof, _offset) = deserializeDomain(_data, _offset);

        uint8 v;
        (v, _offset) = ZeroCopySource.NextUint8(_data, _offset);

        bytes memory r_;
        (r_, _offset) = ZeroCopySource.NextVarBytes(_data, _offset);

        bytes memory s_;
        (s_, _offset) = ZeroCopySource.NextVarBytes(_data, _offset);

        uint256 created;
        (created, _offset) = ZeroCopySource.NextUint255(_data, _offset);

        bytes32 r;
        bytes32 s;

        assembly {
            r := mload(add(r_, 32))
            s := mload(add(s_, 32))
        }

        Proof memory proof = Proof(
            string(typeSignature),
            string(proofPurpose),
            string(verificationMethodCredential),
            domainProof,
            v,
            r,
            s,
            created
        );

        return (proof, _offset);
    }

    function serializeCredentialStore(VerifiableCredential memory _credential)
        internal
        pure
        returns (bytes memory)
    {
        (
            bytes memory contextLenBytes,
            bytes memory contextBytes
        ) = serializeStringArray(_credential.context);

        (
            bytes memory typeCredentialLenBytes,
            bytes memory typeCredentialBytes
        ) = serializeStringArray(_credential.typeCredential);

        bytes memory proofBytes = serializeProof(_credential.proof);

        bytes memory issuerBytes = ZeroCopySink.WriteVarBytes(
            abi.encodePacked(_credential.issuer)
        );

        bytes memory signatureBytes = ZeroCopySink.WriteVarBytes(
            _credential.signature
        );
        bytes memory credentialSubject = ZeroCopySink.WriteVarBytes(
            _credential.credentialSubject
        );

        bytes memory issuanceDateBytes = ZeroCopySink.WriteUint255(
            _credential.issuanceDate
        );
        bytes memory expirationDateBytes = ZeroCopySink.WriteUint255(
            _credential.expirationDate
        );

        bytes memory schemaBytes = serializeSchema(
            _credential.credentialSchema
        );

        return
            abi.encodePacked(
                contextLenBytes,
                contextBytes,
                typeCredentialLenBytes,
                typeCredentialBytes,
                proofBytes,
                issuerBytes,
                signatureBytes,
                credentialSubject,
                issuanceDateBytes,
                expirationDateBytes,
                schemaBytes
            );
    }

    function deserializeCredentialStore(bytes memory _data)
        internal
        pure
        returns (VerifiableCredential memory _credential)
    {
        string[] memory contextCredential;
        uint256 offset;
        (contextCredential, offset) = derializeStringArray(_data, 0);

        string[] memory typeCredential;
        (typeCredential, offset) = derializeStringArray(_data, offset);

        Proof memory proof;
        (proof, offset) = deserializeProof(_data, offset);

        bytes memory source = new bytes(0);
        (source, offset) = ZeroCopySource.NextVarBytes(_data, offset);

        address issuer;
        assembly {
            issuer := mload(add(source, 0x14))
        }

        bytes memory signature;
        (signature, offset) = ZeroCopySource.NextVarBytes(_data, offset);

        bytes memory credentialSubject;
        (credentialSubject, offset) = ZeroCopySource.NextVarBytes(
            _data,
            offset
        );

        uint256 issuanceDate;
        (issuanceDate, offset) = ZeroCopySource.NextUint255(_data, offset);

        uint256 expirationDate;
        (expirationDate, offset) = ZeroCopySource.NextUint255(_data, offset);

        IEIP721.Schema memory credentialSchema;
        (credentialSchema, offset) = deserializeSchema(_data, offset);

        _credential = VerifiableCredential(
            contextCredential,
            typeCredential,
            proof,
            issuer,
            signature,
            credentialSubject,
            issuanceDate,
            expirationDate,
            credentialSchema
        );
    }

    /**
     * @dev Create proof object - https://www.w3.org/TR/vc-data-model/#proofs-signatures
     */
    function createProof(IEIP721 vc, bytes memory _signature)
        internal
        view
        returns (Proof memory)
    {
        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = splitSignature(_signature);
        // create proof
        Proof memory proof = Proof(
            "secp256k1", // default eip712 https://eips.ethereum.org/EIPS/eip-712#signatures-and-hashing-overview
            "assertionMethod", // proofPurpose
            verificationMethod(vc), //verificationMethod
            domain(vc),
            v,
            r,
            s,
            block.timestamp //created
        );

        return proof;
    }

    /**
     * @dev Check if exist credentials with same signature that new
     */
    /*function duplicate(address filter_, bytes memory signature_)
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
    }*/

    /**
     * @dev Verify credential - emit by user
     */
    function verifyVC(
        uint256 index_,
        bytes memory signature_
    ) public view returns (bool) {
        // get credential by index
        StoreCredential memory store = credentialsUsers_[msg.sender][index_];
        VerifiableCredential memory credential = deserializeCredentialStore(
            store.credential
        );
        // init subject contract
        IEIP721 vc = IEIP721(credential.issuer);
        // check signature

        if (
            msg.sender !=
            vc.recoverSignerFromBytes(credential.credentialSubject, signature_)
        ) {
            return false;
        }

        if (store.revoke) {
            return false;
        }

        if (
            credential.expirationDate != 0x000000 &&
            credential.expirationDate < block.timestamp
        ) {
            return false;
        }

        return true;
    }

    /**
     * @dev Revoe credential - only credential owner can revoke
     */
    function revokeVC(
        address owner_,
        address issuer_,
        uint256 index_
    ) public {
        // get credential by index
        StoreCredential memory store = credentialsUsers_[owner_][index_];
        // init subject contract
        IEIP721 vc = IEIP721(issuer_);

        require(!store.revoke, "credential already revoked");

        require(msg.sender == owner(vc), "invalid issuer");

        credentialsUsers_[owner_][index_].revoke = true;
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
        //require(!duplicate(to_, signature_), "duplicate signature found");

        // check signature
        require(
            to_ == vc.recoverSignerFromBytes(identity_, signature_),
            "signer not match"
        );

        Proof memory proof = createProof(vc, signature_);
        // create credential
        VerifiableCredential memory storeCredential = VerifiableCredential(
            context(vc),
            types(vc),
            proof,
            service_, // contract subject
            signature_, // signature,
            identity_, //credentialSubject
            block.timestamp, //issuanceDate,
            expiration_, // expiration
            schema(vc)
        );

        bytes memory encode = serializeCredentialStore(storeCredential);
        //StoreCredential memory _t = deserializeCredentialStore(encode);
        uint256 index = credentialsUsers_[to_].length;

        StoreCredential memory store = StoreCredential(index, encode, false);

        credentialsUsers_[to_].push(store);
    }

    /**
     * @dev Get all credentials from user - alny callable from owner
     */
    function getVCFromUser()
        public
        view
        returns (VerifiableCredential[] memory)
    {
        StoreCredential[] memory store = credentialsUsers_[msg.sender];

        uint256 length = store.length;
        VerifiableCredential[] memory credentials = new VerifiableCredential[](
            length
        );
        for (uint256 i = 0; i < length; i++) {
            VerifiableCredential memory credential = deserializeCredentialStore(
                store[i].credential
            );
            credentials[i] = credential;
        }
        return credentials;
    }

    /**
     * @dev Get contract subject domain - replay attacks
     */
    function domain(IEIP721 vc_)
        public
        view
        returns (IEIP721.EIP712Domain memory)
    {
        return vc_.domain();
    }

    function verificationMethod(IEIP721 vc_)
        public
        view
        returns (string memory)
    {
        return vc_.verificationMethod();
    }

    /**
     * @dev Get contract subject context - https://www.w3.org/TR/vc-data-model/#contexts
     */
    function context(IEIP721 vc_) public view returns (string[] memory) {
        return vc_.context();
    }

    /**
     * @dev Get contract subject types -https://www.w3.org/TR/vc-data-model/#types
     */
    function types(IEIP721 vc_) public view returns (string[] memory) {
        return vc_.typeCredential();
    }

    function schema(IEIP721 vc_) public view returns (IEIP721.Schema memory) {
        return vc_.schema();
    }

    /**
     * @dev Get contract subject owner
     */
    function owner(IEIP721 vc_) public view returns (address) {
        return vc_.owner();
    }

    /**
     * @dev Return r, s, v => digest
     */
    function splitSignature(bytes memory sig_)
        internal
        pure
        returns (
            uint8,
            bytes32,
            bytes32
        )
    {
        require(sig_.length == 65);

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            // first 32 bytes, after the length prefix
            r := mload(add(sig_, 32))
            // second 32 bytes
            s := mload(add(sig_, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig_, 96)))
        }

        return (v, r, s);
    }
}
