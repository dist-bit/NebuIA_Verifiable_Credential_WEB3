// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

pragma experimental ABIEncoderV2;

import "../libs/ZeroCopySink.sol";
import "../libs/ZeroCopySource.sol";
import "../EIP/IEIP712.sol";
import "../utils/Ownable.sol";

contract _DocumentMultiSign is IEIP721, IEIP721Metadata {
    // Credential issuer
    string private _issuer;

    // Credential context
    string[] private _context;

    // Credential identifier
    string private _id;

    // Credential type
    string[] private _type;

    // Credential verification method
    string _verificationMethod;

    // Credential type
    Schema private _schema;

    EIP712Domain private _domain;

    // sample claim
    struct Signatories {
        address signatory;
        bytes signature;
    }

    // Credential subject - can be named differently
    struct Document {
        string id;
        bytes32 hash;
        Signatories[] signatories;
    }

    struct DocumentToSign {
        bytes32 hash;
    }

    // EIP Domain
    bytes32 constant EIP712DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    bytes32 constant SIGNATORIES_TYPEHASH =
        keccak256("Signatories(address signatory,bytes signature)");

    bytes32 constant DOCUMENTSIGN_TYPEHASH =
        keccak256("DocumentToSign(bytes32 hash)");

    bytes32 constant DOCUMENT_TYPEHASH =
        keccak256(
            "Document(string id,bytes32 hash,Signatories[] signatories)Signatories(address signatory,bytes signature)"
        );

    bytes32 DOMAIN_SEPARATOR;

    constructor(
        string memory issuer_,
        string[] memory context_,
        string memory id_,
        string[] memory type_,
        string memory verificationMethod_,
        Schema memory schema_,
        address verifyingContract_,
        string memory name_,
        string memory version_,
        uint256 chain_
    ) {
        _issuer = issuer_;
        _context = context_;
        _id = id_;
        _type = type_;
        _verificationMethod = verificationMethod_;
        _schema = schema_;

        _domain = EIP712Domain({
            name: name_,
            version: version_,
            chainId: chain_,
            verifyingContract: verifyingContract_
        });
        // set credential types
        DOMAIN_SEPARATOR = hash(_domain);
    }

    /**
     * @dev See {IEIP721Metadata-issuer}.
     */
    function issuer() public view virtual override returns (string memory) {
        return _issuer;
    }

    /**
     * @dev See {IEIP721Metadata-context}.
     */
    function context() public view virtual override returns (string[] memory) {
        return _context;
    }

    /**
     * @dev See {IEIP721Metadata-id}.
     */
    function id() public view virtual override returns (string memory) {
        return _id;
    }

    /**
     * @dev See {IEIP721Metadata-schema}.
     */
    function schema() public view virtual override returns (Schema memory) {
        return _schema;
    }

    /**
     * @dev See {IEIP721Metadata-verificationMethod}.
     */
    function verificationMethod()
        public
        view
        virtual
        override
        returns (string memory)
    {
        return _verificationMethod;
    }

    function domain()
        public
        view
        virtual
        override
        returns (EIP712Domain memory)
    {
        return _domain;
    }

    /**
     * @dev See {IEIP721Metadata-type}.
     */
    function typeCredential()
        public
        view
        virtual
        override
        returns (string[] memory)
    {
        return _type;
    }

    function hash(EIP712Domain memory eip712Domain)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encode(
                    EIP712DOMAIN_TYPEHASH,
                    keccak256(bytes(eip712Domain.name)),
                    keccak256(bytes(eip712Domain.version)),
                    eip712Domain.chainId,
                    eip712Domain.verifyingContract
                )
            );
    }

    function hash(Signatories memory signatatories)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encode(
                    SIGNATORIES_TYPEHASH,
                    signatatories.signatory,
                    keccak256(signatatories.signature)
                )
            );
    }

    function hash(Signatories[] memory signatatories)
        internal
        pure
        returns (bytes32)
    {
        bytes32[] memory _array = new bytes32[](signatatories.length);
        for (uint256 i = 0; i < signatatories.length; ++i) {
            _array[i] = hash(signatatories[i]);
        }

        return keccak256(abi.encodePacked(_array));
    }

    function hash(Document memory document) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    DOCUMENT_TYPEHASH,
                    keccak256(bytes(document.id)),
                    document.hash,
                    hash(document.signatories)
                )
            );
    }

    function hash(DocumentToSign memory document)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(DOCUMENTSIGN_TYPEHASH, document.hash));
    }

    function serializeSignatory(Signatories memory signatories)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory signatoryBytes = ZeroCopySink.WriteVarBytes(
            abi.encodePacked(signatories.signatory)
        );

        bytes memory signatureBytes = ZeroCopySink.WriteVarBytes(
            signatories.signature
        );

        return abi.encodePacked(signatoryBytes, signatureBytes);
    }

    function deserializeSignatory(bytes memory _data, uint256 _offset)
        internal
        pure
        returns (Signatories memory signatories, uint256)
    {
        bytes memory source = new bytes(0);
        (source, _offset) = ZeroCopySource.NextVarBytes(_data, _offset);

        address signatory;
        assembly {
            signatory := mload(add(source, 0x14))
        }

        bytes memory signature;
        (signature, _offset) = ZeroCopySource.NextVarBytes(_data, _offset);

        return (Signatories(signatory, signature), _offset);
    }

    function serializeDocument(Document memory document)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory idBytes = ZeroCopySink.WriteVarBytes(
            abi.encodePacked(bytes(document.id))
        );

        bytes memory hashBytes = ZeroCopySink.WriteVarBytes(
            abi.encodePacked(document.hash)
        );

        bytes memory signatoriesLenBytes = ZeroCopySink.WriteUint255(
            document.signatories.length
        );

        bytes memory signatoriesBytes = new bytes(0);
        for (uint256 i = 0; i < document.signatories.length; i++) {
            bytes memory encodeUniversity = serializeSignatory(
                document.signatories[i]
            );

            signatoriesBytes = abi.encodePacked(
                signatoriesBytes,
                encodeUniversity
            );
        }
        return
            abi.encodePacked(
                idBytes,
                hashBytes,
                signatoriesLenBytes,
                signatoriesBytes
            );
    }

    function deserializeDocument(bytes memory data)
        public
        pure
        returns (Document memory)
    {
        (bytes memory idData, uint256 offset) = ZeroCopySource.NextVarBytes(
            data,
            0
        );

        bytes memory _hash;
        (_hash, offset) = ZeroCopySource.NextVarBytes(data, offset);

        bytes32 hashValue;

        assembly {
            hashValue := mload(add(_hash, 32))
        }

        uint256 signatoriesLen;
        (signatoriesLen, offset) = ZeroCopySource.NextUint255(data, offset);
        Signatories[] memory signatories = new Signatories[](signatoriesLen);

        for (uint256 i = 0; i < signatoriesLen; i++) {
            Signatories memory signatory;
            (signatory, offset) = deserializeSignatory(data, offset);
            signatories[i] = signatory;
        }

        return Document(string(idData), hashValue, signatories);
    }

    function verify(
        Document memory document,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal view returns (address) {
        // Note: we need to use `encodePacked` here instead of `encode`.
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hash(document))
        );

        return ecrecover(digest, v, r, s);
    }

    function verify(
        DocumentToSign memory document,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal view returns (address) {
        // Note: we need to use `encodePacked` here instead of `encode`.
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hash(document))
        );

        return ecrecover(digest, v, r, s);
    }

    function recoverSigner(Document memory document, bytes memory _signature)
        public
        view
        returns (address)
    {
        uint8 v;
        bytes32 r;
        bytes32 s;

        (v, r, s) = splitSignature(_signature);

        return verify(document, v, r, s);
    }

    function recoverSignerHash(
        DocumentToSign memory document,
        bytes memory _signature
    ) public view returns (address) {
        uint8 v;
        bytes32 r;
        bytes32 s;

        (v, r, s) = splitSignature(_signature);

        return verify(document, v, r, s);
    }

    function splitSignatureFromBytes(bytes memory signature_)
        public
        pure
        override
        returns (
            uint8,
            bytes32,
            bytes32
        )
    {
        return splitSignature(signature_);
    }

    function recoverSignerFromBytes(bytes memory data_, bytes memory signature_)
        public
        view
        override
        returns (address)
    {
        uint8 v;
        bytes32 r;
        bytes32 s;

        (v, r, s) = splitSignature(signature_);

        Document memory document = deserializeDocument(data_);
        return verify(document, v, r, s);
    }

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

contract DocumentMultiSign is _DocumentMultiSign, Ownable {
    constructor(
        string memory issuer_,
        string[] memory context_,
        string memory id_,
        string[] memory type_,
        string memory verificationMethod_,
        Schema memory schema_
    )
        _DocumentMultiSign(
            issuer_,
            context_,
            id_,
            type_,
            verificationMethod_,
            schema_,
            // domain
            0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC, // contract verifier
            "DocumentMultiSign", // name credential
            "1", // version
            1 // chain id
        )
    {}

    function viewVersion() public view onlyOwner returns (string memory) {
        return "alumniOf";
    }
}
