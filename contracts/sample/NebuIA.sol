// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

pragma experimental ABIEncoderV2;

import "../libs/ZeroCopySink.sol";
import "../libs/ZeroCopySource.sol";
import "../EIP/IEIP712.sol";
import "../utils/Ownable.sol";

contract _NebuIADID is IEIP721, IEIP721Metadata {
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

    // Credential logo
    string private _logo;

    struct VeriableItemNamed {
        string value_;
        uint8 valid_;
    }

    /*struct FaceSimilarityQuantity {
        uint8 value_;
        uint8 valid_;
    }*/

    // Credential subject - can be named differently
    struct IdOf {
        string id_;
        VeriableItemNamed email_;
        VeriableItemNamed address_;
        VeriableItemNamed phone_;
        VeriableItemNamed document_;
        VeriableItemNamed face_;
    }

    // EIP Domain
    bytes32 constant EIP712DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    bytes32 constant VERIFIABLEITEM_TYPEHASH =
        keccak256("VeriableItemNamed(string value_,uint8 valid_)");

    bytes32 constant ID_TYPEHASH =
        keccak256(
            "IdOf(string id_,VeriableItemNamed email_,VeriableItemNamed address_,VeriableItemNamed phone_,VeriableItemNamed document_,VeriableItemNamed face_)VeriableItemNamed(string value_,uint8 valid_)"
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
        uint256 chain_,
        string memory logo_
    ) {
        _issuer = issuer_;
        _context = context_;
        _id = id_;
        _type = type_;
        _verificationMethod = verificationMethod_;
        _schema = schema_;
        _logo = logo_;

        _domain = EIP712Domain({
            name: name_,
            version: version_,
            chainId: chain_,
            verifyingContract: verifyingContract_
        });

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

    /**
     * @dev optional logo.
     */
    function logo() public view virtual returns (string memory) {
        return _logo;
    }

    function hash(
        EIP712Domain memory eip712Domain
    ) internal pure returns (bytes32) {
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

    function hash(VeriableItemNamed memory _item) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    VERIFIABLEITEM_TYPEHASH,
                    keccak256(bytes(_item.value_)),
                    _item.valid_
                )
            );
    }

    function hash(IdOf memory id_) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    ID_TYPEHASH,
                    keccak256(bytes(id_.id_)),
                    hash(id_.email_),
                    hash(id_.address_),
                    hash(id_.phone_),
                    hash(id_.document_),
                    hash(id_.face_)
                )
            );
    }

    function verify(
        IdOf memory identity,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal view returns (address) {
        // Note: we need to use `encodePacked` here instead of `encode`.
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hash(identity))
        );

        return ecrecover(digest, v, r, s);
    }

    // Signature methods

    function splitSignature(
        bytes memory sig
    ) internal pure returns (uint8, bytes32, bytes32) {
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

    function splitSignatureFromBytes(
        bytes memory signature_
    ) public pure override returns (uint8, bytes32, bytes32) {
        return splitSignature(signature_);
    }

    function recoverSignerFromBytes(
        bytes memory data_,
        bytes memory signature_
    ) public view override returns (address) {
        uint8 v;
        bytes32 r;
        bytes32 s;

        (v, r, s) = splitSignature(signature_);
        IdOf memory idOf = deserializeIdOf(data_);
        return verify(idOf, v, r, s);
    }

    function recoverSigner(
        IdOf memory _idOf,
        bytes memory _signature
    ) public view returns (address) {
        uint8 v;
        bytes32 r;
        bytes32 s;

        (v, r, s) = splitSignature(_signature);

        return verify(_idOf, v, r, s);
    }

    function serializeIdOf(IdOf memory id_) public pure returns (bytes memory) {
        bytes memory idBytes = ZeroCopySink.WriteVarBytes(bytes(id_.id_));

        bytes memory emailBytes = new bytes(0);
        bytes memory encodeEmail = serializeVeriableItem(id_.email_);
        emailBytes = abi.encodePacked(emailBytes, encodeEmail);

        bytes memory addressBytes = new bytes(0);
        bytes memory encodeAddress = serializeVeriableItem(id_.address_);
        addressBytes = abi.encodePacked(addressBytes, encodeAddress);

        bytes memory phoneBytes = new bytes(0);
        bytes memory encodePhoneNumber = serializeVeriableItem(id_.phone_);
        phoneBytes = abi.encodePacked(phoneBytes, encodePhoneNumber);

        bytes memory documentBytes = new bytes(0);
        bytes memory encodeDocument = serializeVeriableItem(id_.document_);
        documentBytes = abi.encodePacked(documentBytes, encodeDocument);

        bytes memory faceBytes = new bytes(0);
        bytes memory encodeFace = serializeVeriableItem(
            id_.face_
        );
        faceBytes = abi.encodePacked(faceBytes, encodeFace);

        return
            abi.encodePacked(
                idBytes,
                emailBytes,
                addressBytes,
                phoneBytes,
                documentBytes,
                faceBytes
            );
    }

    function deserializeIdOf(
        bytes memory data_
    ) public pure returns (IdOf memory) {
        (bytes memory idData, uint256 offset) = ZeroCopySource.NextVarBytes(
            data_,
            0
        );

        VeriableItemNamed memory email;
        (email, offset) = deserializeVeriableItem(data_, offset);

        VeriableItemNamed memory addr;
        (addr, offset) = deserializeVeriableItem(data_, offset);

        VeriableItemNamed memory phone;
        (phone, offset) = deserializeVeriableItem(data_, offset);

        VeriableItemNamed memory document;
        (document, offset) = deserializeVeriableItem(data_, offset);

        VeriableItemNamed memory face;
        (face, offset) = deserializeVeriableItem(data_, offset);

        return IdOf(string(idData), email, addr, phone, document, face);
    }

    function serializeVeriableItem(
        VeriableItemNamed memory _item
    ) private pure returns (bytes memory) {
        bytes memory valueBytes = ZeroCopySink.WriteVarBytes(
            bytes(_item.value_)
        );

        bytes memory validBytes = ZeroCopySink.WriteUint8(_item.valid_);

        return abi.encodePacked(valueBytes, validBytes);
    }

    function deserializeVeriableItem(
        bytes memory data,
        uint256 offset
    ) private pure returns (VeriableItemNamed memory, uint256) {
        bytes memory value;
        (value, offset) = ZeroCopySource.NextVarBytes(data, offset);

        uint8 valid;
        (valid, offset) = ZeroCopySource.NextUint8(data, offset);

        return (VeriableItemNamed(string(value), valid), offset);
    }
}

/* */
contract NebuIAVC is _NebuIADID, Ownable {
    constructor(
        string memory issuer_,
        string[] memory context_,
        string memory id_,
        string[] memory type_,
        string memory verificationMethod_,
        Schema memory schema_,
        string memory logo_
    )
        _NebuIADID(
            issuer_,
            context_,
            id_,
            type_,
            verificationMethod_,
            schema_,
            // domain
            0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC, // contract verifier
            "NebuIADID", // name credential
            "1", // version
            1, // chain id
            logo_
        )
    {}

    function viewVersion() public view onlyOwner returns (string memory) {
        return "nebuiIA-DID";
    }
}
