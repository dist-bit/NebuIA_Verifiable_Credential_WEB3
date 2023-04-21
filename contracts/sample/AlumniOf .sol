// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

pragma experimental ABIEncoderV2;

import "../libs/ZeroCopySink.sol";
import "../libs/ZeroCopySource.sol";
import "../EIP/IEIP712.sol";
import "../utils/Ownable.sol";

contract EIP712 is IEIP721, IEIP721Metadata {
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
    struct University {
        string value; // university name
        string[] subjects; // subjects of student in university
    }

    // Credential subject - can be named differently
    struct AlumniOf {
        string id; // identifier about the only subject of the credential
        // assertion about the only subject of the credential
        // TODO - Define credential structure
        University[] universities;
    }

    // EIP Domain
    bytes32 constant EIP712DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    bytes32 constant UNIVERSITY_TYPEHASH =
        keccak256("University(string value,string[] subjects)");

    bytes32 constant ALUMN_TYPEHASH =
        keccak256(
            "AlumniOf(string id,University[] universities)University(string value,string[] subjects)"
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

    // hash array of strings
    function hash(string[] memory items) internal pure returns (bytes32) {
        bytes32[] memory _array = new bytes32[](items.length);
        for (uint256 i = 0; i < items.length; ++i) {
            _array[i] = keccak256(bytes(items[i]));
        }

        return keccak256(abi.encodePacked(_array));
    }

    // hash array of universities
    function hash(University[] memory items) internal pure returns (bytes32) {
        bytes32[] memory _array = new bytes32[](items.length);
        for (uint256 i = 0; i < items.length; ++i) {
            _array[i] = hash(items[i]);
        }

        return keccak256(abi.encodePacked(_array));
    }

    // hash single university item
    function hash(University memory university)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encode(
                    UNIVERSITY_TYPEHASH,
                    keccak256(bytes(university.value)),
                    hash(university.subjects)
                )
            );
    }

    function hash(AlumniOf memory alumn) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    ALUMN_TYPEHASH,
                    keccak256(bytes(alumn.id)),
                    hash(alumn.universities)
                )
            );
    }

    function verify(
        AlumniOf memory identity,
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
        AlumniOf memory alumniOf = deserializeAlumniOf(data_);
        return verify(alumniOf, v, r, s);
    }

    function recoverSigner(AlumniOf memory _alumniOf, bytes memory _signature)
        public
        view
        returns (address)
    {
        uint8 v;
        bytes32 r;
        bytes32 s;

        (v, r, s) = splitSignature(_signature);

        return verify(_alumniOf, v, r, s);
    }

    function serializeAlumniOf(AlumniOf memory alumn)
        public
        pure
        returns (bytes memory)
    {
        bytes memory idBytes = ZeroCopySink.WriteVarBytes(bytes(alumn.id));

        // serialize list of universities
        bytes memory universitiesLenBytes = ZeroCopySink.WriteUint255(
            alumn.universities.length
        );
        bytes memory universitiesBytes = new bytes(0);
        for (uint256 i = 0; i < alumn.universities.length; i++) {
            bytes memory encodeUniversity = serializeUniversity(
                alumn.universities[i]
            );

            universitiesBytes = abi.encodePacked(
                universitiesBytes,
                encodeUniversity
            );
        }

        return
            abi.encodePacked(idBytes, universitiesLenBytes, universitiesBytes);
    }

    function deserializeAlumniOf(bytes memory data)
        public
        pure
        returns (AlumniOf memory)
    {
        (bytes memory idData, uint256 offset) = ZeroCopySource.NextVarBytes(
            data,
            0
        );

        uint256 universitiesLen;
        (universitiesLen, offset) = ZeroCopySource.NextUint255(data, offset);
        University[] memory universities = new University[](universitiesLen);

        for (uint256 i = 0; i < universitiesLen; i++) {
            University memory university;
            (university, offset) = deserializeUniversity(data, offset);
            universities[i] = university;
        }

        return AlumniOf(string(idData), universities);
    }

    function serializeUniversity(University memory university)
        private
        pure
        returns (bytes memory)
    {
        bytes memory valueBytes = ZeroCopySink.WriteVarBytes(
            bytes(university.value)
        );
        // serialize list string
        bytes memory subjectsLenBytes = ZeroCopySink.WriteUint255(
            university.subjects.length
        );
        bytes memory subjectsBytes = new bytes(0);
        for (uint256 i = 0; i < university.subjects.length; i++) {
            subjectsBytes = abi.encodePacked(
                subjectsBytes,
                ZeroCopySink.WriteVarBytes(bytes(university.subjects[i]))
            );
        }

        return abi.encodePacked(valueBytes, subjectsLenBytes, subjectsBytes);
    }

    function deserializeUniversity(bytes memory data, uint256 offset)
        private
        pure
        returns (University memory, uint256)
    {
        bytes memory value;
        (value, offset) = ZeroCopySource.NextVarBytes(data, offset);

        uint256 subjectsLen;
        (subjectsLen, offset) = ZeroCopySource.NextUint255(data, offset);
        string[] memory subjects = new string[](subjectsLen);

        for (uint256 i = 0; i < subjectsLen; i++) {
            bytes memory ctrl;
            (ctrl, offset) = ZeroCopySource.NextVarBytes(data, offset);
            subjects[i] = string(ctrl);
        }

        return (University(string(value), subjects), offset);
    }
}

/* ERC721,*/
contract AlumniOfVC is EIP712, Ownable {
    constructor(
        string memory issuer_,
        string[] memory context_,
        string memory id_,
        string[] memory type_,
        string memory verificationMethod_,
        Schema memory schema_
    )
        EIP712(
            issuer_,
            context_,
            id_,
            type_,
            verificationMethod_,
            schema_,
            // domain
            0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC, // contract verifier
            "AlumniOf Verifiable Credential", // name credential
            "1", // version
            1 // chain id
        )
    {}

    function viewVersion() public view onlyOwner returns (string memory) {
        return "alumniOf";
    }
}
