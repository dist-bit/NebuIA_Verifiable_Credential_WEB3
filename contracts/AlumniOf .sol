// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

pragma experimental ABIEncoderV2;

import "./libs/ZeroCopySink.sol";
import "./libs/ZeroCopySource.sol";

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
}

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor() {
        _transferOwnership(_msgSender());
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions anymore. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby removing any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(
            newOwner != address(0),
            "Ownable: new owner is the zero address"
        );
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

/**
 * @dev String operations.
 */
library Strings {
    bytes16 private constant _HEX_SYMBOLS = "0123456789abcdef";

    /**
     * @dev Converts a `uint256` to its ASCII `string` decimal representation.
     */
    function toString(uint256 value) internal pure returns (string memory) {
        // Inspired by OraclizeAPI's implementation - MIT licence
        // https://github.com/oraclize/ethereum-api/blob/b42146b063c7d6ee1358846c198246239e9360e8/oraclizeAPI_0.4.25.sol

        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.
     */
    function toHexString(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0x00";
        }
        uint256 temp = value;
        uint256 length = 0;
        while (temp != 0) {
            length++;
            temp >>= 8;
        }
        return toHexString(value, length);
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.
     */
    function toHexString(uint256 value, uint256 length)
        internal
        pure
        returns (string memory)
    {
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = _HEX_SYMBOLS[value & 0xf];
            value >>= 4;
        }
        require(value == 0, "Strings: hex length insufficient");
        return string(buffer);
    }
}

library Address {
    /**
     * @dev Returns true if `account` is a contract.
     *
     * [IMPORTANT]
     * ====
     * It is unsafe to assume that an address for which this function returns
     * false is an externally-owned account (EOA) and not a contract.
     *
     * Among others, `isContract` will return false for the following
     * types of addresses:
     *
     *  - an externally-owned account
     *  - a contract in construction
     *  - an address where a contract will be created
     *  - an address where a contract lived, but was destroyed
     * ====
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize, which returns 0 for contracts in
        // construction, since the code is only stored at the end of the
        // constructor execution.

        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
}

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
    function context() external view returns (string memory);

    /**
     * @dev Specify e identifier for the credenttial.
     */
    function id() external view returns (string memory);

    /**
     * @dev The credential types which declare at datao expect in this credential.
     */
    function typeCredential() external view returns (string memory);

    /**
     * @dev https://www.w3.org/TR/vc-data-model/#data-schemas
     */
    function schema() external view returns (Schema memory);

    /**
     * @dev protect against replay atack
     */
    function domain() external view returns (EIP712Domain memory);
}

contract EIP712 is IEIP721, IEIP721Metadata {
    // Credential issuer
    string private _issuer;

    // Credential context
    string private _context;

    // Credential identifier
    string private _id;

    // Credential type
    string private _type;

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
        string memory context_,
        string memory id_,
        string memory type_,
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
    function context() public view virtual override returns (string memory) {
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
        returns (string memory)
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

        //bytes memory serialize = serializeAlumniOf(_alumniOf);
        //AlumniOf memory alumniOf = deserializeAlumniOf(serialize);

        // bytes memory serialize = serializeIdentity(_identity);
        //NebuIA_Identity memory identity = deserializeIdentity(serialize);

        //require(verify(identity, v, r, s) == msg.sender, "invalid signature");

        return verify(_alumniOf, v, r, s);
        //return alumniOf;
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
            bytes memory valueBytes;
            bytes memory subjectsLenBytes;
            bytes memory subjectsBytes;
            (valueBytes, subjectsLenBytes, subjectsBytes) = serializeUniversity(
                alumn.universities[i]
            );

            bytes memory result = abi.encodePacked(
                valueBytes,
                subjectsLenBytes,
                subjectsBytes
            );

            universitiesBytes = abi.encodePacked(universitiesBytes, result);
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
        returns (
            bytes memory,
            bytes memory,
            bytes memory
        )
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

        return (valueBytes, subjectsLenBytes, subjectsBytes);
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

    /*function recoverSignerFromBytes(
        bytes memory _identity,
        bytes memory _signature
    ) public view virtual override returns (address) {
        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = splitSignature(_signature);
        NebuIA_Identity memory identity = deserializeIdentity(_identity);
        return verify(identity, v, r, s);
    }

    function serializeIdentity(NebuIA_Identity memory identity)
        public
        pure
        returns (bytes memory)
    {
        bytes memory nameBytes;
        bytes memory walletBytes;

        (nameBytes, walletBytes) = serializeIssuer(identity.from);

        bytes memory titleBytes = ZeroCopySink.WriteVarBytes(
            bytes(identity.title)
        );

        // serialize list string
        bytes memory contentsLenBytes = ZeroCopySink.WriteUint255(
            identity.contents.length
        );
        bytes memory contentsBytes = new bytes(0);
        for (uint256 i = 0; i < identity.contents.length; i++) {
            contentsBytes = abi.encodePacked(
                contentsBytes,
                ZeroCopySink.WriteVarBytes(bytes(identity.contents[i]))
            );
        }

        bytes memory result = abi.encodePacked(
            nameBytes,
            walletBytes,
            titleBytes
        );
        return abi.encodePacked(result, contentsLenBytes, contentsBytes);
    }

    function deserializeIdentity(bytes memory data)
        public
        pure
        returns (NebuIA_Identity memory)
    {
        (Issuer memory issuer, uint256 offset) = deserializeIssuer(data);

        //emit Test(offset);

        bytes memory title;
        (title, offset) = ZeroCopySource.NextVarBytes(data, offset);

        uint256 contentsLen;
        (contentsLen, offset) = ZeroCopySource.NextUint255(data, offset);
        string[] memory contents = new string[](contentsLen);

        for (uint256 i = 0; i < contentsLen; i++) {
            bytes memory ctrl;
            (ctrl, offset) = ZeroCopySource.NextVarBytes(data, offset);
            contents[i] = string(ctrl);
        }

        return NebuIA_Identity(issuer, string(title), contents);
    }

    function serializeIssuer(Issuer memory service)
        public
        pure
        returns (bytes memory, bytes memory)
    {
        bytes memory nameBytes = ZeroCopySink.WriteVarBytes(
            bytes(service.name)
        );
        bytes memory walletBytes = ZeroCopySink.WriteVarBytes(
            abi.encodePacked((service.wallet))
        );
        //bytes memory result = abi.encodePacked(nameBytes, serviceBytes);
        return (nameBytes, walletBytes);
    }

    function deserializeIssuer(bytes memory data)
        public
        pure
        returns (Issuer memory, uint256)
    {
        (bytes memory name, uint256 offset) = ZeroCopySource.NextVarBytes(
            data,
            0
        );

        bytes memory source = new bytes(0);
        (source, offset) = ZeroCopySource.NextVarBytes(data, offset);

        address addr;
        assembly {
            addr := mload(add(source, 0x14))
        }

        return (Issuer(string(name), addr), offset);
    }

    function sign(NebuIA_Identity memory identity)
        internal
        view
        returns (bytes32)
    {
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hash(identity))
        );

        return digest;
    } */
}

/* ERC721,*/
contract AlumniOfVC is EIP712, Ownable {
    constructor()
        EIP712(
            "https://example.edu/issuers/565049", // issuer
            "https://www.w3.org/2018/credentials/examples/v1", // context
            "http://example.edu/credentials/1872", //id
            "AlumniCredential", // type
            Schema(
                "https://example.org/examples/degree.json",
                "JsonSchemaValidator2018"
            ), // schema
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
