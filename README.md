## Verifiable Credentials - w3c

  

Bibliografias

Reusable Verifiable Claims using [EIP 712 Signed Typed Data](https://eips.ethereum.org/EIPS/eip-712).

## Abstract

El presente trabajo propone la implementación de credenciales verificables usando el estándar propuesto [VC specification](https://www.w3.org/TR/vc-data-model/#abstract) publicado por W3C Credentials Community Group.

  

Este es un estándar para la verificación agnóstica de credenciales bajo el estándar EIP712 e incluye:

-  **Serialización** y **Deserialización** de estructuras (Claims)

- Verificación de **EIP712**

- Metadata basado en [VC specification](https://www.w3.org/TR/vc-data-model/#abstract)

- Conexión de contrato verificador a implementaciones personalizadas implementado metadata [VC specification](https://www.w3.org/TR/vc-data-model/#abstract).

- Creación/ revocación de credenciales verificables

  

## Motivación

  

EIP 712

  

> La firma de datos es un problema resuelto si lo único que nos importa son las cadenas de bytes. Desafortunadamente, en el mundo real nos preocupamos por los mensajes complejos y significativos. Hashing de datos estructurados no es trivial y los errores dan como resultado la pérdida de las propiedades de seguridad del sistema. Como tal, se aplica el adagio "no hagas tu propia criptografía". En su lugar, se debe utilizar un método estándar bien probado y revisado por pares. Este EIP pretende ser ese estándar. Este EIP tiene como objetivo mejorar la usabilidad de la firma de mensajes fuera de la cadena para su uso en la cadena. Estamos viendo una adopción creciente de la firma de mensajes fuera de la cadena, ya que ahorra gasolina y reduce la cantidad de transacciones en la cadena de bloques. Los mensajes actualmente firmados son una cadena hexadecimal opaca que se muestra al usuario con poco contexto sobre los elementos que componen el mensaje.

  

EIP 1812

> Los reclamos verificables fuera de la cadena reutilizables brindan una parte importante de la integración de contratos inteligentes con los requisitos organizacionales del mundo real, como cumplir con los requisitos regulatorios como KYC, GDPR, reglas de inversores acreditados, etc. ERC-735 y ERC-780 proporcionan métodos para hacer afirmaciones que viven en cadena. Esto es útil para algunos casos de uso particulares, donde alguna afirmación sobre una dirección debe verificarse en cadena. Sin embargo, en la mayoría de los casos es peligroso y, en algunos casos, ilegal (según las normas del RGPD de la UE, por ejemplo) registrar reclamos de identidad que contengan información de identificación personal (PII) en una base de datos pública inmutable como la cadena de bloques Ethereum. Las representaciones y el modelo de datos de credenciales verificables de W3C, así como las especificaciones de mensajes de verificación de uPort, son soluciones fuera de la cadena propuestas. Si bien se basan en estándares de la industria como JSON-LD y JWT, ninguno de ellos es fácil de integrar con el ecosistema Ethereum. EIP-712 presenta un nuevo método para firmar datos de identidad de cadena. Esto proporciona un formato de datos basado en la codificación Solidity ABI que se puede analizar fácilmente en la cadena y una nueva llamada JSON-RPC que es fácilmente compatible con las billeteras Ethereum existentes y los clientes Web3. Este formato permite que los reclamos verificables reutilizables fuera de la cadena se emitan de manera económica a los usuarios, quienes pueden presentarlos cuando sea necesario.

  

La creación de estructuras de datos verificables resulta un problema cuando cada institución o individuo decide crear tipos diferentes de datos, provocando esto la no estandarización de consumo de información. Este trabajo tiene como objetivo la creación de un contrato verificador y estándar ó funciones mínimas para la verificación / consulta y operación de datos asignados a un usuario, de ahi la adopción credenciales verificables.

  

## Conformance and Terminology

  

Esta especificación supone un buen grado de comprensión de [W3C VCs Data Model]https://www.w3.org/TR/vc-data-model).

  
  

The key words "MUST", "MUST NOT", "SHOULD", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [IETF RFC 2119](https://www.ietf.org/rfc/rfc2119).

  

## Especifiación

  

Credencial (claims)

Los claimsse pueden generalizar así:

  

> El Emisor afirma que el Sujeto es algo o tiene algún atributo y valor.

> Las reclamaciones deben ser deterministas, en el sentido de que la

> misma reclamación debe estar firmada varias veces por el mismo

> firmante.

  

Ejemplo de claim (Credencial Universitaria)

  

```js

// sample claim

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
```

  

Cada emisor quiere usar su propia estructura de datos, y permitir que esta sea verificable y presentada ante otras implementaciones de forma natural, es por eso que cada estructura de datos debe ser serializada para su uso en bytes desde contratos inteligentes ajenos.

  

```js
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
```
  

## Estructura propuesta

IEIP712

```js
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

```

IEIP712 Metadata

```js
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
     * @dev protect against replay atack
     */
    function domain() external view returns (EIP712Domain memory);
}
```

## Contrato verificador

```js
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

```

## Normative References

  

  

[W3C-DID]

  

  

Decentralized Identifiers (DIDs) v1.0. W3C. Jul 2020. Working Draft. URL: https://www.w3.org/TR/did-core/

  

  

[RFC2119]

  

  

Key words for use in RFCs to Indicate Requirement Levels. S. Bradner. IETF. March 1997. Best Current Practice. URL: https://tools.ietf.org/html/rfc2119

  

  

[RFC3986]

  

  

Uniform Resource Identifier (URI): Generic Syntax. T. Berners-Lee; R. Fielding; L. Masinter. IETF. JANUARY 2005. Standards Track. URL: https://tools.ietf.org/html/rfc3986