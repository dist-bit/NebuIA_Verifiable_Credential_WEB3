// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

pragma experimental ABIEncoderV2;

interface IEIP721 {
    function recoverSignerFromBytes(
        bytes memory _identity,
        bytes memory _signature
    ) external view returns (address);
}

contract NebuVC {
    // sample
    struct VerifiableCredential {
        string creator;
        bytes signature;
        uint256 issuanceDate;
        uint256 expirationDate;
    }

    function check(
        address service,
        bytes memory _identity,
        bytes memory _signature
    ) public view returns (address) {
        IEIP721 token = IEIP721(service);
        return token.recoverSignerFromBytes(_identity, _signature);
    }
}
