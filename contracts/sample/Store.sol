// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

pragma experimental ABIEncoderV2;

contract _Store {
    /**
     * @dev map hashes to hashes
     */
    mapping(address => Hash[]) private stores_;

    struct Hash {
        uint256 index;
        string hash;
    }

    /**
     * @dev register new hash
     */
    function createHash(string memory _signature, address _to, uint256 _index) public {
        Hash memory store = Hash(_index, _signature);
        stores_[_to].push(store);
    }

    /**
     * @dev get hash
     */
    function getHash() public
        view
        returns (Hash[] memory) {
        Hash[] memory store = stores_[msg.sender];
        return store;
    }
}

/* ERC721,*/
contract Store is _Store {
    constructor() {}
}
