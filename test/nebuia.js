const AlumniOfVC = artifacts.require("AlumniOfVC");
const NebuVC = artifacts.require('NebuVC');
const { ethers } = require("ethers");

const domain = {
  name: 'AlumniOf Verifiable Credential',
  version: '1',
  chainId: 1,
  verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC'
};

const types = {
  University: [
    { name: 'value', type: 'string' },
    { name: 'subjects', type: 'string[]' },
  ],
  AlumniOf: [
    { name: 'id', type: 'string' },
    { name: 'universities', type: 'University[]' },
  ]
};

//truffle test --show-events

contract('AlumniOf', (accounts) => {
  it('Test AlumniOf signature', async () => {
    const _id_nebuia = await AlumniOfVC.deployed();
    const _vc = await NebuVC.deployed();
    const signer = new ethers.Wallet('f4951e7e4a65b7c39576eaf474097bc376b5e3c825856dfd26bb9ec6307bc2db');

    // sha512 checksum from ip files
    const subjects = [
      'spanish',
      'english'
    ];

    const value = {
      id: 'id_sample',
      universities: [
        {
          value: 'UAEM',
          subjects: subjects,
        }
      ],
    };

    const bytesEIP = '0x064e656275494114deadbeefdeadbeefdeadbeefdeadbeefdeadbeef1343657274696669636174696f6e207469746c650200000000000000000000000000000000000000000000000000000000000000803231306161653663386639633763346232336565326364303437316337356163373632313037363133366439376631383761393538306139336562313831376333643762623966386462623734323665333366376436306632376237356564653836376666383362333330316138613562323439663932353931633838656365803231306161653663386639633763346232336565326364303437316337356163373632313037363133366439376631383761393538306139336562313831376333643762623966386462623734323665333366376436306632376237356564653836376666383362333330316138613562323439663932353931633838656365';


    const signature = await signer._signTypedData(domain, types, value);

    //console.log(_id_nebuia.address);
    //console.log(_vc.address);
    // (v, r, s) = digest = siganture

    /*let owner = await _vc.check(
      _id_nebuia.address,
      bytesEIP,
      signature); */

      let owner = await _id_nebuia.recoverSigner(
        value,
        signature);

        console.log(owner.universities);

   // assert.equal(owner, signer.address, "invalid signature");


    // assert.equal(await  _id_nebuia.symbol(), 'ID', "invalid symbol");

    /*let balance = await  _id_nebuia.balanceOf(signer.address);
    assert.equal(balance.toNumber(), 0, "invalid balance");

    await  _id_nebuia.mint(signer.address,
      'Certification title',
      contents);

    balance = await  _id_nebuia.balanceOf(signer.address);
    assert.equal(balance.toNumber(), 1, "invalid balance");

    let digest = await  _id_nebuia.generateDigest(
      'Certification title',
      contents);

    let tokenOwner = await  _id_nebuia.ownerOf(digest);
    assert.equal(tokenOwner, signer.address, "invalid owner"); */
  });
});