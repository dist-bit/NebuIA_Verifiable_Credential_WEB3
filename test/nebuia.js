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
    const _credential = await AlumniOfVC.deployed();
    const _vc = await NebuVC.deployed();
    const signer = new ethers.Wallet('911b935b8595ffd4b8a122beef95af027d4a6668eb471ed4231c79179cb5a3eb'); // deployer

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

    const signature = await signer._signTypedData(domain, types, value);

    const encode = await _credential.serializeAlumniOf(value);
    //const decode = await _credential.deserializeAlumniOf(encode);

    // (v, r, s) = digest = signature

    let owner = await _credential.recoverSigner(
      value,
      signature);

    assert.equal(owner, signer.address, "invalid signature");

    const tx = await _vc.createVC(
      _credential.address,
      signer.address,
      encode,
      signature,
      000000, //1662648965, // expiration 000000 for not expiration
    );

    console.log('Gas create VC: ', tx.receipt.gasUsed);

    const credentials = await _vc.getVCFromUser();

    assert.equal(credentials.length, 1, "credential not saved");

    let valid = await _vc.verifyByOwner(
      0,
      signature,
    );

    assert.equal(valid, true, "invalid credential validation by user");

    const revoke = await _vc.revokeVC(
      signer.address,
      _credential.address,
      0,
    );

    console.log('Gas revoke: ', revoke.receipt.gasUsed);


    valid = await _vc.verifyByOwner(
      0,
      signature,
    );

    assert.equal(valid, false, "invalid credential validation by user");

    valid = await _vc.verifyByIssuer(
      signer.address,
      0,
      signature,
    );

    assert.equal(valid, false, "invalid credential validation by issuer");

    const domainVC = await _vc.domain(_credential.address);

    assert.equal(domainVC.name, domain.name, "invalid domain name");
    assert.equal(domainVC.version, domain.version, "invalid domain version");
    assert.equal(domainVC.chainId, domain.chainId, "invalid domain chainId");


    const onwerVC = await _vc.owner(_credential.address);
    assert.equal(onwerVC, signer.address, "invalid domain name");
  });
});