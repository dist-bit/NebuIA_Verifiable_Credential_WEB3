const AlumniOfVC = artifacts.require("AlumniOfVC");
const NebuIAVC = artifacts.require("NebuIAVC");
const DocumentMultiSign = artifacts.require("DocumentMultiSign");
const NebuVC = artifacts.require('NebuVC');
const { ethers, utils } = require("ethers");
const { toUtf8Bytes } = require("ethers/lib/utils");

//truffle test --show-events
const VeriableItemNamed = 'VeriableItemNamed';
contract('NebuIAVC', (accounts) => {
  const domain = {
    name: 'NebuIADID',
    version: '1',
    chainId: 1,
    verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC'
  };

  const types = {
    VeriableItemNamed: [
      { name: 'value_', type: 'string' },
      { name: 'valid_', type: 'uint8' },
    ],
    IdOf: [
      { name: 'id_', type: 'string' },
      { name: 'email_', type: VeriableItemNamed },
      { name: 'address_', type: VeriableItemNamed },
      { name: 'phone_', type: VeriableItemNamed },
      { name: 'document_', type: VeriableItemNamed },
      { name: 'face_', type: VeriableItemNamed },
    ]
  };

  it('Test IdOf signature', async () => {
    const _credential = await NebuIAVC.deployed();

    const _vc = await NebuVC.deployed();
    const signer = new ethers.Wallet('0xe27f7317faf6dd425ca5fe16e150bbcb39bde022445758a004f13e28a29e1012'); // deployer
    console.log(_vc.address);

    const value = {
      id_: 'id_sample',
      email_: {
        value_: 'miguel@distbit.io',
        valid_: 1,
      },
      address_: {
        value_: 'Chimalhuacan Edo Mex',
        valid_: 1,
      },
      phone_: {
        value_: '8129099148',
        valid_: 1,
      },
      document_: {
        value_: '32432423',
        valid_: 1,
      },
      face_: {
        value_: 'match and spoofing',
        valid_: 1,
      },
    };

    console.log(await _credential.viewVersion());

    const signature = await signer._signTypedData(domain, types, value);
    const encode = await _credential.serializeIdOf(value);
    //const decode = await _credential.deserializeIdOf(encode);

    //console.log(encode);
    // console.log(await _credential.recoverSignerFromBytes(encode, signature));

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
      encode, // body as bytes
    );

    assert.equal(valid, true, "invalid credential validation by user");

    /*const revoke = await _vc.revokeVC(
      signer.address,
      _credential.address,
      0,
    );

    console.log('Gas revoke: ', revoke.receipt.gasUsed);


    valid = await _vc.verifyByOwner(
      0,
      encode,
    );

    assert.equal(valid, false, "invalid credential validation by user");

    valid = await _vc.verifyByIssuer(
      signer.address,
      0,
      encode,
    );

    assert.equal(valid, false, "invalid credential validation by issuer");

    const domainVC = await _vc.domain(_credential.address);

    assert.equal(domainVC.name, domain.name, "invalid domain name");
    assert.equal(domainVC.version, domain.version, "invalid domain version");
    assert.equal(domainVC.chainId, domain.chainId, "invalid domain chainId");


    const onwerVC = await _vc.owner(_credential.address);
    assert.equal(onwerVC, signer.address, "invalid domain name"); */
  });

}
)
/*
contract('AlumniOf', (accounts) => {
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

  it('Test AlumniOf signature', async () => {
    const _credential = await AlumniOfVC.deployed();
    const _vc = await NebuVC.deployed();
    const signer = new ethers.Wallet('0x18efd23c4d4de43791353abca8d20533d26ae91823f34317119fc768c95398b7'); // deployer

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
*/
/*
contract('DocumentMultiSign', (accounts) => {
  const fs = require('fs');
  const documentPDF = fs.readFileSync('./cyberpunk.pdf');
  const hashDocument = ethers.utils.keccak256(new Uint8Array(documentPDF.buffer));

  const domain = {
    name: 'DocumentMultiSign',
    version: '1',
    chainId: 1,
    verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC'
  };

  const types = {
    Signatories: [
      { name: 'signatory', type: 'address' },
      { name: 'signature', type: 'bytes' },
    ],
    Document: [
      { name: 'id', type: 'string' },
      { name: 'hash', type: 'bytes32' },
      { name: 'signatories', type: 'Signatories[]' },
    ]
  };

  const documentSignatureTypes = {
    DocumentToSign: [
      { name: 'hash', type: 'bytes32' },
    ]
  }

  const valueHash = {
    hash: hashDocument
  };

  it('Test Document signature', async () => {

    async function signData(wallet) {
      const signature = await wallet._signTypedData(domain, documentSignatureTypes, valueHash);
      return signature;
    }

    const _credential = await DocumentMultiSign.deployed();
    //const _vc = await NebuVC.deployed();
    const signer = new ethers.Wallet('911b935b8595ffd4b8a122beef95af027d4a6668eb471ed4231c79179cb5a3eb'); // deployer

    const userToSign1 = new ethers.Wallet('7bc2ec8c8b65b15ad8ece66548e5aa63fce23fbe54219ca9ee4e96c039ce4edb');
    const userToSign2 = new ethers.Wallet('0bdda1526ad0f3d93c8a78f313a4b2aa88d47f36a0bd75e47b9e91e3cd245202');

    const sign1 = await signData(userToSign1);
    const sign2 = await signData(userToSign2);

    const signatories = [
      {
        signatory: userToSign1.address,
        signature: sign1
      },
      {
        signatory: userToSign2.address,
        signature: sign2
      }
    ];

    const value = {
      id: 'id_sample',
      hash: hashDocument,
      signatories,
    };

    const signature = await signer._signTypedData(domain, types, value);


    let owner = await _credential.recoverSigner(
      value,
      signature);

    assert.equal(owner, signer.address, "invalid signature");

    let hashOwner1 = await _credential.recoverSignerHash(
      valueHash,
      sign1);

    assert.equal(hashOwner1, userToSign1.address, "invalid signature 1");

    let hashOwner2 = await _credential.recoverSignerHash(
      valueHash,
      sign2);

    assert.equal(hashOwner2, userToSign2.address, "invalid signature 2");
  });
});

*/