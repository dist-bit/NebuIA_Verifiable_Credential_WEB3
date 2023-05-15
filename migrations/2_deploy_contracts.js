const AlumniOfVC = artifacts.require("AlumniOfVC");
const DocumentMultiSign = artifacts.require("DocumentMultiSign");
const NebuIA = artifacts.require("NebuIAVC");
const Store = artifacts.require("Store");
const ZeroCopySink = artifacts.require("ZeroCopySink");
const ZeroCopySource = artifacts.require("ZeroCopySource");

const NebuVC = artifacts.require('NebuVC');

module.exports = async function (deployer, network, accounts) {
  //deployer.deploy(ConvertLib);
  //deployer.link(ConvertLib, MetaCoin);

  await deployer.deploy(ZeroCopySink);
  await deployer.deploy(Store);
  await deployer.deploy(ZeroCopySource);

  await deployer.link(ZeroCopySource, AlumniOfVC);
  await deployer.link(ZeroCopySink, AlumniOfVC);

  await deployer.link(ZeroCopySource, DocumentMultiSign);
  await deployer.link(ZeroCopySink, DocumentMultiSign);

  await deployer.link(ZeroCopySource, NebuIA);
  await deployer.link(ZeroCopySink, NebuIA);

  await deployer.link(ZeroCopySource, NebuVC);
  await deployer.link(ZeroCopySink, NebuVC);

  /*
  await deployer.deploy(DocumentMultiSign,
    "https://example.edu/issuers/565049", // issuer
    ["https://www.w3.org/2018/credentials/examples/v1", "https://www.w3.org/2018/credentials/examples/v2"], // context
    "http://example.edu/credentials/1872", // id
    ["VerifiableCredential", "UniversityDegreeCredential"], // type
    "https://example.edu/issuers/14#key-1", // verificationMethod
    {
      id: "https://example.org/examples/degree.json",
      typeSchema: "JsonSchemaValidator2018"
    }, // schema
  );

  await deployer.deploy(AlumniOfVC,
    "https://example.edu/issuers/565049", // issuer
    ["https://www.w3.org/2018/credentials/examples/v1", "https://www.w3.org/2018/credentials/examples/v2"], // context
    "http://example.edu/credentials/1872", // id
    ["VerifiableCredential", "UniversityDegreeCredential"], // type
    "https://example.edu/issuers/14#key-1", // verificationMethod
    {
      id: "https://example.org/examples/degree.json",
      typeSchema: "JsonSchemaValidator2018"
    }, // schema
  );

  

  await deployer.deploy(NebuIA,
    "https://example.edu/issuers/565049", // issuer
    ["https://www.w3.org/2018/credentials/examples/v1", "https://www.w3.org/2018/credentials/examples/v2"], // context
    "http://example.edu/credentials/1872", // id
    ["VerifiableCredential", "UniversityDegreeCredential"], // type
    "https://example.edu/issuers/14#key-1", // verificationMethod
    {
      id: "https://example.org/examples/degree.json",
      typeSchema: "JsonSchemaValidator2018"
    }, // schema
  );

  await deployer.deploy(DocumentMultiSign,
    "https://example.edu/issuers/565049", // issuer
    ["https://www.w3.org/2018/credentials/examples/v1", "https://www.w3.org/2018/credentials/examples/v2"], // context
    "http://example.edu/credentials/1872", // id
    ["VerifiableCredential", "UniversityDegreeCredential"], // type
    "https://example.edu/issuers/14#key-1", // verificationMethod
    {
      id: "https://example.org/examples/degree.json",
      typeSchema: "JsonSchemaValidator2018"
    }, // schema
  ); */

  await deployer.deploy(NebuIA,
    "https://example.edu/issuers/565049", // issuer
    ["https://www.w3.org/2018/credentials/examples/v1", "https://www.w3.org/2018/credentials/examples/v2"], // context
    "http://example.edu/credentials/1872", // id
    ["VerifiableCredential", "UniversityDegreeCredential"], // type
    "https://example.edu/issuers/14#key-1", // verificationMethod
    {
      id: "https://example.org/examples/degree.json",
      typeSchema: "JsonSchemaValidator2018"
    }, // schema
    "QmW6gFG2DPEBzG66yAunLGJRVWBj1d6MWsrjvhJWUfRu1H"
  );

  await deployer.deploy(NebuVC);
  await deployer.deploy(Store);
};
