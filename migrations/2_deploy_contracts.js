const AlumniOfVC = artifacts.require("AlumniOfVC");
const ZeroCopySink = artifacts.require("ZeroCopySink");
const ZeroCopySource = artifacts.require("ZeroCopySource");

const NebuVC = artifacts.require('NebuVC');

module.exports = async function (deployer, network, accounts) {
  //deployer.deploy(ConvertLib);
  //deployer.link(ConvertLib, MetaCoin);

  await deployer.deploy(ZeroCopySink);
  await deployer.deploy(ZeroCopySource);

  await deployer.link(ZeroCopySource, AlumniOfVC);
  await deployer.link(ZeroCopySink, AlumniOfVC);

  await deployer.deploy(AlumniOfVC,  
    "https://example.edu/issuers/565049", // issuer
    ["https://www.w3.org/2018/credentials/examples/v1", "https://www.w3.org/2018/credentials/examples/v2"],
    "http://example.edu/credentials/1872", // id
    ["AlumniCredential"], // type
    {
      id: "https://example.org/examples/degree.json",
      typeSchema: "JsonSchemaValidator2018"
    }, // schema
    );
  await deployer.deploy(NebuVC);
};
