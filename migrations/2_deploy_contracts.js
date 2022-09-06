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

  await deployer.deploy(AlumniOfVC);
  await deployer.deploy(NebuVC);
};
