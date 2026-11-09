// Deploys ThreatRegistry to the configured network and writes the deployed
// address + ABI to backend/contract.json, which the backend reads at runtime.
// The address is never hardcoded in Python: restarting `npx hardhat node`
// resets the chain, so the address changes with every fresh node.

const fs = require("fs");
const path = require("path");
const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();

  console.log("Deploying ThreatRegistry with account:", deployer.address);
  console.log(
    "Account balance:",
    (await hre.ethers.provider.getBalance(deployer.address)).toString()
  );

  const factory = await hre.ethers.getContractFactory("ThreatRegistry");
  const registry = await factory.deploy();
  await registry.waitForDeployment();

  const address = await registry.getAddress();
  const network = await hre.ethers.provider.getNetwork();

  console.log("ThreatRegistry deployed to:", address);
  console.log("Chain id:", network.chainId.toString());

  const artifact = await hre.artifacts.readArtifact("ThreatRegistry");

  const output = {
    address: address,
    chain_id: Number(network.chainId),
    network: hre.network.name,
    deployed_at: new Date().toISOString(),
    abi: artifact.abi,
  };

  const target = path.join(__dirname, "..", "..", "backend", "contract.json");
  fs.writeFileSync(target, JSON.stringify(output, null, 2) + "\n", "utf8");

  console.log("Wrote address + ABI to:", target);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
