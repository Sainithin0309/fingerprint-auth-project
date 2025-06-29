const hre = require("hardhat");

async function main() {
  const Verifier = await hre.ethers.getContractFactory("Groth16Verifier"); // Use correct contract name
  const verifier = await Verifier.deploy();

  await verifier.waitForDeployment();

  console.log("Verifier contract deployed to:", verifier.target);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
