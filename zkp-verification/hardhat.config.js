require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config(); // To load secrets from .env file
module.exports = {
  solidity: "0.8.19",
  networks: {
    sepolia: {
      url: process.env.SEPOLIA_RPC_URL,
      accounts: [process.env.PRIVATE_KEY]
    }
  }
};
