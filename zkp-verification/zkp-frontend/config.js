// PEUAP-W3 Contract Configuration — Sepolia Testnet
export const CONTRACTS = {
  AuthenticatorContract: {
    address: "0x720b8EC75b7551b8663a2C8906eBB9D7625d49b7",
    abi: [
      {
        "inputs": [
          { "internalType": "uint256[2]", "name": "a", "type": "uint256[2]" },
          { "internalType": "uint256[2][2]", "name": "b", "type": "uint256[2][2]" },
          { "internalType": "uint256[2]", "name": "c", "type": "uint256[2]" },
          { "internalType": "uint256[6]", "name": "publicSignals", "type": "uint256[6]" }
        ],
        "name": "authenticate",
        "outputs": [{ "internalType": "bool", "name": "", "type": "bool" }],
        "stateMutability": "nonpayable",
        "type": "function"
      },
      {
        "inputs": [{ "internalType": "uint256", "name": "nonce", "type": "uint256" }],
        "name": "isNonceUsed",
        "outputs": [{ "internalType": "bool", "name": "", "type": "bool" }],
        "stateMutability": "view",
        "type": "function"
      },
      {
        "anonymous": false,
        "inputs": [
          { "indexed": true, "internalType": "address", "name": "caller", "type": "address" },
          { "indexed": false, "internalType": "uint256", "name": "commitment", "type": "uint256" },
          { "indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256" }
        ],
        "name": "AuthenticationSuccessful",
        "type": "event"
      }
    ]
  },
  BiometricVerifier: {
    address: "0x6E2929Ab6a30FA06b87bFE45306a940e6ec3578e"
  },
  IdentifierStorage: {
    address: "0xF4Cb5Ebe60063BF67E3ADdf14e2a81034a58f716"
  },
  AuditTrail: {
    address: "0xCcFb036b694fFAde95177126181f9a8C0887e246"
  }
};

export const NETWORK = {
  chainId: "0xaa36a7", // Sepolia
  chainName: "Sepolia Testnet",
  rpcUrls: ["https://rpc.sepolia.org"],
  blockExplorerUrls: ["https://sepolia.etherscan.io"]
};

export const BACKEND_URL = "https://fingerprint-auth-using-zkp.onrender.com";
export const RELAY_URL = "https://peuap-relay-coordinator.onrender.com";
