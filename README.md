# PEUAP-W3 — Privacy-Enhanced & User-Centric Authentication Protocol for Web 3.0

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Render-blue)](https://fingerprint-auth-using-zkp.onrender.com)
[![Sepolia](https://img.shields.io/badge/Contracts-Sepolia%20Testnet-purple)](https://sepolia.etherscan.io/address/0x720b8EC75b7551b8663a2C8906eBB9D7625d49b7)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![PhD Research](https://img.shields.io/badge/PhD-Alliance%20University%20Bengaluru-orange)](https://alliance.edu.in)

> **PhD Research Project** — Alliance School of Advanced Computing, Alliance University, Bengaluru  
> **Candidate:** Adarsh S V Nair | **Supervisor:** Prof. Rathnakar Achary | **Year:** 2026

---

## What Is PEUAP-W3?

PEUAP-W3 is the first formally verified, biometric zero-knowledge authentication framework for Web 3.0 that simultaneously achieves:

- **Biometric authentication** — fingerprint credential binding via WebAuthn FIDO2
- **Zero-knowledge privacy** — Groth16 ZKP proves identity without revealing biometric data
- **Liveness detection** — SpO₂ range proof encoded in the ZKP circuit (no spoofing with replicas)
- **Threshold accountability** — k-of-n Shamir Secret Sharing across relay nodes for governed de-anonymisation
- **W3C SSI compliance** — DID Core v1.0, VC Data Model 2.0, Ed25519Signature2020
- **GDPR-by-architecture** — cryptographic erasure, Bitstring Status List revocation
- **Behavioural AI security** — Isolation Forest anomaly detection (C5)
- **Formal verification** — ProVerif 2.05 + Scyther under Dolev-Yao adversary model

### Security Property Comparison

| Property | PEUAP-W3 | Wallet Login | Web3Auth | zkLogin | FIDO2 |
|---|---|---|---|---|---|
| Biometric authentication | ✅ | ❌ | ❌ | ❌ | ✅ |
| Zero-knowledge privacy | ✅ | ❌ | ❌ | ✅ | ❌ |
| SpO₂ liveness detection | ✅ | ❌ | ❌ | ❌ | ❌ |
| Threshold accountability | ✅ | ❌ | ❌ | ❌ | ❌ |
| On-chain verifiability | ✅ | ✅ | ❌ | ✅ | ❌ |
| W3C VC 2.0 compliant | ✅ | ❌ | ❌ | ❌ | ❌ |
| GDPR by architecture | ✅ | ❌ | ❌ | ✅ | ❌ |
| Formally verified | ✅ | ❌ | ❌ | ❌ | ❌ |
| Behavioural AI gate | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Score** | **9/9** | **2/9** | **0/9** | **4/9** | **2/9** |

---

## Five-Layer Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1 — Hardware Authenticator (STM32F407 + FPC1020)         │
│  Fingerprint capture → SpO₂ liveness → SE050 ECC key → BLE 6.0 │
├─────────────────────────────────────────────────────────────────┤
│  Layer 2 — Browser Extension (Chrome, Manifest V3)              │
│  WebAuthn → OTP input → ZKP fetch → HMAC-signed postMessage     │
├─────────────────────────────────────────────────────────────────┤
│  Layer 3 — Modified Onion Routing + Shamir SSS                  │
│  3 relay nodes (k=2, n=3) → threshold de-anonymisation          │
├─────────────────────────────────────────────────────────────────┤
│  Layer 4 — Web3 dApp + Smart Contracts (Sepolia)                │
│  BiometricVerifier + AuthenticatorContract + AuditTrail + IdentifierStorage │
├─────────────────────────────────────────────────────────────────┤
│  Layer 5 — W3C SSI / DID Layer                                  │
│  did:key + Ed25519Signature2020 + VC DM 2.0 + Bitstring Revocation │
└─────────────────────────────────────────────────────────────────┘
```

---

## Live Deployment

| Service | URL |
|---|---|
| **Flask Backend** | https://fingerprint-auth-using-zkp.onrender.com |
| **React dApp** | https://peuap-w3-dapp1.onrender.com |
| **Relay Coordinator** | https://peuap-relay-coordinator.onrender.com |
| **Relay Node 1** | https://peuap-relay-node1.onrender.com |
| **Relay Node 2** | https://peuap-relay-node2.onrender.com |
| **Relay Node 3** | https://peuap-relay-node3.onrender.com |

### Deployed Smart Contracts (Ethereum Sepolia)

| Contract | Address |
|---|---|
| **BiometricVerifier** | `0x6E2929Ab6a30FA06b87bFE45306a940e6ec3578e` |
| **IdentifierStorage** | `0xF4Cb5Ebe60063BF67E3ADdf14e2a81034a58f716` |
| **AuditTrail** | `0xCcFb036b694fFAde95177126181f9a8C0887e246` |
| **AuthenticatorContract** | `0x720b8EC75b7551b8663a2C8906eBB9D7625d49b7` |

---

## Repository Structure

```
fingerprint-auth-project/
│
├── app.py                          # Flask backend (main entry point)
├── ai_anomaly.py                   # C5: Isolation Forest anomaly detection
├── ssi_did.py                      # C3: W3C VC 2.0 + did:key + Ed25519
├── requirements.txt
├── build.sh                        # Render build script
├── Procfile / render.yaml
│
├── biometric_auth.circom           # C1: ZKP circuit (1,579 R1CS constraints)
├── biometric_auth_final.zkey       # Trusted setup (contribution: Adarsh S V Nair)
├── biometric_auth_verification_key.json
├── biometric_auth_js/              # Compiled WASM + witness generator
│   ├── biometric_auth.wasm
│   └── generate_witness.js
│
├── BiometricVerifier.sol           # Auto-generated Groth16 verifier
│
├── templates/
│   ├── index.html                  # Registration page
│   └── validate.html               # Fingerprint validation + OTP
├── static/
│
├── fingerprint_zkp_extension/      # L2: Chrome browser extension
│   ├── manifest.json
│   ├── popup.html / popup.js
│   ├── background.js
│   └── content.js
│
├── relay-nodes/                    # L3: Shamir relay nodes
│   ├── coordinator.js
│   ├── node1/server.js
│   ├── node2/server.js
│   └── node3/server.js
│
├── zkp-verification/               # L4: Hardhat + React dApp
│   ├── contracts/
│   │   ├── BiometricVerifier.sol
│   │   ├── AuthenticatorContract.sol
│   │   ├── AuditTrail.sol
│   │   └── IdentifierStorage.sol
│   ├── scripts/deploy.js
│   └── zkp-frontend/               # React dApp (CRA + ethers v5)
│       └── src/
│           ├── App.jsx
│           └── abi/Groth16Verifier.json
│
├── peuap_w3.pv                     # ProVerif 2.05 specification
├── peuap_w3.spdl                   # Scyther SPDL specification
└── proverif_results.txt            # Formal verification output
```

---

## ZKP Circuit — biometric_auth.circom

The core of the system. A single Groth16 proof simultaneously proves:

| Template | What It Proves |
|---|---|
| `CommitmentCheck` | Poseidon(credential_id, blinding) = commitment (Pedersen binding) |
| `SpO2RangeProof` | 85 ≤ spo2_value ≤ 100 (liveness, without revealing value) |
| `NonceBinding` | credential_id is bound to this session_nonce (anti-replay) |
| `HMACBinding` | Poseidon(credential_id, hmac_key) = hmac_out (device binding) |

```
Private inputs (never revealed):    Public inputs (on-chain):
  credential_id                        commitment
  blinding_factor                      session_nonce
  spo2_value                           hmac_out
  hmac_key                             spo2_min = 85
                                       spo2_max = 100
```

**Stats:** 1,579 R1CS constraints | 192-byte proof | ~3ms on-chain verify | BN254 curve

**Trusted setup:** Contribution by Adarsh S V Nair  
Hash: `b778851d 048380a3 f6df040d ad1ada4a 30bd93a2 7b120c0e ...`

---

## Authentication Flow

```
1. REGISTER
   User → fingerprint_auth_using-zkp.onrender.com/register
   → credential stored onion-encrypted (3-layer Fernet) in PostgreSQL

2. VALIDATE
   User opens validate page → places finger on WebAuthn reader
   → SpO₂ liveness value entered (85–100)
   → Flask: credential matched → AI risk check → ZKP generated → OTP issued

3. BROWSER EXTENSION
   User opens WEB3.0 Authenticator extension
   → enters User ID + OTP → fetches ZKP from /get_zkp
   → ZKP deleted from DB after retrieval (ephemeral)
   → HMAC-signed postMessage to dApp

4. WEB3 DAPP
   peuap-w3-dapp1.onrender.com receives ZKP
   → MetaMask connects to Sepolia
   → AuthenticatorContract.verifyProof() called on-chain
   → BiometricVerifier.sol verifies Groth16 proof
   → AuditTrail logs proof_hash + pseudonym (NO identity)
   → Authentication successful

5. SSI / VC ISSUANCE
   POST /vc/issue → W3C VC 2.0 issued
   → did:key:z6Mkqw... issuer DID
   → Ed25519Signature2020 signed
   → BitstringStatusListEntry for revocation
```

---

## AI Anomaly Detection (Contribution C5)

Isolation Forest trained on `auth_events` table. Blocks ZKP generation when risk score > 0.8.

**Four behavioural features:**
- Attempt frequency (attempts per hour)
- Time-of-day deviation from historical pattern
- Consecutive failure rate
- Days since last successful authentication

**Integration point:** `/validate` route — after credential match, before ZKP generation.

```
Normal user:  score=0.69 → ALLOWED → ZKP generated
Brute force:  score=0.92 → BLOCKED → 403 "high attempt frequency"
3am attempt:  score=0.85 → BLOCKED → "unusual time"
```

---

## Formal Verification Results

**ProVerif 2.05** — 5 queries under Dolev-Yao adversary:

| Query | Property | Result |
|---|---|---|
| Q1 | Biometric secrecy: `not attacker(credential_id)` | ✅ TRUE |
| Q2 | Issuer key secrecy: `not attacker(issuer_sk)` | ✅ TRUE |
| Q3 | Proof correspondence: ProofVerified ⟹ ProofGenerated | ❌ FALSE* |
| Q4 | OTP single-use: OTPConsumed ⟹ OTPIssued | ✅ TRUE |
| Q5 | VC correspondence: VCVerified ⟹ VCIssued | ❌ FALSE* |

*Q3 and Q5 FALSE: ProVerif cannot model on-chain BN254 pairing verification.  
Mitigated by BiometricVerifier.sol on-chain Groth16 check.

**Scyther** — Secret, Niagree, Nisynch, Alive verified for all 3 roles.

---

## Running Locally

### Prerequisites

```bash
# WSL (Ubuntu 24.04) recommended for Windows
node --version   # v18+
python3 --version # 3.12+
circom --version  # 2.2.2
snarkjs --version # 0.7.5
```

### Environment Variables

```bash
export DATABASE_URL="postgresql://..."
export ONION_KEY1="..."   # Fernet key 1
export ONION_KEY2="..."   # Fernet key 2
export ONION_KEY3="..."   # Fernet key 3
export HMAC_SECRET="..."
export ISSUER_PRIVATE_KEY_HEX="..."  # Ed25519 issuer key
```

### Backend

```bash
pip install -r requirements.txt
npm install  # installs circomlibjs
python3 app.py
```

### Relay Nodes (4 terminals)

```bash
cd relay-nodes/node1 && node server.js   # port 3001
cd relay-nodes/node2 && node server.js   # port 3002
cd relay-nodes/node3 && node server.js   # port 3003
cd relay-nodes && node coordinator.js    # port 3000
```

### React dApp

```bash
cd zkp-verification/zkp-frontend
npm install && npm start
```

### Smart Contracts (Sepolia)

```bash
cd zkp-verification
# Add SEPOLIA_RPC_URL and PRIVATE_KEY to .env
npx hardhat run scripts/deploy.js --network sepolia
```

---

## Hardware Authenticator (Planned — Immediate Future Work)

The hardware authenticator is fully architecturally specified. Physical fabrication is the primary next step.

### Bill of Materials (~$115)

| Component | Part Number | Purpose | Cost |
|---|---|---|---|
| STM32F4-DISCOVERY | STM32F407VGT6 | Main MCU (Cortex-M4, 168 MHz) | ~$25 |
| Fingerprint Module | FPC1020-DEV-KIT | Capacitive fingerprint, SPI | ~$15 |
| SpO₂ Sensor | MAX30102 (SparkFun SEN-14045) | Liveness detection, I2C | ~$10 |
| Secure Element | NXP SE050 (OM-SE050ARD) | ECC key storage, I2C | ~$30 |
| BLE Module | nRF52840 (Adafruit 4062) | BLE 6.0 transport, UART | ~$20 |
| OLED Display | SSD1306 0.96" I2C | Status display | ~$5 |
| LiPo Battery | 400mAh JST 2mm | Portable operation | ~$8 |

### Wiring Summary

**FPC1020 → STM32 (SPI):** CLK→PA5, MOSI→PA7, MISO→PA6, CS→PA4, IRQ→PB0  
**MAX30102 → STM32 (I2C):** SDA→PB7, SCL→PB6, INT→PC13  
**SE050 → STM32 (I2C):** SDA→PB9, SCL→PB10, ENA→PC0  
**nRF52840 → STM32 (UART):** TX→PA3, RX→PA2, RESET→PE1

### Firmware Pipeline (6 stages)

```
1. Fingerprint capture (FPC1020 SPI)
2. Minutiae extraction → SHA-256 hash
3. SpO₂ liveness check (MAX30102 I2C) — reject if < 85%
4. SE050 ECC signing (secp256k1)
5. Pedersen commitment computation
6. BLE 6.0 transmission (nRF52840 UART bridge)
```

> **Note:** The software prototype uses WebAuthn FIDO2 (`navigator.credentials.get()`) as the hardware simulation layer. The ZKP circuit and all protocol logic are identical regardless of whether the credential originates from physical hardware or WebAuthn.

---

## Publications

1. **A. S. V. Nair and R. Achary**, "Reinforcing Trust and Security in Decentralized Web 3.0: A Cryptographic Framework for Authentication in Resource-Constrained Devices," *IEEE Conference Proceedings (Scopus Indexed)*, 2024.

2. **A. S. V. Nair and R. Achary**, "Social Engineering Defender (SE.Def): Human Emotion Factor Based Classification and Defense against Social Engineering Attacks," *IEEE Conference Proceedings (Scopus Indexed)*, 2023.

---

## Novel Contributions

| ID | Contribution |
|---|---|
| **C1** | First ZKP biometric authentication circuit with SpO₂ liveness detection (biometric_auth.circom, 1,579 R1CS constraints, Groth16) |
| **C2** | Modified onion routing with Shamir k-of-n threshold de-anonymisation and on-chain governance |
| **C3** | W3C VC 2.0 SSI layer with did:key, Ed25519Signature2020, Bitstring Status List — GDPR-by-architecture |
| **C4** | Four-contract Solidity architecture with anti-replay nonce tracking and pseudonymous audit trail |
| **C5** | Isolation Forest behavioural AI security gate — fourth independent security layer orthogonal to biometric, cryptographic, and liveness layers |

---

## Candidate

**Adarsh S V Nair**  
PhD Candidate — Alliance School of Advanced Computing  
Alliance University, Bengaluru  
Supervisor: Prof. Rathnakar Achary  

---

*PEUAP-W3 — Demonstrating that privacy and accountability are not mutually exclusive in Web 3.0 authentication.*
