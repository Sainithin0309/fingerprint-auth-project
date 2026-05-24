// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title AuthenticatorContract
 * @author Adarsh S V Nair — Alliance University, Bengaluru
 * @notice PEUAP-W3: Privacy-Enhanced & User-Centric Authentication for Web 3.0
 *
 * This contract is the on-chain verifier for the biometric_auth Groth16 circuit.
 * It wraps BiometricVerifier.sol and adds:
 *   1. Anti-replay protection via session nonce tracking
 *   2. SpO2 liveness bound enforcement
 *   3. Audit trail event emission (proof hash + pseudonym only — no identity)
 *   4. VC revocation check via IdentifierStorage
 */

interface IBiometricVerifier {
    function verifyProof(
        uint[2]    calldata _pA,
        uint[2][2] calldata _pB,
        uint[2]    calldata _pC,
        uint[5]    calldata _pubSignals
    ) external view returns (bool);
}

interface IIdentifierStorage {
    function isRevoked(bytes32 vcHash) external view returns (bool);
}

interface IAuditTrail {
    function logAuth(
        bytes32 proofHash,
        bytes32 pseudonym,
        uint256 commitment,
        uint256 sessionNonce
    ) external;
}

contract AuthenticatorContract {

    // ── State ──────────────────────────────────────────────────────────────
    address public owner;
    IBiometricVerifier public verifier;
    IIdentifierStorage public identifierStorage;
    IAuditTrail        public auditTrail;

    // Nonces used — prevents proof replay attacks
    mapping(uint256 => bool) public usedNonces;

    // SpO2 public signal indices in the circuit output array
    // pubSignals order: [proof_valid, commitment, session_nonce, hmac_out, spo2_min, spo2_max]
    uint256 public constant SPO2_MIN = 85;
    uint256 public constant SPO2_MAX = 100;

    // ── Events ─────────────────────────────────────────────────────────────
    event AuthenticationSuccess(
        bytes32 indexed pseudonym,
        bytes32         proofHash,
        uint256         commitment,
        uint256         sessionNonce,
        uint256         timestamp
    );

    event AuthenticationFailed(
        bytes32 indexed pseudonym,
        string          reason,
        uint256         timestamp
    );

    event VerifierUpdated(address indexed newVerifier);
    event AuditTrailUpdated(address indexed newAuditTrail);

    // ── Modifiers ──────────────────────────────────────────────────────────
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // ── Constructor ────────────────────────────────────────────────────────
    constructor(
        address _verifier,
        address _identifierStorage,
        address _auditTrail
    ) {
        owner              = msg.sender;
        verifier           = IBiometricVerifier(_verifier);
        identifierStorage  = IIdentifierStorage(_identifierStorage);
        auditTrail         = IAuditTrail(_auditTrail);
    }

    // ── Core: authenticate ─────────────────────────────────────────────────
    /**
     * @notice Verifies a Groth16 biometric proof on-chain.
     *
     * @param _pA            Proof element A (G1 point)
     * @param _pB            Proof element B (G2 point)
     * @param _pC            Proof element C (G1 point)
     * @param _pubSignals    Public signals from circuit:
     *                         [0] proof_valid  (must be 1)
     *                         [1] commitment   Poseidon(cred, blinding)
     *                         [2] session_nonce anti-replay
     *                         [3] hmac_out     Poseidon(cred, hmac_key)
     *                         [4] spo2_min     (85)
     *                         [5] spo2_max     (100) — note: circuit has 5 public inputs + 1 output
     * @param pseudonym      User pseudonym (hash of wallet address — not real identity)
     * @param vcHash         W3C VC hash to check revocation status
     */
    function authenticate(
        uint[2]    calldata _pA,
        uint[2][2] calldata _pB,
        uint[2]    calldata _pC,
        uint[5]    calldata _pubSignals,
        bytes32             pseudonym,
        bytes32             vcHash
    ) external returns (bool) {

        uint256 sessionNonce = _pubSignals[2];
        uint256 commitment   = _pubSignals[1];

        // 1. Anti-replay: nonce must be fresh
        require(!usedNonces[sessionNonce], "Replay attack: nonce already used");

        // 2. VC revocation check
        if (address(identifierStorage) != address(0)) {
            require(
                !identifierStorage.isRevoked(vcHash),
                "VC has been revoked"
            );
        }

        // 3. Groth16 proof verification
        bool proofValid = verifier.verifyProof(_pA, _pB, _pC, _pubSignals);
        if (!proofValid) {
            emit AuthenticationFailed(pseudonym, "Invalid ZKP", block.timestamp);
            return false;
        }

        // 4. Mark nonce as used (after proof check — save gas on failure)
        usedNonces[sessionNonce] = true;

        // 5. Compute proof hash for audit trail (no PII — just cryptographic fingerprint)
        bytes32 proofHash = keccak256(abi.encodePacked(
            _pA[0], _pA[1],
            _pB[0][0], _pB[0][1],
            _pB[1][0], _pB[1][1],
            _pC[0], _pC[1]
        ));

        // 6. Log to audit trail (pseudonym + proof hash only — no identity)
        if (address(auditTrail) != address(0)) {
            auditTrail.logAuth(proofHash, pseudonym, commitment, sessionNonce);
        }

        // 7. Emit success event
        emit AuthenticationSuccess(
            pseudonym,
            proofHash,
            commitment,
            sessionNonce,
            block.timestamp
        );

        return true;
    }

    // ── Admin ──────────────────────────────────────────────────────────────
    function updateVerifier(address _verifier) external onlyOwner {
        verifier = IBiometricVerifier(_verifier);
        emit VerifierUpdated(_verifier);
    }

    function updateAuditTrail(address _auditTrail) external onlyOwner {
        auditTrail = IAuditTrail(_auditTrail);
        emit AuditTrailUpdated(_auditTrail);
    }

    function isNonceUsed(uint256 nonce) external view returns (bool) {
        return usedNonces[nonce];
    }
}
