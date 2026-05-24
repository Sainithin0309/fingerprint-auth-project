// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IdentifierStorage
 * @author Adarsh S V Nair — Alliance University, Bengaluru
 * @notice PEUAP-W3: W3C Verifiable Credential Registry with Bitstring Revocation
 *
 * Stores only:
 *   - Hash of the W3C VC (not the VC itself — GDPR compliant)
 *   - Revocation status per VC hash
 *   - DID document hash per user pseudonym
 *
 * Implements W3C Bitstring Status List 1.0 pattern:
 *   - Each VC gets a status list index
 *   - Revocation flips a bit — does not delete (immutability preserved)
 *   - Cryptographic erasure: destroying the device key makes the
 *     on-chain anchor computationally irrecoverable (GDPR Article 17)
 *
 * GDPR right-to-erasure runbook:
 *   1. Holder destroys device private key
 *   2. Issuer calls revokeVC(vcHash)
 *   3. On-chain anchor becomes a hash whose preimage is gone
 *   4. AuthenticatorContract rejects future proofs with this VC
 */
contract IdentifierStorage {

    // ── Types ──────────────────────────────────────────────────────────────
    struct VCRecord {
        bytes32 vcHash;         // keccak256 of the W3C VC JSON
        bytes32 pseudonym;      // owner pseudonym (not real identity)
        uint256 issuedAt;       // block timestamp
        uint256 revokedAt;      // 0 if active
        bool    revoked;
        uint256 statusListIndex; // W3C Bitstring Status List index
    }

    struct DIDRecord {
        bytes32 pseudonym;
        bytes32 didDocHash;     // keccak256 of DID document
        bytes32 publicKeyHash;  // keccak256 of ECC public key
        uint256 registeredAt;
        uint256 updatedAt;
        bool    active;
    }

    // ── State ──────────────────────────────────────────────────────────────
    address public owner;
    address public issuer;      // ACA-Py agent address

    mapping(bytes32 => VCRecord)  public vcRecords;     // vcHash → record
    mapping(bytes32 => DIDRecord) public didRecords;    // pseudonym → DID
    mapping(bytes32 => bytes32[]) public pseudonymVCs;  // pseudonym → vcHashes

    // W3C Bitstring Status List — packed bits
    // Each uint256 holds 256 status bits
    uint256[] public statusList;
    uint256   public vcCount;

    // ── Events ─────────────────────────────────────────────────────────────
    event VCIssued(
        bytes32 indexed vcHash,
        bytes32 indexed pseudonym,
        uint256         statusListIndex,
        uint256         timestamp
    );

    event VCRevoked(
        bytes32 indexed vcHash,
        bytes32 indexed pseudonym,
        uint256         timestamp
    );

    event DIDRegistered(
        bytes32 indexed pseudonym,
        bytes32         didDocHash,
        uint256         timestamp
    );

    event DIDUpdated(
        bytes32 indexed pseudonym,
        bytes32         newDidDocHash,
        uint256         timestamp
    );

    event DIDDeactivated(
        bytes32 indexed pseudonym,
        uint256         timestamp
    );

    // ── Modifiers ──────────────────────────────────────────────────────────
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyIssuer() {
        require(
            msg.sender == issuer || msg.sender == owner,
            "Not issuer"
        );
        _;
    }

    // ── Constructor ────────────────────────────────────────────────────────
    constructor(address _issuer) {
        owner  = msg.sender;
        issuer = _issuer;
        // Initialise first status list word
        statusList.push(0);
    }

    // ── VC Registry ────────────────────────────────────────────────────────
    /**
     * @notice Register a new W3C VC hash on-chain.
     *         Called by the ACA-Py issuer agent after VC issuance.
     *         Only the hash is stored — never the VC content (GDPR).
     */
    function issueVC(
        bytes32 vcHash,
        bytes32 pseudonym
    ) external onlyIssuer returns (uint256 statusListIndex) {
        require(vcRecords[vcHash].issuedAt == 0, "VC already registered");

        statusListIndex = vcCount++;

        // Expand status list if needed (256 VCs per uint256 word)
        if (statusListIndex % 256 == 0 && statusListIndex > 0) {
            statusList.push(0);
        }

        vcRecords[vcHash] = VCRecord({
            vcHash           : vcHash,
            pseudonym        : pseudonym,
            issuedAt         : block.timestamp,
            revokedAt        : 0,
            revoked          : false,
            statusListIndex  : statusListIndex
        });

        pseudonymVCs[pseudonym].push(vcHash);

        emit VCIssued(vcHash, pseudonym, statusListIndex, block.timestamp);
    }

    /**
     * @notice Revoke a VC — flips its bit in the Bitstring Status List.
     *         Part of GDPR right-to-erasure runbook.
     */
    function revokeVC(bytes32 vcHash) external onlyIssuer {
        VCRecord storage vc = vcRecords[vcHash];
        require(vc.issuedAt > 0, "VC not found");
        require(!vc.revoked,     "Already revoked");

        vc.revoked    = true;
        vc.revokedAt  = block.timestamp;

        // Flip bit in Bitstring Status List
        uint256 wordIndex = vc.statusListIndex / 256;
        uint256 bitIndex  = vc.statusListIndex % 256;
        statusList[wordIndex] |= (1 << bitIndex);

        emit VCRevoked(vcHash, vc.pseudonym, block.timestamp);
    }

    /**
     * @notice Check if a VC is revoked.
     *         Called by AuthenticatorContract before accepting a proof.
     */
    function isRevoked(bytes32 vcHash) external view returns (bool) {
        VCRecord storage vc = vcRecords[vcHash];
        if (vc.issuedAt == 0) return false; // Unknown VC — not revoked
        return vc.revoked;
    }

    // ── DID Registry ───────────────────────────────────────────────────────
    /**
     * @notice Register a DID document hash for a pseudonym.
     *         Conforms to W3C DID Core v1.0 + did:indy:besu pattern.
     */
    function registerDID(
        bytes32 pseudonym,
        bytes32 didDocHash,
        bytes32 publicKeyHash
    ) external onlyIssuer {
        require(!didRecords[pseudonym].active, "DID already registered");

        didRecords[pseudonym] = DIDRecord({
            pseudonym      : pseudonym,
            didDocHash     : didDocHash,
            publicKeyHash  : publicKeyHash,
            registeredAt   : block.timestamp,
            updatedAt      : block.timestamp,
            active         : true
        });

        emit DIDRegistered(pseudonym, didDocHash, block.timestamp);
    }

    /**
     * @notice Update DID document — key rotation support.
     */
    function updateDID(
        bytes32 pseudonym,
        bytes32 newDidDocHash,
        bytes32 newPublicKeyHash
    ) external onlyIssuer {
        DIDRecord storage did = didRecords[pseudonym];
        require(did.active, "DID not active");

        did.didDocHash    = newDidDocHash;
        did.publicKeyHash = newPublicKeyHash;
        did.updatedAt     = block.timestamp;

        emit DIDUpdated(pseudonym, newDidDocHash, block.timestamp);
    }

    /**
     * @notice Deactivate DID — part of GDPR erasure runbook.
     *         After device key destruction, holder deactivates their DID.
     */
    function deactivateDID(bytes32 pseudonym) external onlyIssuer {
        DIDRecord storage did = didRecords[pseudonym];
        require(did.active, "DID not active");
        did.active    = false;
        did.updatedAt = block.timestamp;

        emit DIDDeactivated(pseudonym, block.timestamp);
    }

    // ── Views ──────────────────────────────────────────────────────────────
    function getVC(bytes32 vcHash) external view returns (
        bytes32 pseudonym,
        uint256 issuedAt,
        uint256 revokedAt,
        bool    revoked,
        uint256 statusListIndex
    ) {
        VCRecord storage vc = vcRecords[vcHash];
        return (vc.pseudonym, vc.issuedAt, vc.revokedAt,
                vc.revoked, vc.statusListIndex);
    }

    function getDID(bytes32 pseudonym) external view returns (
        bytes32 didDocHash,
        bytes32 publicKeyHash,
        uint256 registeredAt,
        uint256 updatedAt,
        bool    active
    ) {
        DIDRecord storage did = didRecords[pseudonym];
        return (did.didDocHash, did.publicKeyHash,
                did.registeredAt, did.updatedAt, did.active);
    }

    function getPseudonymVCs(bytes32 pseudonym)
        external view returns (bytes32[] memory)
    {
        return pseudonymVCs[pseudonym];
    }

    function getStatusListWord(uint256 wordIndex)
        external view returns (uint256)
    {
        return statusList[wordIndex];
    }

    // ── Admin ──────────────────────────────────────────────────────────────
    function setIssuer(address _issuer) external onlyOwner {
        issuer = _issuer;
    }
}
