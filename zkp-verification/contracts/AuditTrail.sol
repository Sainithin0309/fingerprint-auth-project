// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title AuditTrail
 * @author Adarsh S V Nair — Alliance University, Bengaluru
 * @notice PEUAP-W3: Accountable Anonymous Authentication Audit Trail
 *
 * Records every authentication event as:
 *   - proof hash (cryptographic fingerprint of the ZKP)
 *   - pseudonym  (hash of wallet — NOT real identity)
 *   - commitment (Poseidon commitment from circuit)
 *   - timestamp
 *
 * De-anonymisation (linking pseudonym → real identity) requires
 * k-of-n auditor consensus via on-chain voting — the "threshold
 * accountability" mechanism described in the thesis.
 *
 * GDPR compliance:
 *   - No PII stored on-chain
 *   - Real identity lives off-chain in encrypted relay nodes
 *   - De-anonymisation requires governance quorum
 */
contract AuditTrail {

    // ── Types ──────────────────────────────────────────────────────────────
    struct AuthRecord {
        bytes32 proofHash;
        bytes32 pseudonym;
        uint256 commitment;
        uint256 sessionNonce;
        uint256 timestamp;
        bool    deanonymised;
    }

    struct DeanonRequest {
        bytes32   pseudonym;
        string    reason;
        uint256   createdAt;
        uint256   voteCount;
        bool      executed;
        mapping(address => bool) voted;
    }

    // ── State ──────────────────────────────────────────────────────────────
    address public owner;
    address public authenticatorContract;

    // k-of-n threshold parameters
    uint256 public requiredVotes;   // k
    uint256 public auditorCount;    // n

    mapping(address => bool)    public auditors;
    AuthRecord[]                public records;
    mapping(bytes32 => uint256[]) public pseudonymRecords; // pseudonym → record indices
    mapping(uint256 => DeanonRequest) public deanonRequests;
    uint256 public requestCount;

    // ── Events ─────────────────────────────────────────────────────────────
    event AuthLogged(
        uint256 indexed recordId,
        bytes32 indexed pseudonym,
        bytes32         proofHash,
        uint256         timestamp
    );

    event DeanonRequested(
        uint256 indexed requestId,
        bytes32 indexed pseudonym,
        string          reason,
        uint256         timestamp
    );

    event DeanonVoted(
        uint256 indexed requestId,
        address indexed auditor,
        uint256         voteCount,
        uint256         requiredVotes
    );

    event DeanonExecuted(
        uint256 indexed requestId,
        bytes32 indexed pseudonym,
        uint256         timestamp
    );

    event AuditorAdded(address indexed auditor);
    event AuditorRemoved(address indexed auditor);

    // ── Modifiers ──────────────────────────────────────────────────────────
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyAuthenticator() {
        require(
            msg.sender == authenticatorContract || msg.sender == owner,
            "Not authorised"
        );
        _;
    }

    modifier onlyAuditor() {
        require(auditors[msg.sender], "Not an auditor");
        _;
    }

    // ── Constructor ────────────────────────────────────────────────────────
    /**
     * @param _requiredVotes  k — minimum auditor votes to de-anonymise
     * @param _auditorList    Initial list of n auditor addresses
     */
    constructor(uint256 _requiredVotes, address[] memory _auditorList) {
        owner         = msg.sender;
        requiredVotes = _requiredVotes;

        for (uint i = 0; i < _auditorList.length; i++) {
            auditors[_auditorList[i]] = true;
            auditorCount++;
            emit AuditorAdded(_auditorList[i]);
        }

        require(
            requiredVotes <= auditorCount,
            "Required votes exceeds auditor count"
        );
    }

    // ── Core: log authentication ───────────────────────────────────────────
    /**
     * @notice Called by AuthenticatorContract after successful proof verification.
     *         Stores only: proof hash, pseudonym, commitment, nonce, timestamp.
     *         NO real identity stored.
     */
    function logAuth(
        bytes32 proofHash,
        bytes32 pseudonym,
        uint256 commitment,
        uint256 sessionNonce
    ) external onlyAuthenticator {
        uint256 recordId = records.length;

        records.push(AuthRecord({
            proofHash    : proofHash,
            pseudonym    : pseudonym,
            commitment   : commitment,
            sessionNonce : sessionNonce,
            timestamp    : block.timestamp,
            deanonymised : false
        }));

        pseudonymRecords[pseudonym].push(recordId);

        emit AuthLogged(recordId, pseudonym, proofHash, block.timestamp);
    }

    // ── De-anonymisation: request ──────────────────────────────────────────
    /**
     * @notice Any auditor can initiate a de-anonymisation request for a pseudonym.
     *         This starts the k-of-n voting process.
     */
    function requestDeanon(
        bytes32 pseudonym,
        string calldata reason
    ) external onlyAuditor returns (uint256 requestId) {
        requestId = requestCount++;

        DeanonRequest storage req = deanonRequests[requestId];
        req.pseudonym  = pseudonym;
        req.reason     = reason;
        req.createdAt  = block.timestamp;
        req.voteCount  = 0;
        req.executed   = false;

        emit DeanonRequested(requestId, pseudonym, reason, block.timestamp);
    }

    // ── De-anonymisation: vote ─────────────────────────────────────────────
    /**
     * @notice Auditors vote on a de-anonymisation request.
     *         When voteCount reaches requiredVotes, DeanonExecuted is emitted.
     *         Off-chain relay nodes listen for this event and release
     *         their Shamir shares to reconstruct the real identity.
     */
    function voteDeanon(uint256 requestId) external onlyAuditor {
        DeanonRequest storage req = deanonRequests[requestId];

        require(!req.executed, "Already executed");
        require(!req.voted[msg.sender], "Already voted");

        req.voted[msg.sender] = true;
        req.voteCount++;

        emit DeanonVoted(requestId, msg.sender, req.voteCount, requiredVotes);

        // Threshold reached — trigger de-anonymisation
        if (req.voteCount >= requiredVotes) {
            req.executed = true;

            // Mark all records for this pseudonym as de-anonymised
            uint256[] storage recs = pseudonymRecords[req.pseudonym];
            for (uint i = 0; i < recs.length; i++) {
                records[recs[i]].deanonymised = true;
            }

            emit DeanonExecuted(requestId, req.pseudonym, block.timestamp);
        }
    }

    // ── Views ──────────────────────────────────────────────────────────────
    function getRecord(uint256 recordId) external view returns (
        bytes32 proofHash,
        bytes32 pseudonym,
        uint256 commitment,
        uint256 sessionNonce,
        uint256 timestamp,
        bool    deanonymised
    ) {
        AuthRecord storage r = records[recordId];
        return (r.proofHash, r.pseudonym, r.commitment,
                r.sessionNonce, r.timestamp, r.deanonymised);
    }

    function getRecordCount() external view returns (uint256) {
        return records.length;
    }

    function getPseudonymRecords(bytes32 pseudonym)
        external view returns (uint256[] memory)
    {
        return pseudonymRecords[pseudonym];
    }

    function getDeanonRequest(uint256 requestId) external view returns (
        bytes32 pseudonym,
        string memory reason,
        uint256 createdAt,
        uint256 voteCount,
        bool    executed
    ) {
        DeanonRequest storage req = deanonRequests[requestId];
        return (req.pseudonym, req.reason, req.createdAt,
                req.voteCount, req.executed);
    }

    function hasVoted(uint256 requestId, address auditor)
        external view returns (bool)
    {
        return deanonRequests[requestId].voted[auditor];
    }

    // ── Admin ──────────────────────────────────────────────────────────────
    function setAuthenticatorContract(address _auth) external onlyOwner {
        authenticatorContract = _auth;
    }

    function addAuditor(address auditor) external onlyOwner {
        require(!auditors[auditor], "Already auditor");
        auditors[auditor] = true;
        auditorCount++;
        emit AuditorAdded(auditor);
    }

    function removeAuditor(address auditor) external onlyOwner {
        require(auditors[auditor], "Not an auditor");
        auditors[auditor] = false;
        auditorCount--;
        require(requiredVotes <= auditorCount, "Would break quorum");
        emit AuditorRemoved(auditor);
    }

    function updateRequiredVotes(uint256 _required) external onlyOwner {
        require(_required <= auditorCount, "Exceeds auditor count");
        require(_required > 0, "Must be > 0");
        requiredVotes = _required;
    }
}
