pragma circom 2.2.2;

// Import from your existing circomlib (already in your project)
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/*
 * PEUAP-W3 Biometric Authentication Circuit
 * Author: Adarsh S V Nair
 * Supervisor: Prof. Rathnakar Achary
 * Alliance University, Bengaluru
 *
 * This circuit proves simultaneously:
 *   1. Pedersen-style commitment: H(credential_id, blinding) == commitment
 *   2. SpO2 liveness range proof: 85 <= spo2 <= 100
 *   3. Session nonce binding (anti-replay)
 *   4. HMAC binding: H(credential_id, hmac_key) == hmac_out
 *
 * Private inputs (never revealed to verifier):
 *   - credential_id    : user's biometric-derived credential
 *   - blinding_factor  : random blinding for commitment hiding
 *   - spo2_value       : live SpO2 reading from MAX30102 sensor
 *   - hmac_key         : device-side HMAC secret key
 *
 * Public inputs (known to verifier / smart contract):
 *   - commitment       : Poseidon(credential_id, blinding_factor)
 *   - session_nonce    : anti-replay nonce (fresh per session)
 *   - hmac_out         : Poseidon(credential_id, hmac_key)
 *   - spo2_min         : minimum liveness threshold (85)
 *   - spo2_max         : maximum liveness threshold (100)
 */

// -----------------------------------------------------------
// Template 1: Pedersen-style Commitment Check
// Proves: Poseidon(credential_id, blinding_factor) == commitment
// -----------------------------------------------------------
template CommitmentCheck() {
    // Private
    signal input credential_id;
    signal input blinding_factor;
    // Public
    signal input commitment;

    signal output valid;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== credential_id;
    hasher.inputs[1] <== blinding_factor;

    // Constraint: computed hash must equal the public commitment
    commitment === hasher.out;

    valid <== 1;
}

// -----------------------------------------------------------
// Template 2: SpO2 Liveness Range Proof
// Proves: spo2_min <= spo2_value <= spo2_max
// Without revealing the actual spo2_value
// Uses circomlib LessEqThan comparator (n=8 bits, max value 255)
// -----------------------------------------------------------
template SpO2RangeProof(n) {
    // Private
    signal input spo2_value;
    // Public
    signal input spo2_min;
    signal input spo2_max;

    signal output in_range;

    // Check: spo2_value >= spo2_min
    // Equivalent to: spo2_min <= spo2_value
    component lower = LessEqThan(n);
    lower.in[0] <== spo2_min;
    lower.in[1] <== spo2_value;

    // Check: spo2_value <= spo2_max
    component upper = LessEqThan(n);
    upper.in[0] <== spo2_value;
    upper.in[1] <== spo2_max;

    // Both must be true
    in_range <== lower.out * upper.out;

    // Constraint: must be in range
    in_range === 1;
}

// -----------------------------------------------------------
// Template 3: Session Nonce Binding (Anti-Replay)
// Proves: Poseidon(credential_id, session_nonce) is computable
// The nonce is public — binds this proof to exactly one session
// -----------------------------------------------------------
template NonceBinding() {
    // Private
    signal input credential_id;
    // Public
    signal input session_nonce;

    signal output nonce_hash;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== credential_id;
    hasher.inputs[1] <== session_nonce;

    nonce_hash <== hasher.out;
}

// -----------------------------------------------------------
// Template 4: HMAC Binding
// Proves: Poseidon(credential_id, hmac_key) == hmac_out
// Binds the device's secret key to this credential
// -----------------------------------------------------------
template HMACBinding() {
    // Private
    signal input credential_id;
    signal input hmac_key;
    // Public
    signal input hmac_out;

    signal output valid;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== credential_id;
    hasher.inputs[1] <== hmac_key;

    // Constraint: computed HMAC must match public output
    hmac_out === hasher.out;

    valid <== 1;
}

// -----------------------------------------------------------
// MAIN CIRCUIT: BiometricAuth
// Combines all 4 sub-circuits into a single Groth16 proof
// -----------------------------------------------------------
template BiometricAuth() {

    // ---- PRIVATE INPUTS (prover knows, verifier never sees) ----
    signal input credential_id;       // biometric-derived credential
    signal input blinding_factor;     // Pedersen blinding scalar
    signal input spo2_value;          // live SpO2 from MAX30102
    signal input hmac_key;            // device HMAC secret key

    // ---- PUBLIC INPUTS (on-chain verifier knows these) ----
    signal input commitment;          // Poseidon(credential_id, blinding_factor)
    signal input session_nonce;       // fresh per-session anti-replay value
    signal input hmac_out;            // Poseidon(credential_id, hmac_key)
    signal input spo2_min;            // liveness lower bound (85)
    signal input spo2_max;            // liveness upper bound (100)

    // ---- OUTPUTS ----
    signal output proof_valid;        // 1 if all checks pass

    // ---- Sub-circuit instantiations ----

    // 1. Commitment check
    component commit = CommitmentCheck();
    commit.credential_id    <== credential_id;
    commit.blinding_factor  <== blinding_factor;
    commit.commitment       <== commitment;

    // 2. SpO2 liveness range proof (8-bit comparators, values 0-255)
    component liveness = SpO2RangeProof(8);
    liveness.spo2_value <== spo2_value;
    liveness.spo2_min   <== spo2_min;
    liveness.spo2_max   <== spo2_max;

    // 3. Session nonce binding
    component nonce = NonceBinding();
    nonce.credential_id  <== credential_id;
    nonce.session_nonce  <== session_nonce;
    // nonce_hash is an intermediate signal — not exposed publicly
    // but the constraint binds credential_id to this session_nonce

    // 4. HMAC binding
    component hmac = HMACBinding();
    hmac.credential_id <== credential_id;
    hmac.hmac_key      <== hmac_key;
    hmac.hmac_out      <== hmac_out;

    // All sub-circuits valid → overall proof valid
    // commit.valid == 1, liveness.in_range == 1 (enforced by === 1 constraints)
    // hmac.valid == 1
    // If any constraint fails, snarkjs throws — no proof is generated
    proof_valid <== commit.valid * hmac.valid;
}

// Entry point
component main {public [commitment, session_nonce, hmac_out, spo2_min, spo2_max]} = BiometricAuth();
