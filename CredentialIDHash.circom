pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

template CredentialIDHash() {
    signal input credential_id[32]; // 32 bytes input
    signal output hash;

    signal chunk[4];

    for (var i = 0; i < 4; i++) {
        chunk[i] <== 
            credential_id[i*8 + 0] +
            credential_id[i*8 + 1] * (1 << 8) +
            credential_id[i*8 + 2] * (1 << 16) +
            credential_id[i*8 + 3] * (1 << 24) +
            credential_id[i*8 + 4] * (1 << 32) +
            credential_id[i*8 + 5] * (1 << 40) +
            credential_id[i*8 + 6] * (1 << 48) +
            credential_id[i*8 + 7] * (1 << 56);
    }

    component poseidon = Poseidon(4);
    for (var i = 0; i < 4; i++) {
        poseidon.inputs[i] <== chunk[i];
    }
    hash <== poseidon.out;
}

component main = CredentialIDHash();