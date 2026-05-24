const { buildPoseidon } = require("circomlibjs");

async function main() {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const credential_id = BigInt("123456789");
    const blinding_factor = BigInt("987654321");
    const hmac_key = BigInt("111222333");
    const session_nonce = BigInt("444555666");

    // commitment = Poseidon(credential_id, blinding_factor)
    const commitment = poseidon([credential_id, blinding_factor]);
    const commitment_str = F.toString(commitment);

    // hmac_out = Poseidon(credential_id, hmac_key)
    const hmac_out = poseidon([credential_id, hmac_key]);
    const hmac_out_str = F.toString(hmac_out);

    console.log("commitment:", commitment_str);
    console.log("hmac_out:  ", hmac_out_str);

    // Write correct input.json
    const fs = require("fs");
    const input = {
        credential_id: credential_id.toString(),
        blinding_factor: blinding_factor.toString(),
        spo2_value: "97",
        hmac_key: hmac_key.toString(),
        commitment: commitment_str,
        session_nonce: session_nonce.toString(),
        hmac_out: hmac_out_str,
        spo2_min: "85",
        spo2_max: "100"
    };
    fs.writeFileSync("biometric_auth_input.json", JSON.stringify(input, null, 2));
    console.log("\nbiometric_auth_input.json written successfully");
}

main().catch(console.error);
