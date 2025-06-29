from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import psycopg2
import secrets
import json
import subprocess
import os
import shutil
import base64

app = Flask(__name__, template_folder='templates')
CORS(app)

# PostgreSQL connection setup
conn = psycopg2.connect(os.environ["DATABASE_URL"])
cur = conn.cursor()

# Create necessary tables
cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        name TEXT,
        dob TEXT,
        country TEXT,
        credential_id TEXT UNIQUE
    )
""")
cur.execute("""
    CREATE TABLE IF NOT EXISTS zkp_storage (
        user_id TEXT PRIMARY KEY REFERENCES users(user_id),
        zkp_proof TEXT
    )
""")
conn.commit()

# In-memory OTP store
otp_storage = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/validate_page')
def validate_page():
    return render_template('validate.html')

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        user_id = data.get('user_id')
        name = data.get('name')
        dob = data.get('dob')
        country = data.get('country')
        credential_id = data.get('credential_id')

        cur.execute("""
            INSERT INTO users (user_id, name, dob, country, credential_id)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (user_id) DO NOTHING
        """, (user_id, name, dob, country, credential_id))
        conn.commit()

        return jsonify({"status": "success", "message": "User registered successfully"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

def generate_real_zk_proof_credential_id(credential_id_b64):
    # Decode base64 to bytes
    cred_bytes = base64.b64decode(credential_id_b64)
    cred_bytes = list(cred_bytes)[:32]
    cred_bytes += [0] * (32 - len(cred_bytes))
    if len(cred_bytes) != 32:
        raise ValueError("credential_id bytes must be exactly 32 bytes")

    # Save input.json for the Circom circuit
    input_data = {
        "credential_id": cred_bytes
    }
    with open("input.json", "w") as f:
        json.dump(input_data, f)

    # Run witness generation and proof as before, but with new circuit/wasm/zkey
    subprocess.run([
        "node", "CredentialIDHash_js/generate_witness.js", "CredentialIDHash_js/CredentialIDHash.wasm", "input.json", "witness.wtns"
    ], check=True)

    snarkjs_path = shutil.which("snarkjs")
    subprocess.run([
        snarkjs_path, "groth16", "prove", "CredentialIDHash_final.zkey", "witness.wtns", "proof.json", "public.json"
    ], check=True)

    with open("proof.json") as f:
        proof = json.load(f)
    with open("public.json") as f:
        public_json = json.load(f)
    if isinstance(public_json, dict):
        public_signals = list(public_json.values())[0]
    else:
        public_signals = public_json
    public_signals = [str(x) for x in public_signals]

    # Convert proof to on-chain format (Groth16 Solidity verifier expects this)
    def to_hex(x):
        if isinstance(x, str):
            return hex(int(x))
        return [to_hex(i) for i in x]

    onchain_proof = {
        "a": [str(int(proof["pi_a"][0])), str(int(proof["pi_a"][1]))],
        "b": [
            [str(int(proof["pi_b"][0][1])), str(int(proof["pi_b"][0][0]))],
            [str(int(proof["pi_b"][1][1])), str(int(proof["pi_b"][1][0]))]
        ],
        "c": [str(int(proof["pi_c"][0])), str(int(proof["pi_c"][1]))],
        "publicSignals": public_signals
    }

    return {
        "proof": proof,
        "public": public_signals,
        "onchain_proof": onchain_proof
    }

@app.route('/validate', methods=['POST'])
def validate():
    try:
        data = request.json
        user_id = data.get('user_id')
        credential_id = data.get('credential_id')

        cur.execute("SELECT name, credential_id FROM users WHERE user_id = %s", (user_id,))
        result = cur.fetchone()

        if result:
            name, stored_credential_id = result
            if stored_credential_id == credential_id:
                otp = str(secrets.randbelow(900000) + 100000)
                otp_storage[user_id] = otp

                zk_result = generate_real_zk_proof_credential_id(credential_id)
                zkp_proof = json.dumps(zk_result)

                cur.execute("""
                    INSERT INTO zkp_storage (user_id, zkp_proof)
                    VALUES (%s, %s)
                    ON CONFLICT (user_id) DO UPDATE
                    SET zkp_proof = EXCLUDED.zkp_proof
                """, (user_id, zkp_proof))
                conn.commit()

                return jsonify({"status": "success", "otp": otp}), 200
            else:
                return jsonify({"status": "error", "message": "Fingerprint verification failed"}), 403
        else:
            return jsonify({"status": "error", "message": "User not found"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/get_zkp', methods=['POST'])
def get_zkp():
    data = request.json
    user_id = data.get('user_id')
    otp = data.get('otp')
    if otp_storage.get(user_id) == otp:
        cur.execute("SELECT zkp_proof FROM zkp_storage WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if row:
            # Delete the ZKP after fetching
            cur.execute("DELETE FROM zkp_storage WHERE user_id = %s", (user_id,))
            conn.commit()
            return jsonify({"status": "success", "zkp": json.loads(row[0])}), 200
        else:
            return jsonify({"status": "error", "message": "No ZKP found"}), 404
    else:
        return jsonify({"status": "error", "message": "Invalid OTP"}), 403

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))