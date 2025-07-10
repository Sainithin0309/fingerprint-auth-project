from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import psycopg2
import secrets
import json
import subprocess
import os
import shutil
import base64
from cryptography.fernet import Fernet

app = Flask(__name__, template_folder='templates')
CORS(app)

# PostgreSQL connection
try:
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    cur = conn.cursor()
except Exception as e:
    print(f"Database connection failed: {e}")
    raise

# Onion routing setup
KEYS = [Fernet(k.encode()) for k in [
    os.environ["ONION_KEY1"],
    os.environ["ONION_KEY2"],
    os.environ["ONION_KEY3"]
]]

def onion_encrypt(data: str) -> str:
    enc = data.encode()
    for k in KEYS:
        enc = k.encrypt(enc)
    return enc.decode()

def onion_decrypt(data: str) -> str:
    dec = data.encode()
    for k in reversed(KEYS):
        dec = k.decrypt(dec)
    return dec.decode()

# DB Tables
try:
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            name TEXT,
            dob TEXT,
            country TEXT,
            credential_id TEXT UNIQUE
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS zkp_storage (
            user_id TEXT PRIMARY KEY REFERENCES users(user_id),
            zkp_proof TEXT
        );
    """)
    conn.commit()
except Exception as e:
    conn.rollback()
    print(f"Table creation failed: {e}")
    raise

# OTP storage
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
        required = ['user_id', 'name', 'dob', 'country', 'credential_id']
        for field in required:
            if not data.get(field):
                return jsonify({"status": "error", "message": f"Missing {field}"}), 400

        encrypted = {f: onion_encrypt(data[f]) for f in required}

        cur.execute("""
            INSERT INTO users (user_id, name, dob, country, credential_id)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (user_id) DO UPDATE SET
                name = EXCLUDED.name,
                dob = EXCLUDED.dob,
                country = EXCLUDED.country,
                credential_id = EXCLUDED.credential_id;
        """, (
            encrypted["user_id"], encrypted["name"], encrypted["dob"],
            encrypted["country"], encrypted["credential_id"]
        ))
        conn.commit()

        return jsonify({"status": "success", "message": "User registered securely"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

def generate_real_zk_proof_credential_id(credential_id_b64):
    try:
        cred_bytes = base64.b64decode(credential_id_b64)
    except Exception:
        raise ValueError("Invalid base64 credential_id")

    cred_bytes = list(cred_bytes)[:32]
    cred_bytes += [0] * (32 - len(cred_bytes))

    input_data = {"credential_id": cred_bytes}
    with open("input.json", "w") as f:
        json.dump(input_data, f)

    subprocess.run([
        "node", "CredentialIDHash_js/generate_witness.js",
        "CredentialIDHash_js/CredentialIDHash.wasm",
        "input.json", "witness.wtns"
    ], check=True)

    snarkjs = shutil.which("snarkjs")
    subprocess.run([
        snarkjs, "groth16", "prove",
        "CredentialIDHash_final.zkey", "witness.wtns",
        "proof.json", "public.json"
    ], check=True)

    with open("proof.json") as f:
        proof = json.load(f)
    with open("public.json") as f:
        public = json.load(f)

    public_signals = public if isinstance(public, list) else list(public.values())[0]
    public_signals = [str(x) for x in public_signals]

    return {
        "proof": proof,
        "public": public_signals,
        "onchain_proof": {
            "a": [str(int(proof["pi_a"][0])), str(int(proof["pi_a"][1]))],
            "b": [
                [str(int(proof["pi_b"][0][1])), str(int(proof["pi_b"][0][0]))],
                [str(int(proof["pi_b"][1][1])), str(int(proof["pi_b"][1][0]))]
            ],
            "c": [str(int(proof["pi_c"][0])), str(int(proof["pi_c"][1]))],
            "publicSignals": public_signals
        }
    }

@app.route('/validate', methods=['POST'])
def validate():
    try:
        data = request.json
        user_id = data.get('user_id')
        credential_id = data.get('credential_id')

        if not user_id or not credential_id:
            return jsonify({"status": "error", "message": "Missing user_id or credential_id"}), 400

        # Search all rows and decrypt user_ids
        cur.execute("SELECT user_id, credential_id FROM users")
        found = False
        for enc_uid, enc_cred in cur.fetchall():
            try:
                dec_uid = onion_decrypt(enc_uid)
                if dec_uid == user_id:
                    dec_cred = onion_decrypt(enc_cred)
                    if dec_cred != credential_id:
                        return jsonify({"status": "error", "message": "Fingerprint verification failed"}), 403
                    found = True
                    encrypted_user_id = enc_uid
                    break
            except Exception:
                continue

        if not found:
            return jsonify({"status": "error", "message": "User not found"}), 404

        otp = str(secrets.randbelow(900000) + 100000)
        otp_storage[user_id] = otp

        zk_result = generate_real_zk_proof_credential_id(credential_id)
        zkp_proof = json.dumps(zk_result)

        cur.execute("""
            INSERT INTO zkp_storage (user_id, zkp_proof)
            VALUES (%s, %s)
            ON CONFLICT (user_id) DO UPDATE SET zkp_proof = EXCLUDED.zkp_proof;
        """, (encrypted_user_id, zkp_proof))
        conn.commit()

        return jsonify({"status": "success", "otp": otp}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/get_zkp', methods=['POST'])
def get_zkp():
    try:
        data = request.json
        user_id = data.get('user_id')
        otp = data.get('otp')

        if not user_id or not otp:
            return jsonify({"status": "error", "message": "Missing user_id or otp"}), 400

        if otp_storage.get(user_id) != otp:
            return jsonify({"status": "error", "message": "Invalid OTP"}), 403

        # Find encrypted user_id matching the decrypted user_id
        cur.execute("SELECT user_id FROM users")
        encrypted_user_id = None
        for row in cur.fetchall():
            try:
                if onion_decrypt(row[0]) == user_id:
                    encrypted_user_id = row[0]
                    break
            except:
                continue

        if not encrypted_user_id:
            return jsonify({"status": "error", "message": "User not found"}), 404

        cur.execute("SELECT zkp_proof FROM zkp_storage WHERE user_id = %s", (encrypted_user_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"status": "error", "message": "No ZKP found"}), 404

        otp_storage.pop(user_id, None)
        cur.execute("DELETE FROM zkp_storage WHERE user_id = %s", (encrypted_user_id,))
        conn.commit()

        return jsonify({"status": "success", "zkp": json.loads(row[0])}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
