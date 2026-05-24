from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import psycopg2
import psycopg2.extras
import secrets
import json
import subprocess
import os
import shutil
import hashlib
import hmac
import time
from cryptography.fernet import Fernet

app = Flask(__name__, template_folder='templates')
CORS(app)

# ─────────────────────────────────────────────
# DATABASE CONNECTION (with reconnect support)
# ─────────────────────────────────────────────
def get_db():
    """Always returns a live connection — reconnects if dropped."""
    global conn, cur
    try:
        conn.isolation_level  # ping
    except Exception:
        conn = psycopg2.connect(os.environ["DATABASE_URL"])
        cur  = conn.cursor()
    return conn, cur

try:
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    cur  = conn.cursor()
except Exception as e:
    print(f"Database connection failed: {e}")
    raise

# ─────────────────────────────────────────────
# ONION ENCRYPTION  (unchanged — keep working)
# ─────────────────────────────────────────────
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

# ─────────────────────────────────────────────
# HMAC HELPER
# Computes HMAC-SHA256(credential_id, HMAC_SECRET)
# Returns integer string for Poseidon circuit input
# ─────────────────────────────────────────────
HMAC_SECRET = os.environ.get("HMAC_SECRET", "peuap_w3_hmac_secret_key_2025")

def compute_hmac_int(credential_id: str) -> str:
    """Returns HMAC as a decimal integer string (fits BN254 field)."""
    h = hmac.new(HMAC_SECRET.encode(), credential_id.encode(), hashlib.sha256)
    # Take first 31 bytes to stay within BN254 field prime
    return str(int.from_bytes(h.digest()[:31], "big"))

# ─────────────────────────────────────────────
# DB TABLES  (idempotent — safe to re-run)
# ─────────────────────────────────────────────
def init_tables():
    conn, cur = get_db()
    try:
        # Original tables — unchanged
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id       TEXT PRIMARY KEY,
                name          TEXT,
                dob           TEXT,
                country       TEXT,
                credential_id TEXT UNIQUE
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS zkp_storage (
                user_id   TEXT PRIMARY KEY REFERENCES users(user_id),
                zkp_proof TEXT
            );
        """)

        # NEW: OTP storage in DB (replaces in-memory dict)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS otp_store (
                user_id    TEXT PRIMARY KEY,
                otp        TEXT NOT NULL,
                created_at BIGINT NOT NULL,
                expires_at BIGINT NOT NULL
            );
        """)

        # NEW: Auth events log (for AI anomaly detection later)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS auth_events (
                id            SERIAL PRIMARY KEY,
                user_id       TEXT,
                event_type    TEXT,
                success       BOOLEAN,
                ip_address    TEXT,
                attempt_count INTEGER DEFAULT 1,
                created_at    BIGINT
            );
        """)

        conn.commit()
        print("Tables initialised successfully")
    except Exception as e:
        conn.rollback()
        print(f"Table creation failed: {e}")
        raise

init_tables()

# ─────────────────────────────────────────────
# OTP HELPERS  (PostgreSQL-backed, 5-min expiry)
# ─────────────────────────────────────────────
OTP_TTL = 300  # seconds

def otp_store(user_id: str, otp: str):
    conn, cur = get_db()
    now = int(time.time())
    cur.execute("""
        INSERT INTO otp_store (user_id, otp, created_at, expires_at)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (user_id) DO UPDATE SET
            otp        = EXCLUDED.otp,
            created_at = EXCLUDED.created_at,
            expires_at = EXCLUDED.expires_at;
    """, (user_id, otp, now, now + OTP_TTL))
    conn.commit()

def otp_verify(user_id: str, otp: str) -> bool:
    conn, cur = get_db()
    now = int(time.time())
    cur.execute("""
        SELECT otp FROM otp_store
        WHERE user_id = %s AND expires_at > %s
    """, (user_id, now))
    row = cur.fetchone()
    return row is not None and row[0] == otp

def otp_delete(user_id: str):
    conn, cur = get_db()
    cur.execute("DELETE FROM otp_store WHERE user_id = %s", (user_id,))
    conn.commit()

# ─────────────────────────────────────────────
# AUTH EVENT LOGGER
# ─────────────────────────────────────────────
def log_event(user_id: str, event_type: str, success: bool, ip: str = None):
    try:
        conn, cur = get_db()
        cur.execute("""
            INSERT INTO auth_events (user_id, event_type, success, ip_address, created_at)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, event_type, success, ip, int(time.time())))
        conn.commit()
    except Exception as e:
        print(f"Event logging failed (non-critical): {e}")

# ─────────────────────────────────────────────
# ZKP PROOF GENERATOR  (upgraded circuit)
# ─────────────────────────────────────────────
def generate_biometric_zkp(credential_id: str, spo2_value: int = 97) -> dict:
    """
    Generates a Groth16 ZKP using the new biometric_auth circuit.

    Private inputs:
      - credential_id    : user credential (as integer string)
      - blinding_factor  : random per-session scalar
      - spo2_value       : liveness reading (real device) or simulated
      - hmac_key         : HMAC-derived integer

    Public inputs (go on-chain):
      - commitment       : Poseidon(credential_id, blinding_factor)
      - session_nonce    : fresh random anti-replay value
      - hmac_out         : Poseidon(credential_id, hmac_key)
      - spo2_min / max   : 85 / 100
    """

    # Convert credential_id to integer (take SHA256 → first 31 bytes → int)
    cred_int = str(int.from_bytes(
        hashlib.sha256(credential_id.encode()).digest()[:31], "big"
    ))

    # Random blinding factor and session nonce (fresh per proof)
    blinding = str(secrets.randbelow(
        21888242871839275222246405745257275088548364400416034343698204186575808495617
    ))
    nonce = str(secrets.randbelow(
        21888242871839275222246405745257275088548364400416034343698204186575808495617
    ))

    # HMAC key as integer
    hmac_key_int = compute_hmac_int(credential_id)

    # We need to compute Poseidon hashes (commitment and hmac_out)
    # using the same circomlibjs library used during circuit compilation
    compute_script = f"""
const {{ buildPoseidon }} = require("circomlibjs");
const fs = require("fs");

async function main() {{
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const cred        = BigInt("{cred_int}");
    const blinding    = BigInt("{blinding}");
    const hmac_key    = BigInt("{hmac_key_int}");
    const nonce       = BigInt("{nonce}");

    const commitment = F.toString(poseidon([cred, blinding]));
    const hmac_out   = F.toString(poseidon([cred, hmac_key]));

    const input = {{
        credential_id  : cred.toString(),
        blinding_factor: blinding.toString(),
        spo2_value     : "{spo2_value}",
        hmac_key       : hmac_key.toString(),
        commitment     : commitment,
        session_nonce  : nonce.toString(),
        hmac_out       : hmac_out,
        spo2_min       : "85",
        spo2_max       : "100"
    }};

    fs.writeFileSync("biometric_auth_input.json", JSON.stringify(input, null, 2));
    console.log(JSON.stringify({{ commitment, hmac_out, session_nonce: nonce.toString() }}));
}}
main().catch(e => {{ console.error(e); process.exit(1); }});
"""

    with open("_compute_poseidon.js", "w") as f:
        f.write(compute_script)

    # Step 1: compute public inputs
    result = subprocess.run(
        ["node", "_compute_poseidon.js"],
        capture_output=True, text=True, check=True
    )
    public_vals = json.loads(result.stdout.strip())

    # Step 2: generate witness
    subprocess.run([
        "node", "biometric_auth_js/generate_witness.js",
        "biometric_auth_js/biometric_auth.wasm",
        "biometric_auth_input.json",
        "biometric_auth_witness.wtns"
    ], check=True)

    # Step 3: generate Groth16 proof
    snarkjs_bin = shutil.which("snarkjs")
    subprocess.run([
        snarkjs_bin, "groth16", "prove",
        "biometric_auth_final.zkey",
        "biometric_auth_witness.wtns",
        "biometric_auth_proof.json",
        "biometric_auth_public.json"
    ], check=True)

    with open("biometric_auth_proof.json") as f:
        proof = json.load(f)
    with open("biometric_auth_public.json") as f:
        public = json.load(f)

    public_signals = [str(x) for x in public]

    return {
        "proof"      : proof,
        "public"     : public_signals,
        "commitment" : public_vals["commitment"],
        "session_nonce": public_vals["session_nonce"],
        "circuit"    : "biometric_auth_v2",
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

# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/validate_page')
def validate_page():
    return render_template('validate.html')


@app.route('/register', methods=['POST'])
def register():
    """Unchanged — onion encryption preserved exactly."""
    conn, cur = get_db()
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
                name          = EXCLUDED.name,
                dob           = EXCLUDED.dob,
                country       = EXCLUDED.country,
                credential_id = EXCLUDED.credential_id;
        """, (
            encrypted["user_id"], encrypted["name"], encrypted["dob"],
            encrypted["country"], encrypted["credential_id"]
        ))
        conn.commit()

        log_event(data["user_id"], "register", True,
                  request.remote_addr)

        return jsonify({"status": "success", "message": "User registered securely"}), 200

    except Exception as e:
        conn.rollback()
        log_event(data.get("user_id", "unknown"), "register", False,
                  request.remote_addr)
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/validate', methods=['POST'])
def validate():
    """
    Validates fingerprint credential, generates ZKP with new circuit,
    stores OTP in PostgreSQL (not in-memory).
    """
    conn, cur = get_db()
    ip = request.remote_addr
    try:
        data = request.json
        user_id      = data.get('user_id')
        credential_id = data.get('credential_id')
        # Optional: spo2 from hardware device (defaults to 97 if not provided)
        spo2_value   = int(data.get('spo2_value', 97))

        if not user_id or not credential_id:
            return jsonify({"status": "error",
                            "message": "Missing user_id or credential_id"}), 400

        # Validate SpO2 range before even generating proof
        if not (85 <= spo2_value <= 100):
            log_event(user_id, "validate_liveness_fail", False, ip)
            return jsonify({"status": "error",
                            "message": "Liveness check failed: SpO2 out of range"}), 403

        # Find user in DB (O(n) scan — acceptable for prototype)
        cur.execute("SELECT user_id, credential_id FROM users")
        found              = False
        encrypted_user_id  = None

        for enc_uid, enc_cred in cur.fetchall():
            try:
                dec_uid = onion_decrypt(enc_uid)
                if dec_uid == user_id:
                    dec_cred = onion_decrypt(enc_cred)
                    if dec_cred != credential_id:
                        log_event(user_id, "validate_cred_fail", False, ip)
                        return jsonify({"status": "error",
                                        "message": "Fingerprint verification failed"}), 403
                    found             = True
                    encrypted_user_id = enc_uid
                    break
            except Exception:
                continue

        if not found:
            log_event(user_id, "validate_user_not_found", False, ip)
            return jsonify({"status": "error", "message": "User not found"}), 404

        # Generate ZKP with new biometric_auth circuit
        zk_result = generate_biometric_zkp(credential_id, spo2_value)
        zkp_proof  = json.dumps(zk_result)

        # Store ZKP
        cur.execute("""
            INSERT INTO zkp_storage (user_id, zkp_proof)
            VALUES (%s, %s)
            ON CONFLICT (user_id) DO UPDATE SET zkp_proof = EXCLUDED.zkp_proof;
        """, (encrypted_user_id, zkp_proof))

        # Generate OTP and store in PostgreSQL (not in-memory dict)
        otp = str(secrets.randbelow(900000) + 100000)
        otp_store(user_id, otp)

        conn.commit()
        log_event(user_id, "validate_success", True, ip)

        return jsonify({"status": "success", "otp": otp}), 200

    except Exception as e:
        conn.rollback()
        log_event(data.get("user_id", "unknown") if 'data' in dir() else "unknown",
                  "validate_error", False, ip)
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/get_zkp', methods=['POST'])
def get_zkp():
    """
    Validates OTP (from PostgreSQL), returns ZKP, deletes both.
    Unchanged logic — improved OTP backend only.
    """
    conn, cur = get_db()
    ip = request.remote_addr
    try:
        data    = request.json
        user_id = data.get('user_id')
        otp     = data.get('otp')

        if not user_id or not otp:
            return jsonify({"status": "error",
                            "message": "Missing user_id or otp"}), 400

        # Verify OTP from PostgreSQL
        if not otp_verify(user_id, otp):
            log_event(user_id, "get_zkp_otp_fail", False, ip)
            return jsonify({"status": "error", "message": "Invalid or expired OTP"}), 403

        # Find encrypted user_id
        cur.execute("SELECT user_id FROM users")
        encrypted_user_id = None
        for row in cur.fetchall():
            try:
                if onion_decrypt(row[0]) == user_id:
                    encrypted_user_id = row[0]
                    break
            except Exception:
                continue

        if not encrypted_user_id:
            return jsonify({"status": "error", "message": "User not found"}), 404

        # Fetch ZKP
        cur.execute("SELECT zkp_proof FROM zkp_storage WHERE user_id = %s",
                    (encrypted_user_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"status": "error", "message": "No ZKP found"}), 404

        # Delete OTP + ZKP (ephemeral — one-time use)
        otp_delete(user_id)
        cur.execute("DELETE FROM zkp_storage WHERE user_id = %s",
                    (encrypted_user_id,))
        conn.commit()

        log_event(user_id, "get_zkp_success", True, ip)

        return jsonify({"status": "success", "zkp": json.loads(row[0])}), 200

    except Exception as e:
        conn.rollback()
        log_event(data.get("user_id", "unknown") if 'data' in dir() else "unknown",
                  "get_zkp_error", False, ip)
        return jsonify({"status": "error", "message": str(e)}), 500


# ─────────────────────────────────────────────
# HEALTH CHECK  (useful for Render monitoring)
# ─────────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    try:
        conn, cur = get_db()
        cur.execute("SELECT 1")
        return jsonify({"status": "ok", "db": "connected",
                        "circuit": "biometric_auth_v2"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
