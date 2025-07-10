from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import psycopg2
import json
import os
import hashlib
import time
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import subprocess

load_dotenv()

app = Flask(__name__)
CORS(app)

# Load encryption keys for onion routing
KEY1 = os.getenv("ONION_KEY1").encode()
KEY2 = os.getenv("ONION_KEY2").encode()
KEY3 = os.getenv("ONION_KEY3").encode()

fernet1 = Fernet(KEY1)
fernet2 = Fernet(KEY2)
fernet3 = Fernet(KEY3)

# PostgreSQL DB config
DB_URL = os.getenv("DATABASE_URL")

# Onion encryption
def onion_encrypt(data: str) -> str:
    step1 = fernet1.encrypt(data.encode())
    step2 = fernet2.encrypt(step1)
    step3 = fernet3.encrypt(step2)
    return step3.decode()

# Onion decryption
def onion_decrypt(data: str) -> str:
    step1 = fernet3.decrypt(data.encode())
    step2 = fernet2.decrypt(step1)
    step3 = fernet1.decrypt(step2)
    return step3.decode()

# Home page
@app.route('/')
def index():
    return render_template('index.html')

# Validate page
@app.route('/validate_page')
def validate_page():
    return render_template('validate.html')

# User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    user_id = data.get('user_id')
    name = data.get('name')
    dob = data.get('dob')
    country = data.get('country')
    fingerprint_template = data.get('fingerprint_template')

    if not all([user_id, name, dob, country, fingerprint_template]):
        return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400

    try:
        conn = psycopg2.connect(DB_URL)
        cur = conn.cursor()

        fingerprint_hash = hashlib.sha256(fingerprint_template.encode()).hexdigest()
        encrypted_hash = onion_encrypt(fingerprint_hash)

        cur.execute("""
            INSERT INTO users (user_id, name, dob, country, fingerprint_hash)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (user_id) DO NOTHING
        """, (user_id, name, dob, country, encrypted_hash))

        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'status': 'success', 'message': 'User registered'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Generate ZKP
@app.route('/generate-proof', methods=['POST'])
def generate_proof():
    data = request.get_json()
    user_id = data.get('user_id')

    try:
        conn = psycopg2.connect(DB_URL)
        cur = conn.cursor()
        cur.execute("SELECT fingerprint_hash FROM users WHERE user_id = %s", (user_id,))
        result = cur.fetchone()
        cur.close()
        conn.close()

        if not result:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        encrypted_hash = result[0]
        fingerprint_hash = onion_decrypt(encrypted_hash)

        # Store fingerprint hash to input.json (for witness generation)
        with open("input.json", "w") as f:
            json.dump({"fingerprintHash": int(fingerprint_hash, 16)}, f)

        subprocess.run(["node", "generate_witness.js"])
        subprocess.run(["node", "generate_proof.js"])

        with open("zkp.json") as f:
            zkp_data = json.load(f)

        return jsonify({'status': 'success', 'zkp': zkp_data})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Get ZKP via OTP (extension)
@app.route('/get_zkp', methods=['POST'])
def get_zkp():
    data = request.get_json()
    user_id = data.get('user_id')
    otp = data.get('otp')

    if not user_id or not otp:
        return jsonify({'status': 'error', 'message': 'Missing fields'}), 400

    # You can add OTP expiry or validation if needed here

    return generate_proof()

if __name__ == '__main__':
    app.run(debug=True)
