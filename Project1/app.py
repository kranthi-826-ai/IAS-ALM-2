"""
AegisCrypt :: Project 1 REST API Server (Port 5001)
Advanced Asymmetric Cryptosystem, PKI Certificate Authority,
Diffie-Hellman Key Exchange Engine, and Elgamal/SHA-512 Digital Signatures.
"""

import os
import sqlite3
import hashlib
from flask import Flask, request, jsonify, Response
from flask_cors import CORS

from crypto_engine import (
    AsymmetricEngine,
    DiffieHellmanProtocol,
    ElgamalSignatureSystem
)

app = Flask(__name__)
CORS(app)

DATABASE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aegiscrypt.db")


def get_db_connection():
    """Returns a row-mapped SQLite database connection."""
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    """Initializes tables for user PKI identities and public credentials."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_handle TEXT UNIQUE NOT NULL,
        password_digest TEXT NOT NULL,
        public_key_pem TEXT NOT NULL,
        private_key_pem TEXT NOT NULL,
        x509_cert_pem TEXT,
        created_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()


initialize_database()


# ----------------- HEALTH & SYSTEM METRICS -----------------
@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "AegisCrypt",
        "project": "Project1",
        "version": "2.4.0",
        "engine": "cryptography.hazmat"
    })


# ----------------- 1. PKI & USER AUTHENTICATION -----------------
@app.route("/api/auth/register", methods=["POST"])
def register_user():
    payload = request.get_json() or {}
    user_handle = payload.get("username", "").strip() or payload.get("user_handle", "").strip()
    password = payload.get("password", "").strip()
    org_unit = payload.get("organization", "AegisOps PKI Authority")

    if not user_handle or not password:
        return jsonify({"error": "user_handle and password are required"}), 400

    pass_digest = hashlib.sha256(password.encode("utf-8")).hexdigest()

    try:
        priv_k, pub_k, priv_pem, pub_pem = AsymmetricEngine.generate_keypair(key_size=2048)
        cert_pem = AsymmetricEngine.issue_x509_certificate(
            priv_k, pub_k,
            subject_name=user_handle,
            ca_authority=org_unit
        )

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO user_credentials (user_handle, password_digest, public_key_pem, private_key_pem, x509_cert_pem)
            VALUES (?, ?, ?, ?, ?)
        """, (user_handle, pass_digest, pub_pem, priv_pem, cert_pem))
        conn.commit()
        conn.close()

        return jsonify({
            "message": "User cryptographic profile enrolled successfully",
            "username": user_handle,
            "user_handle": user_handle,
            "public_key_pem": pub_pem,
            "private_key_pem": priv_pem,
            "x509_certificate_pem": cert_pem,
            "pki_note": "AegisOps CA issued X.509 certificate with RSA-2048 identity binding."
        }), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": f"Identifier '{user_handle}' is already registered."}), 409
    except Exception as err:
        return jsonify({"error": str(err)}), 500


@app.route("/api/auth/login", methods=["POST"])
def login_user():
    payload = request.get_json() or {}
    user_handle = payload.get("username", "").strip() or payload.get("user_handle", "").strip()
    password = payload.get("password", "").strip()

    if not user_handle or not password:
        return jsonify({"error": "user_handle and password are required"}), 400

    pass_digest = hashlib.sha256(password.encode("utf-8")).hexdigest()

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM user_credentials WHERE user_handle = ? AND password_digest = ?",
        (user_handle, pass_digest)
    )
    record = cur.fetchone()
    conn.close()

    if not record:
        return jsonify({"error": "Authentication failed: invalid credentials"}), 401

    return jsonify({
        "message": "Authentication successful",
        "username": record["user_handle"],
        "user_handle": record["user_handle"],
        "public_key_pem": record["public_key_pem"],
        "private_key_pem": record["private_key_pem"],
        "x509_certificate_pem": record["x509_cert_pem"]
    })


@app.route("/api/users/list", methods=["GET"])
def list_enrolled_users():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, user_handle AS username, public_key_pem, x509_cert_pem AS x509_certificate_pem, created_timestamp AS created_at FROM user_credentials")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify({"users": rows})


@app.route("/api/pki/download-cert/<user_handle>", methods=["GET"])
def download_x509_cert(user_handle):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT x509_cert_pem FROM user_credentials WHERE user_handle = ?", (user_handle,))
    row = cur.fetchone()
    conn.close()

    if not row or not row["x509_cert_pem"]:
        return jsonify({"error": "Certificate not found for the requested entity"}), 404

    return Response(
        row["x509_cert_pem"],
        mimetype="application/x-x509-ca-cert",
        headers={"Content-Disposition": f"attachment; filename={user_handle}_aegis_cert.crt"}
    )


# ----------------- 2. RSA OPERATIONS (OAEP & PSS) -----------------
@app.route("/api/rsa/generate", methods=["GET"])
def rsa_generate_pair():
    _, _, priv_pem, pub_pem = AsymmetricEngine.generate_keypair(key_size=2048)
    return jsonify({
        "public_key_pem": pub_pem,
        "private_key_pem": priv_pem,
        "key_size": 2048,
        "format": "PKCS#8 Private / SubjectPublicKeyInfo Public"
    })


@app.route("/api/rsa/encrypt", methods=["POST"])
def rsa_encrypt_payload():
    payload = request.get_json() or {}
    pub_pem = payload.get("public_key_pem", "")
    plaintext = payload.get("plaintext", "")

    if not pub_pem or not plaintext:
        return jsonify({"error": "public_key_pem and plaintext are mandatory"}), 400

    try:
        result = AsymmetricEngine.encrypt_oaep(pub_pem, plaintext)
        return jsonify(result)
    except Exception as err:
        return jsonify({"error": f"Encryption error: {str(err)}"}), 400


@app.route("/api/rsa/decrypt", methods=["POST"])
def rsa_decrypt_payload():
    payload = request.get_json() or {}
    priv_pem = payload.get("private_key_pem", "")
    ciphertext_b64 = payload.get("ciphertext_base64", "")

    if not priv_pem or not ciphertext_b64:
        return jsonify({"error": "private_key_pem and ciphertext_base64 are mandatory"}), 400

    try:
        result = AsymmetricEngine.decrypt_oaep(priv_pem, ciphertext_b64)
        return jsonify(result)
    except Exception as err:
        return jsonify({"error": f"Decryption error: {str(err)}"}), 400


@app.route("/api/rsa/sign", methods=["POST"])
def rsa_sign_payload():
    payload = request.get_json() or {}
    priv_pem = payload.get("private_key_pem", "")
    message = payload.get("message", "")

    if not priv_pem or not message:
        return jsonify({"error": "private_key_pem and message are mandatory"}), 400

    try:
        result = AsymmetricEngine.sign_pss(priv_pem, message)
        return jsonify(result)
    except Exception as err:
        return jsonify({"error": f"Signing error: {str(err)}"}), 400


@app.route("/api/rsa/verify", methods=["POST"])
def rsa_verify_payload():
    payload = request.get_json() or {}
    pub_pem = payload.get("public_key_pem", "")
    message = payload.get("message", "")
    sig_b64 = payload.get("signature_base64", "")

    if not pub_pem or not message or not sig_b64:
        return jsonify({"error": "public_key_pem, message, and signature_base64 are required"}), 400

    result = AsymmetricEngine.verify_pss(pub_pem, message, sig_b64)
    return jsonify(result)


# ----------------- 3. DIFFIE-HELLMAN KEY AGREEMENT -----------------
@app.route("/api/dh/setup", methods=["POST"])
def dh_setup_parameters():
    data = request.get_json() or {}
    profile = data.get("mode", "small")
    custom_p = data.get("p")
    custom_g = data.get("g")

    result = DiffieHellmanProtocol.initialize_parameters(profile, custom_p, custom_g)
    return jsonify(result)


@app.route("/api/dh/calculate-step", methods=["POST"])
def dh_calculate_step():
    data = request.get_json() or {}
    step = int(data.get("step", 1))
    p = int(data.get("p", 353))
    g = int(data.get("g", 3))
    a = int(data.get("alice_private", 97))
    b = int(data.get("bob_private", 233))

    result = DiffieHellmanProtocol.execute_exchange_step(step, p, g, a, b)
    return jsonify(result)


# ----------------- 4. ELGAMAL DIGITAL SIGNATURE & SHA-512 -----------------
@app.route("/api/elgamal/keygen", methods=["GET"])
def elgamal_keygen():
    keys = ElgamalSignatureSystem.generate_keypair()
    return jsonify(keys)


@app.route("/api/elgamal/hash", methods=["POST"])
def elgamal_compute_hash():
    data = request.get_json() or {}
    message = data.get("message", "")
    result = ElgamalSignatureSystem.compute_sha512_digest(message)
    return jsonify(result)


@app.route("/api/elgamal/sign", methods=["POST"])
def elgamal_sign_message():
    data = request.get_json() or {}
    message = data.get("message", "")
    private_x = int(data.get("private_key_x", 0))
    p = int(data.get("p", ElgamalSignatureSystem.P_DEFAULT))
    g = int(data.get("g", ElgamalSignatureSystem.G_DEFAULT))

    if not message or not private_x:
        return jsonify({"error": "message and private_key_x are required"}), 400

    result = ElgamalSignatureSystem.sign_message(message, private_x, p, g)
    return jsonify(result)


@app.route("/api/elgamal/verify", methods=["POST"])
def elgamal_verify_message():
    data = request.get_json() or {}
    message = data.get("message", "")
    r = int(data.get("signature_r", 0))
    s = int(data.get("signature_s", 0))
    public_y = int(data.get("public_key_y", 0))
    p = int(data.get("p", ElgamalSignatureSystem.P_DEFAULT))
    g = int(data.get("g", ElgamalSignatureSystem.G_DEFAULT))

    if not message or not r or not s or not public_y:
        return jsonify({"error": "message, signature_r, signature_s, and public_key_y are required"}), 400

    result = ElgamalSignatureSystem.verify_signature(message, r, s, public_y, p, g)
    return jsonify(result)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5101))
    app.run(host="0.0.0.0", port=port, debug=True)
