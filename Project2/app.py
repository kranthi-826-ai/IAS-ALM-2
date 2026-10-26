"""
NexusTunnel :: Project 2 REST API Server (Port 5002)
Interactive Transport Layer Security (TLS/SSL) Handshake Simulator,
SSH-2.0 Protocol Negotiation Engine, and IPsec ESP Datagram Inspector.
"""

import uuid
from flask import Flask, request, jsonify
from flask_cors import CORS

from tunnel_engine import (
    TLSProtocolSession,
    SSHProtocolSession,
    IPSecESPAnalyzer
)

app = Flask(__name__)
CORS(app)

tls_active_sessions = {}
ssh_active_sessions = {}


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "service": "NexusTunnel",
        "project": "Project2",
        "version": "2.4.0",
        "active_tls_sessions": len(tls_active_sessions),
        "active_ssh_sessions": len(ssh_active_sessions)
    })


# ----------------- 1. TLS/SSL HANDSHAKE SIMULATION -----------------
@app.route("/api/tls/init", methods=["POST"])
def tls_initialize():
    session_id = str(uuid.uuid4())[:8]
    session = TLSProtocolSession(session_id)
    tls_active_sessions[session_id] = session

    return jsonify({
        "session_id": session_id,
        "status": "Initialized",
        "cipher_suites_available": session.AVAILABLE_CIPHERS,
        "message": "TLS session allocated. Proceed with Step 1 (Client Hello)."
    })


@app.route("/api/tls/step/<int:step_num>", methods=["POST"])
def tls_step(step_num):
    data = request.get_json() or {}
    session_id = data.get("session_id")
    session = tls_active_sessions.get(session_id)

    if not session:
        return jsonify({"error": "TLS Session not found. Please initialize session first."}), 404

    try:
        step_result = session.execute_step(step_num, data)
        return jsonify(step_result)
    except ValueError as val_err:
        return jsonify({"error": str(val_err)}), 400
    except Exception as err:
        return jsonify({"error": f"Internal execution failure: {str(err)}"}), 500


@app.route("/api/tls/send-data", methods=["POST"])
def tls_transmit_data():
    data = request.get_json() or {}
    session_id = data.get("session_id")
    plaintext = data.get("message", "GET /api/telemetry HTTP/1.1\r\nHost: nexustunnel.net\r\n\r\n")

    session = tls_active_sessions.get(session_id)
    if not session:
        return jsonify({"error": "TLS Session not found."}), 404

    try:
        result = session.transmit_data(plaintext)
        return jsonify(result)
    except ValueError as val_err:
        return jsonify({"error": str(val_err)}), 400
    except Exception as err:
        return jsonify({"error": str(err)}), 500


# ----------------- 2. SSH-2.0 CONNECTION SIMULATION -----------------
@app.route("/api/ssh/init", methods=["POST"])
def ssh_initialize():
    session_id = str(uuid.uuid4())[:8]
    session = SSHProtocolSession(session_id)
    ssh_active_sessions[session_id] = session

    return jsonify({
        "session_id": session_id,
        "server_banner": session.server_version,
        "client_banner": session.client_version,
        "message": "SSH session context initialized. Ready for protocol negotiation."
    })


@app.route("/api/ssh/step/<int:step_num>", methods=["POST"])
def ssh_step(step_num):
    data = request.get_json() or {}
    session_id = data.get("session_id")
    session = ssh_active_sessions.get(session_id)

    if not session:
        return jsonify({"error": "SSH Session not found. Please initialize session first."}), 404

    try:
        step_result = session.execute_step(step_num, data)
        return jsonify(step_result)
    except ValueError as val_err:
        return jsonify({"error": str(val_err)}), 400
    except Exception as err:
        return jsonify({"error": f"Internal SSH failure: {str(err)}"}), 500


# ----------------- 3. IPSEC ESP ENCAPSULATION MODULE -----------------
@app.route("/api/ipsec/analyze", methods=["POST"])
def ipsec_analyze():
    data = request.get_json() or {}
    result = IPSecESPAnalyzer.dissect(data)
    return jsonify(result)


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5102))
    app.run(host="0.0.0.0", port=port, debug=True)
