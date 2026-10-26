"""
Citadel Defense :: Project 3 REST API Server (Port 5003)
Firewall Rule Manager, Bastion Host Perimeter Controller,
Rule-based & 3-Sigma Statistical Anomaly Intrusion Detection Engine.
"""

import os
import random
import sqlite3
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from flask_cors import CORS

from defense_engine import (
    FirewallEngine,
    IntrusionDetectionEngine,
    THREAT_ENCYCLOPEDIA_ARTICLES
)

app = Flask(__name__)
CORS(app)

DATABASE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "citadel.db")
ids_engine = IntrusionDetectionEngine()

bastion_state = {
    "enabled": True,
    "ip": "10.0.0.5",
    "name": "Citadel-Bastion-01",
    "allowed_management_subnet": "192.168.1.0/24",
    "monitored_ports": [22, 443]
}


def get_db():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS firewall_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        direction TEXT DEFAULT 'INBOUND',
        source_ip TEXT NOT NULL,
        dest_ip TEXT NOT NULL,
        protocol TEXT NOT NULL,
        port INTEGER,
        action TEXT NOT NULL,
        priority INTEGER DEFAULT 100,
        is_bastion_rule INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS ids_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        alert_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        dest_ip TEXT NOT NULL,
        port INTEGER,
        protocol TEXT,
        rule_name TEXT,
        message TEXT NOT NULL,
        details TEXT
    )
    """)

    # Seed initial rules if empty
    c.execute("SELECT COUNT(*) AS total FROM firewall_rules")
    if c.fetchone()["total"] == 0:
        initial_rules = [
            ("Block Known Threat Actor", "INBOUND", "198.51.100.44", "ANY", "ANY", None, "BLOCK", 10, 0),
            ("Drop Cleartext Telnet", "INBOUND", "ANY", "ANY", "TCP", 23, "BLOCK", 20, 0),
            ("Allow Bastion Admin SSH", "INBOUND", "192.168.1.0/24", "10.0.0.5", "TCP", 22, "ALLOW", 30, 1),
            ("Block Direct Host SSH (Bypass Attempt)", "INBOUND", "ANY", "10.0.0.10", "TCP", 22, "BLOCK", 40, 0),
            ("Permit Web HTTP", "INBOUND", "ANY", "ANY", "TCP", 80, "ALLOW", 50, 0),
            ("Permit Web HTTPS", "INBOUND", "ANY", "ANY", "TCP", 443, "ALLOW", 60, 0),
            ("Default Drop Policy", "INBOUND", "ANY", "ANY", "ANY", None, "BLOCK", 999, 0),
        ]
        c.executemany("""
            INSERT INTO firewall_rules (name, direction, source_ip, dest_ip, protocol, port, action, priority, is_bastion_rule)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, initial_rules)

    conn.commit()
    conn.close()


init_db()


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "service": "Citadel Defense",
        "project": "Project3",
        "version": "2.4.0",
        "bastion_ip": bastion_state["ip"]
    })


# ----------------- 1. FIREWALL RULE MANAGER -----------------
@app.route("/api/firewall/rules", methods=["GET"])
def list_rules():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM firewall_rules ORDER BY priority ASC, id ASC")
    rules = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify({"rules": rules, "bastion": bastion_state})


@app.route("/api/firewall/rules", methods=["POST"])
def create_rule():
    payload = request.get_json() or {}
    name = payload.get("name", "Custom Rule").strip()
    direction = payload.get("direction", "INBOUND").upper()
    source_ip = payload.get("source_ip", "ANY").strip()
    dest_ip = payload.get("dest_ip", "ANY").strip()
    protocol = payload.get("protocol", "TCP").upper()
    port = payload.get("port")
    port = int(port) if port is not None and str(port).isdigit() else None
    action = payload.get("action", "BLOCK").upper()
    priority = int(payload.get("priority", 50))
    is_bastion = 1 if payload.get("is_bastion_rule") else 0

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO firewall_rules (name, direction, source_ip, dest_ip, protocol, port, action, priority, is_bastion_rule)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (name, direction, source_ip, dest_ip, protocol, port, action, priority, is_bastion))
    new_id = c.lastrowid
    conn.commit()
    conn.close()

    return jsonify({"message": "Firewall policy added successfully", "rule_id": new_id}), 201


@app.route("/api/firewall/rules/<int:rule_id>", methods=["PUT"])
def update_rule(rule_id):
    payload = request.get_json() or {}
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        UPDATE firewall_rules SET
            name = COALESCE(?, name),
            source_ip = COALESCE(?, source_ip),
            dest_ip = COALESCE(?, dest_ip),
            protocol = COALESCE(?, protocol),
            port = ?,
            action = COALESCE(?, action),
            priority = COALESCE(?, priority),
            is_bastion_rule = COALESCE(?, is_bastion_rule)
        WHERE id = ?
    """, (
        payload.get("name"),
        payload.get("source_ip"),
        payload.get("dest_ip"),
        payload.get("protocol"),
        int(payload.get("port")) if payload.get("port") else None,
        payload.get("action"),
        payload.get("priority"),
        payload.get("is_bastion_rule"),
        rule_id
    ))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Rule #{rule_id} updated successfully"})


@app.route("/api/firewall/rules/<int:rule_id>", methods=["DELETE"])
def delete_rule(rule_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM firewall_rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Rule #{rule_id} deleted successfully"})


@app.route("/api/firewall/bastion", methods=["POST"])
def update_bastion():
    payload = request.get_json() or {}
    bastion_state["ip"] = payload.get("ip", bastion_state["ip"])
    bastion_state["name"] = payload.get("name", bastion_state["name"])
    bastion_state["enabled"] = bool(payload.get("enabled", True))
    bastion_state["allowed_management_subnet"] = payload.get("allowed_management_subnet", bastion_state["allowed_management_subnet"])
    return jsonify({"message": "Bastion host configuration updated", "bastion": bastion_state})


@app.route("/api/firewall/inspect", methods=["POST"])
def inspect_packet():
    data = request.get_json() or {}
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM firewall_rules ORDER BY priority ASC, id ASC")
    rules = [dict(r) for r in c.fetchall()]
    conn.close()

    result = FirewallEngine.evaluate_packet(rules, data, bastion_state)
    return jsonify(result)


# ----------------- 2. IDS ENGINE & TELEMETRY -----------------
def insert_alerts(alert_list):
    if not alert_list:
        return
    conn = get_db()
    c = conn.cursor()
    now_stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    for a in alert_list:
        c.execute("""
            INSERT INTO ids_alerts (timestamp, alert_type, severity, source_ip, dest_ip, port, protocol, rule_name, message, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            now_stamp,
            a.get("alert_type", "RULE_BASED"),
            a.get("severity", "MEDIUM"),
            a.get("src_ip", "0.0.0.0"),
            a.get("dst_ip", "0.0.0.0"),
            a.get("port"),
            a.get("protocol", "TCP"),
            a.get("rule_name", "Security Engine"),
            a.get("message", ""),
            a.get("details", "")
        ))
    conn.commit()
    conn.close()


@app.route("/api/ids/alerts", methods=["GET"])
def get_alerts():
    limit = int(request.args.get("limit", 50))
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM ids_alerts ORDER BY id DESC LIMIT ?", (limit,))
    alerts = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify({"alerts": alerts, "total": len(alerts)})


@app.route("/api/ids/alerts", methods=["DELETE"])
def clear_alerts():
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM ids_alerts")
    conn.commit()
    conn.close()
    return jsonify({"message": "IDS security alerts cleared successfully"})


@app.route("/api/ids/traffic/generate", methods=["POST"])
def generate_traffic():
    data = request.get_json() or {}
    scenario = data.get("scenario", "normal")
    src_ip = data.get("source_ip", f"192.168.1.{random.randint(15, 240)}")
    dst_ip = data.get("dest_ip", "10.0.0.5")

    packets, alerts, metrics = ids_engine.generate_scenario(scenario, src_ip, dst_ip)
    insert_alerts(alerts)

    return jsonify({
        "scenario": scenario,
        "packets_generated": packets,
        "alerts_triggered": [a["message"] for a in alerts],
        "metrics": metrics
    })


@app.route("/api/ids/metrics", methods=["GET"])
def get_metrics():
    summary = ids_engine.compute_summary_metrics()
    return jsonify(summary)


# ----------------- 3. THREAT ENCYCLOPEDIA -----------------
@app.route("/api/threats", methods=["GET"])
def get_threats():
    return jsonify({"encyclopedia": THREAT_ENCYCLOPEDIA_ARTICLES})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5103))
    app.run(host="0.0.0.0", port=port, debug=True)
