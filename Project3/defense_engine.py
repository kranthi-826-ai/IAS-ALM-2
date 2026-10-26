"""
Citadel Defense :: Core Security Operations Engine
Implements Rule-Based Firewall packet filtering with Bastion Host isolation,
Signature-based Intrusion Detection, and 3-Sigma Gaussian Statistical Anomaly Detection.
"""

import time
import random
from datetime import datetime, timezone
from collections import deque
from typing import List, Dict, Any, Optional

import numpy as np
import pandas as pd


class FirewallEngine:
    """Evaluates packet streams against priority-ordered firewall rules with CIDR support."""

    @staticmethod
    def match_ip_pattern(rule_ip: str, packet_ip: str) -> bool:
        if rule_ip == "ANY" or packet_ip == "ANY":
            return True
        if "/" in rule_ip:
            # Subnet CIDR match (e.g. 192.168.1.0/24)
            prefix = rule_ip.split("/")[0].rsplit(".", 1)[0]
            return packet_ip.startswith(prefix)
        return rule_ip.strip() == packet_ip.strip()

    @classmethod
    def evaluate_packet(cls, rules: List[Dict[str, Any]], packet: Dict[str, Any], bastion_cfg: Dict[str, Any]) -> Dict[str, Any]:
        src_ip = packet.get("source_ip", "")
        dst_ip = packet.get("dest_ip", "")
        proto = packet.get("protocol", "TCP").upper()
        port = packet.get("port")
        direction = packet.get("direction", "INBOUND").upper()

        matched_rule = None
        action = "BLOCK"
        reason = "Default Implicit Deny Policy"

        for r in rules:
            if r.get("direction") != "ANY" and r.get("direction") != direction:
                continue
            if r.get("protocol") != "ANY" and r.get("protocol") != proto:
                continue
            if r.get("port") is not None and port is not None and int(r.get("port")) != int(port):
                continue
            if not cls.match_ip_pattern(r.get("source_ip", "ANY"), src_ip):
                continue
            if not cls.match_ip_pattern(r.get("dest_ip", "ANY"), dst_ip):
                continue

            matched_rule = r
            action = r.get("action", "BLOCK")
            reason = f"Matched Firewall Policy #{r.get('id')} [{r.get('name')}] (Priority: {r.get('priority')})"
            break

        is_bastion = (dst_ip == bastion_cfg.get("ip"))

        return {
            "packet": {
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "protocol": proto,
                "port": port,
                "direction": direction
            },
            "decision": action,
            "is_bastion_targeted": is_bastion,
            "matched_rule": matched_rule,
            "reason": reason
        }


class IntrusionDetectionEngine:
    """Hybrid signature & 3-sigma statistical anomaly intrusion detection system."""

    def __init__(self):
        self.packet_buffer = deque(maxlen=250)
        self.failed_auth_tracker = {}  # {ip: [timestamps]}
        self.rate_history = deque(maxlen=60)

        # Baseline generation (Gaussian normal: mean=12.5, std=2.4)
        np.random.seed(108)
        initial_samples = list(np.random.normal(loc=12.5, scale=2.4, size=45))
        for val in initial_samples:
            self.rate_history.append(max(2.0, round(float(val), 1)))

    def generate_scenario(self, scenario: str, src_ip: str, dst_ip: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
        current_epoch = time.time()
        packets = []
        alerts = []

        if scenario == "normal":
            for _ in range(5):
                p = random.choice([80, 443])
                pkt = {
                    "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                    "source_ip": src_ip,
                    "dest_ip": dst_ip,
                    "protocol": "TCP",
                    "port": p,
                    "payload": "GET /api/v2/secure-dashboard HTTP/1.1",
                    "status": "NORMAL"
                }
                packets.append(pkt)
                self.packet_buffer.append(pkt)
            self.rate_history.append(round(random.uniform(9.5, 14.2), 1))

        elif scenario == "ssh_bruteforce":
            if src_ip not in self.failed_auth_tracker:
                self.failed_auth_tracker[src_ip] = []

            for attempt in range(6):
                self.failed_auth_tracker[src_ip].append(current_epoch)
                pkt = {
                    "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                    "source_ip": src_ip,
                    "dest_ip": dst_ip,
                    "protocol": "TCP",
                    "port": 22,
                    "payload": f"SSH-2.0 auth failure: invalid credential trial #{attempt + 1}",
                    "status": "SUSPICIOUS"
                }
                packets.append(pkt)
                self.packet_buffer.append(pkt)

            recent_failures = [t for t in self.failed_auth_tracker[src_ip] if current_epoch - t <= 60]
            if len(recent_failures) >= 5:
                alerts.append({
                    "alert_type": "RULE_BASED",
                    "severity": "HIGH",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "port": 22,
                    "protocol": "TCP",
                    "rule_name": "SSH Brute-Force Signature Detection",
                    "message": f"Rule Alert: {len(recent_failures)} failed SSH login attempts in <60s from {src_ip}",
                    "details": f"Signature threshold triggered (>= 5 attempts). Host {src_ip} targeting SSH port 22."
                })
            self.rate_history.append(round(random.uniform(15.0, 19.5), 1))

        elif scenario == "telnet_insecure":
            pkt = {
                "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "protocol": "TCP",
                "port": 23,
                "payload": "TELNET IAC DO SUPPRESS-LOCAL-ECHO",
                "status": "INSECURE"
            }
            packets.append(pkt)
            self.packet_buffer.append(pkt)

            alerts.append({
                "alert_type": "RULE_BASED",
                "severity": "MEDIUM",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "port": 23,
                "protocol": "TCP",
                "rule_name": "Insecure Protocol Detected (Telnet Port 23)",
                "message": f"Rule Alert: Cleartext Telnet connection attempted on port 23 from {src_ip}",
                "details": "Telnet communicates in plaintext and violates zero-trust perimeter defense."
            })

        elif scenario == "port_scan":
            scanned_ports = [21, 22, 23, 25, 80, 110, 443, 3389, 8080]
            for target_port in scanned_ports:
                pkt = {
                    "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                    "source_ip": src_ip,
                    "dest_ip": dst_ip,
                    "protocol": "TCP",
                    "port": target_port,
                    "payload": "SYN Stealth Probe [TCP Flag: SYN]",
                    "status": "RECONNAISSANCE"
                }
                packets.append(pkt)
                self.packet_buffer.append(pkt)

            alerts.append({
                "alert_type": "RULE_BASED",
                "severity": "HIGH",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "port": None,
                "protocol": "TCP",
                "rule_name": "Multi-Port Reconnaissance Scan",
                "message": f"Rule Alert: Reconnaissance Port Scan detected from {src_ip} ({len(scanned_ports)} ports targeted)",
                "details": f"Sequential probes directed across ports: {scanned_ports}."
            })
            self.rate_history.append(round(random.uniform(22.0, 27.5), 1))

        elif scenario == "syn_flood":
            volumetric_rate = 58.5
            for _ in range(12):
                pkt = {
                    "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                    "source_ip": src_ip,
                    "dest_ip": dst_ip,
                    "protocol": "TCP",
                    "port": 80,
                    "payload": "SYN Flood Datagram [SYN-ACK Unacknowledged]",
                    "status": "ANOMALY"
                }
                packets.append(pkt)
                self.packet_buffer.append(pkt)
            self.rate_history.append(volumetric_rate)

        # ---------------- Statistical Anomaly 3-Sigma Evaluation ----------------
        series = pd.Series(list(self.rate_history))
        mean_val = float(series.mean())
        std_val = float(series.std()) if len(series) > 1 else 1.0
        latest_val = float(self.rate_history[-1]) if self.rate_history else mean_val
        threshold_3sigma = mean_val + 3.0 * std_val

        is_anomaly = (latest_val > threshold_3sigma and std_val > 0)
        z_score = round((latest_val - mean_val) / (std_val if std_val > 0 else 1.0), 2)

        if is_anomaly:
            alerts.append({
                "alert_type": "STATISTICAL_ANOMALY",
                "severity": "CRITICAL",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "port": 80,
                "protocol": "TCP",
                "rule_name": "Statistical Anomaly Engine (3-Sigma Deviation)",
                "message": f"Statistical Anomaly Alert: Packet rate {latest_val} pkts/sec exceeds 3-sigma threshold ({round(threshold_3sigma, 2)}) [Z-Score = {z_score}]",
                "details": f"Observed rate {latest_val} pkts/s vs Baseline mean {round(mean_val, 2)} pkts/s (std: {round(std_val, 2)}). Z-score: {z_score}."
            })

        metrics = {
            "latest_rate": latest_val,
            "mean": round(mean_val, 2),
            "std_dev": round(std_val, 2),
            "threshold_3sigma": round(threshold_3sigma, 2),
            "z_score": z_score,
            "is_anomaly": is_anomaly
        }

        return packets, alerts, metrics

    def compute_summary_metrics(self) -> Dict[str, Any]:
        series = pd.Series(list(self.rate_history))
        mean_val = float(series.mean()) if len(series) > 0 else 12.5
        std_val = float(series.std()) if len(series) > 1 else 2.4
        threshold = round(mean_val + 3.0 * std_val, 2)

        history_points = [
            {"index": idx + 1, "rate": round(r, 1), "threshold": threshold, "mean": round(mean_val, 1)}
            for idx, r in enumerate(self.rate_history)
        ]

        return {
            "current_mean": round(mean_val, 2),
            "current_std": round(std_val, 2),
            "threshold_3sigma": threshold,
            "total_packets_recorded": len(self.packet_buffer),
            "history": history_points,
            "recent_traffic": list(self.packet_buffer)[-10:]
        }


THREAT_ENCYCLOPEDIA_ARTICLES = [
    {
        "id": "file-infector",
        "category": "Viruses",
        "title": "File Infector Viruses",
        "summary": "Parasitic viral code that attaches directly to executable host binaries (.exe, .elf, .dll).",
        "mechanism": "Upon program execution, malicious payload executes initial bootstrapping, remains memory-resident, and modifies other system binaries prior to passing control back to the host program.",
        "historical_examples": ["Jerusalem Virus (1987)", "Cascade Virus", "CIH / Chernobyl (1998)"],
        "countermeasures": [
            "Signature-based and heuristic file integrity scanning",
            "Cryptographic hashing (SHA-256) and binary tripwires",
            "Enforced code signing policies and execution restriction (AppLocker)"
        ]
    },
    {
        "id": "boot-sector",
        "category": "Viruses",
        "title": "Boot Sector Viruses",
        "summary": "Viruses targeting the Master Boot Record (MBR) or partition boot sectors.",
        "mechanism": "Injects viral payload into boot sectors so malware loads into kernel memory before operating system security controls or antivirus engines initialize.",
        "historical_examples": ["Brain (1986 - first PC virus)", "Stoned", "Michelangelo Virus"],
        "countermeasures": [
            "UEFI Secure Boot with hardware TPM verification",
            "Hardware write-protection on critical boot partitions",
            "Disabling boot from untrusted removable media in BIOS"
        ]
    },
    {
        "id": "macro-viruses",
        "category": "Viruses",
        "title": "Macro Viruses",
        "summary": "Malicious code embedded in office documents using macro languages (e.g. VBA).",
        "mechanism": "Executes automatically when user opens document or enables macros, abusing scripting capabilities to spawn PowerShell payloads and download second-stage implants.",
        "historical_examples": ["Concept (1995)", "Melissa Virus (1999)"],
        "countermeasures": [
            "Default blocking of macros in files originating from the internet",
            "Protected View document sandboxing",
            "Application and script execution auditing"
        ]
    },
    {
        "id": "network-worms",
        "category": "Worms",
        "title": "Self-Propagating Network Worms",
        "summary": "Autonomous malware capable of replicating across networked systems without human intervention.",
        "mechanism": "Actively scans IP subnets for vulnerable unpatched listening services (e.g. SMBv1, MS-RPC), delivers remote code execution exploits, and triggers automated self-propagation.",
        "historical_examples": ["Morris Worm (1988)", "Code Red (2001)", "SQL Slammer (2003)", "WannaCry / EternalBlue (2017)"],
        "countermeasures": [
            "Perimeter and internal micro-segmentation firewalls",
            "Immediate security patch deployment for zero-day vulnerabilities",
            "IDS/IPS protocol inspection blocking unauthenticated RPC/SMB traffic"
        ]
    },
    {
        "id": "bastion-defense",
        "category": "Perimeter Defense",
        "title": "Bastion Host Architecture & Countermeasures",
        "summary": "Hardened, highly scrutinized proxy gateway exposed to untrusted networks.",
        "mechanism": "Acts as the single strictly controlled ingress point for administrative access. Eliminates direct access to internal subnets, enforces multi-factor authentication, and records full audit logs.",
        "historical_examples": ["Dual-Homed Firewalls", "Screened Host Architecture", "Cloud Jump-Boxes"],
        "countermeasures": [
            "Restrict management subnet access via IP whitelisting",
            "Aggressive OS hardening: disable all unnecessary daemons, compilers, and ports",
            "Centralized real-time log forwarding to SIEM with strict anomaly alerts"
        ]
    }
]
