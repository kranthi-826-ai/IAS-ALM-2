"""
Unit Test Suite for Citadel Defense (Project 3)
Tests:
  1. Service health check
  2. Firewall policy CRUD operations and packet inspection
  3. Signature-based IDS scenarios (SSH Brute Force, Telnet detection)
  4. Statistical Anomaly detection via 3-sigma Gaussian deviation (SYN Flood)
"""

import unittest
from app import app, init_db


class CitadelDefenseUnitTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        init_db()

    def test_01_health_status(self):
        resp = self.client.get('/health')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("service"), "Citadel Defense")
        self.assertEqual(data.get("status"), "healthy")

    def test_02_firewall_rule_operations_and_packet_inspection(self):
        # 1. List rules
        res = self.client.get('/api/firewall/rules')
        self.assertEqual(res.status_code, 200)
        rules = res.get_json()["rules"]
        self.assertGreater(len(rules), 0)

        # 2. Add custom rule
        new_rule = {
            "name": "Drop Insecure MongoDB",
            "source_ip": "ANY",
            "dest_ip": "ANY",
            "protocol": "TCP",
            "port": 27017,
            "action": "BLOCK",
            "priority": 12
        }
        add_res = self.client.post('/api/firewall/rules', json=new_rule)
        self.assertEqual(add_res.status_code, 201)
        rule_id = add_res.get_json()["rule_id"]

        # 3. Inspect packet matching new rule
        inspect_res = self.client.post('/api/firewall/inspect', json={
            "source_ip": "10.10.10.10",
            "dest_ip": "10.0.0.5",
            "protocol": "TCP",
            "port": 27017
        })
        self.assertEqual(inspect_res.status_code, 200)
        self.assertEqual(inspect_res.get_json()["decision"], "BLOCK")

        # 4. Delete rule
        del_res = self.client.delete(f'/api/firewall/rules/{rule_id}')
        self.assertEqual(del_res.status_code, 200)

    def test_03_signature_ids_alerts(self):
        # Clear alerts
        self.client.delete('/api/ids/alerts')

        # Trigger SSH Brute Force
        bf_res = self.client.post('/api/ids/traffic/generate', json={"scenario": "ssh_bruteforce"})
        self.assertEqual(bf_res.status_code, 200)
        self.assertGreater(len(bf_res.get_json()["alerts_triggered"]), 0)

        # Trigger Insecure Telnet
        tel_res = self.client.post('/api/ids/traffic/generate', json={"scenario": "telnet_insecure"})
        self.assertEqual(tel_res.status_code, 200)
        self.assertGreater(len(tel_res.get_json()["alerts_triggered"]), 0)

        # Verify alerts stored
        alerts_res = self.client.get('/api/ids/alerts')
        self.assertEqual(alerts_res.status_code, 200)
        self.assertGreater(len(alerts_res.get_json()["alerts"]), 0)

    def test_04_statistical_anomaly_syn_flood(self):
        # Generate SYN flood
        flood_res = self.client.post('/api/ids/traffic/generate', json={"scenario": "syn_flood"})
        self.assertEqual(flood_res.status_code, 200)
        metrics = flood_res.get_json()["metrics"]
        self.assertTrue(metrics["is_anomaly"])
        self.assertGreater(metrics["z_score"], 3.0)

        # Verify metrics summary endpoint
        metrics_res = self.client.get('/api/ids/metrics')
        self.assertEqual(metrics_res.status_code, 200)
        self.assertIn("threshold_3sigma", metrics_res.get_json())


if __name__ == "__main__":
    unittest.main()
