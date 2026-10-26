"""
Unit Test Suite for NexusTunnel (Project 2)
Tests:
  1. Service health check
  2. TLS 1.2/1.3 5-step handshake lifecycle & AES-128-GCM symmetric transmission
  3. SSH-2.0 5-step connection negotiation and authentication
  4. IPsec ESP Transport and Tunnel mode packet breakdown
"""

import unittest
from app import app


class NexusTunnelUnitTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_01_health_status(self):
        resp = self.client.get('/health')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("service"), "NexusTunnel")
        self.assertEqual(data.get("status"), "healthy")

    def test_02_tls_handshake_and_symmetric_transmission(self):
        # 1. Init
        init_res = self.client.post('/api/tls/init')
        self.assertEqual(init_res.status_code, 200)
        sid = init_res.get_json()["session_id"]

        # Step 1: Client Hello
        s1 = self.client.post('/api/tls/step/1', json={"session_id": sid})
        self.assertEqual(s1.status_code, 200)
        self.assertEqual(s1.get_json()["step"], 1)

        # Step 2: Server Hello
        s2 = self.client.post('/api/tls/step/2', json={
            "session_id": sid,
            "cipher_suite": "TLS_AES_128_GCM_SHA256"
        })
        self.assertEqual(s2.status_code, 200)
        self.assertEqual(s2.get_json()["step"], 2)

        # Step 3: Client Key Exchange
        s3 = self.client.post('/api/tls/step/3', json={"session_id": sid})
        self.assertEqual(s3.status_code, 200)
        self.assertEqual(s3.get_json()["step"], 3)

        # Step 4: Key Generation
        s4 = self.client.post('/api/tls/step/4', json={"session_id": sid})
        self.assertEqual(s4.status_code, 200)
        self.assertIn("client_write_key", s4.get_json()["details"]["derived_keys"])

        # Step 5: Finished
        s5 = self.client.post('/api/tls/step/5', json={"session_id": sid})
        self.assertEqual(s5.status_code, 200)
        self.assertEqual(s5.get_json()["step"], 5)

        # Test symmetric transmission over tunnel
        tx_res = self.client.post('/api/tls/send-data', json={
            "session_id": sid,
            "message": "AegisOps Classified Data Stream"
        })
        self.assertEqual(tx_res.status_code, 200)
        tx_data = tx_res.get_json()
        self.assertIn("symmetric_ciphertext_hex", tx_data)
        self.assertEqual(tx_data["cipher"], "AES-128-GCM")

    def test_03_ssh_handshake_lifecycle(self):
        init_res = self.client.post('/api/ssh/init')
        self.assertEqual(init_res.status_code, 200)
        sid = init_res.get_json()["session_id"]

        for step_idx in range(1, 6):
            res = self.client.post(f'/api/ssh/step/{step_idx}', json={
                "session_id": sid,
                "username": "v_officer",
                "auth_method": "publickey"
            })
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.get_json()["step"], step_idx)

    def test_04_ipsec_esp_modes(self):
        # Transport mode
        t_res = self.client.post('/api/ipsec/analyze', json={"mode": "transport"})
        self.assertEqual(t_res.status_code, 200)
        self.assertEqual(len(t_res.get_json()["elements"]), 5)

        # Tunnel mode
        tun_res = self.client.post('/api/ipsec/analyze', json={"mode": "tunnel"})
        self.assertEqual(tun_res.status_code, 200)
        self.assertEqual(len(tun_res.get_json()["elements"]), 5)


if __name__ == "__main__":
    unittest.main()
