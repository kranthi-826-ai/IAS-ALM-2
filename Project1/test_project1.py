"""
Unit Test Suite for AegisCrypt (Project 1)
Tests:
  1. Service health check
  2. Identity enrolment and X.509 CA certificate issuance
  3. RSA-2048 key generation, OAEP encryption/decryption, and PSS signing/verification
  4. Diffie-Hellman mathematical key agreement
  5. Elgamal digital signature generation and verification with SHA-512
"""

import unittest
from app import app, initialize_database


class AegisCryptUnitTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        initialize_database()

    def test_01_service_health(self):
        resp = self.client.get('/health')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("service"), "AegisCrypt")
        self.assertEqual(data.get("status"), "healthy")

    def test_02_pki_enrollment_and_certificate_download(self):
        credentials = {
            "user_handle": "v_analyst",
            "password": "VPassword#2026",
            "organization": "AegisOps Security Division"
        }
        reg_resp = self.client.post('/api/auth/register', json=credentials)
        self.assertIn(reg_resp.status_code, [201, 409])

        # Login verification
        login_resp = self.client.post('/api/auth/login', json=credentials)
        self.assertEqual(login_resp.status_code, 200)
        user_data = login_resp.get_json()
        self.assertIn("BEGIN CERTIFICATE", user_data["x509_certificate_pem"])
        self.assertIn("BEGIN PUBLIC KEY", user_data["public_key_pem"])
        self.assertIn("BEGIN PRIVATE KEY", user_data["private_key_pem"])

        # Certificate download endpoint
        cert_resp = self.client.get('/api/pki/download-cert/v_analyst')
        self.assertEqual(cert_resp.status_code, 200)
        self.assertIn(b"BEGIN CERTIFICATE", cert_resp.data)

    def test_03_rsa_oaep_and_pss_mechanisms(self):
        # 1. Generate fresh keypair
        gen_resp = self.client.get('/api/rsa/generate')
        self.assertEqual(gen_resp.status_code, 200)
        key_data = gen_resp.get_json()
        pub_pem = key_data["public_key_pem"]
        priv_pem = key_data["private_key_pem"]

        sample_text = "AegisOps Secure Cryptographic Directive :: 2026"

        # 2. RSA-OAEP Encryption
        enc_resp = self.client.post('/api/rsa/encrypt', json={
            "public_key_pem": pub_pem,
            "plaintext": sample_text
        })
        self.assertEqual(enc_resp.status_code, 200)
        ciphertext_b64 = enc_resp.get_json()["ciphertext_base64"]

        # 3. RSA-OAEP Decryption
        dec_resp = self.client.post('/api/rsa/decrypt', json={
            "private_key_pem": priv_pem,
            "ciphertext_base64": ciphertext_b64
        })
        self.assertEqual(dec_resp.status_code, 200)
        self.assertEqual(dec_resp.get_json()["plaintext"], sample_text)

        # 4. RSA-PSS Signing
        sign_resp = self.client.post('/api/rsa/sign', json={
            "private_key_pem": priv_pem,
            "message": sample_text
        })
        self.assertEqual(sign_resp.status_code, 200)
        sig_b64 = sign_resp.get_json()["signature_base64"]

        # 5. RSA-PSS Verification
        verify_resp = self.client.post('/api/rsa/verify', json={
            "public_key_pem": pub_pem,
            "message": sample_text,
            "signature_base64": sig_b64
        })
        self.assertEqual(verify_resp.status_code, 200)
        self.assertTrue(verify_resp.get_json()["is_valid"])

    def test_04_diffie_hellman_agreement(self):
        setup_resp = self.client.post('/api/dh/setup', json={"mode": "small"})
        self.assertEqual(setup_resp.status_code, 200)

        # Run step 4 computation
        calc_resp = self.client.post('/api/dh/calculate-step', json={
            "step": 4,
            "p": 353,
            "g": 3,
            "alice_private": 97,
            "bob_private": 233
        })
        self.assertEqual(calc_resp.status_code, 200)
        dh_data = calc_resp.get_json()
        self.assertTrue(dh_data["match"])
        self.assertEqual(
            dh_data["alice_computation"]["shared_secret"],
            dh_data["bob_computation"]["shared_secret"]
        )

    def test_05_elgamal_digital_signature_with_sha512(self):
        # 1. Keygen
        keygen_resp = self.client.get('/api/elgamal/keygen')
        self.assertEqual(keygen_resp.status_code, 200)
        keys = keygen_resp.get_json()

        test_msg = "Authorized wire transfer for security infrastructure"

        # 2. Hash
        hash_resp = self.client.post('/api/elgamal/hash', json={"message": test_msg})
        self.assertEqual(hash_resp.status_code, 200)
        self.assertEqual(len(hash_resp.get_json()["sha512_hex"]), 128)

        # 3. Sign
        sign_resp = self.client.post('/api/elgamal/sign', json={
            "message": test_msg,
            "private_key_x": keys["private_key_x"],
            "p": keys["p"],
            "g": keys["g"]
        })
        self.assertEqual(sign_resp.status_code, 200)
        sig = sign_resp.get_json()

        # 4. Verify
        verify_resp = self.client.post('/api/elgamal/verify', json={
            "message": test_msg,
            "signature_r": sig["signature_r"],
            "signature_s": sig["signature_s"],
            "public_key_y": keys["public_key_y"],
            "p": keys["p"],
            "g": keys["g"]
        })
        self.assertEqual(verify_resp.status_code, 200)
        self.assertTrue(verify_resp.get_json()["is_valid"])


if __name__ == "__main__":
    unittest.main()
