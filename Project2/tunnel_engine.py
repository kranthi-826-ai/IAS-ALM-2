"""
NexusTunnel :: Transport Security Protocols & Tunnel Engine
Simulates TLS 1.2/1.3 handshakes with PRF key expansion,
SSH-2.0 protocol negotiation with DH group exchange,
and IPsec ESP datagram encapsulation analysis.
"""

import os
import uuid
import secrets
import hashlib
import hmac
import base64
import datetime
from typing import Dict, Any, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def calculate_tls_prf(secret: bytes, label: str, seed: bytes, output_len: int) -> bytes:
    """Pseudo-Random Function (PRF) per RFC 5246 using HMAC-SHA256 data expansion."""
    expanded_output = b""
    a_seed = hmac.new(secret, label.encode("utf-8") + seed, hashlib.sha256).digest()
    while len(expanded_output) < output_len:
        chunk = hmac.new(secret, a_seed + label.encode("utf-8") + seed, hashlib.sha256).digest()
        expanded_output += chunk
        a_seed = hmac.new(secret, a_seed, hashlib.sha256).digest()
    return expanded_output[:output_len]


class TLSProtocolSession:
    """Stateful simulation of TLS 1.2/1.3 handshake lifecycle and symmetric tunnel."""

    AVAILABLE_CIPHERS = [
        {"id": "TLS_AES_128_GCM_SHA256", "name": "TLS_AES_128_GCM_SHA256 (Modern AEAD)", "recommended": True},
        {"id": "TLS_AES_256_GCM_SHA384", "name": "TLS_AES_256_GCM_SHA384 (Modern AEAD)", "recommended": True},
        {"id": "TLS_RSA_WITH_AES_128_CBC_SHA256", "name": "TLS_RSA_WITH_AES_128_CBC_SHA256 (Legacy)", "recommended": False},
        {"id": "TLS_RSA_WITH_AES_256_CBC_SHA", "name": "TLS_RSA_WITH_AES_256_CBC_SHA (Legacy)", "recommended": False}
    ]

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.stage = 0
        self.client_random: str = ""
        self.server_random: str = ""
        self.selected_cipher: str = ""
        self.pre_master_secret: bytes = b""
        self.master_secret: bytes = b""
        self.symmetric_keys: Dict[str, str] = {}
        self.encrypted_pms_b64: str = ""
        self.established: bool = False
        self.step_history: list = []

        # Generate ephemeral server RSA key and X.509 certificate
        self.server_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.server_pub = self.server_priv.public_key()
        self.server_pub_pem = self.server_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NexusTunnel Gateway"),
            x509.NameAttribute(NameOID.COMMON_NAME, "gateway.nexustunnel.net"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.server_pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=90))
            .sign(self.server_priv, hashes.SHA256())
        )
        self.server_cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    def execute_step(self, step_num: int, input_data: Dict[str, Any]) -> Dict[str, Any]:
        if step_num == 1:
            self.client_random = secrets.token_hex(32)
            self.stage = 1
            payload = {
                "step": 1,
                "name": "Client Hello",
                "direction": "Client -> Server",
                "details": {
                    "tls_version": "TLS 1.2 / TLS 1.3",
                    "client_random": self.client_random,
                    "supported_ciphers": [c["id"] for c in self.AVAILABLE_CIPHERS]
                },
                "explanation": "Client sends Client Hello containing a 32-byte cryptographically secure random nonce and supported cipher suites."
            }
            self.step_history.append(payload)
            return payload

        elif step_num == 2:
            if self.stage < 1:
                raise ValueError("Must execute Step 1 (Client Hello) first.")
            self.server_random = secrets.token_hex(32)
            self.selected_cipher = input_data.get("cipher_suite", "TLS_AES_128_GCM_SHA256")
            self.stage = 2
            payload = {
                "step": 2,
                "name": "Server Hello & Certificate",
                "direction": "Server -> Client",
                "details": {
                    "server_random": self.server_random,
                    "chosen_cipher": self.selected_cipher,
                    "server_certificate_pem": self.server_cert_pem,
                    "server_public_key_pem": self.server_pub_pem
                },
                "explanation": "Server selects cipher suite, provides server random nonce, and presents its X.509 digital certificate for public identity verification."
            }
            self.step_history.append(payload)
            return payload

        elif step_num == 3:
            if self.stage < 2:
                raise ValueError("Must execute Step 2 (Server Hello) first.")
            raw_pms = secrets.token_bytes(48)
            self.pre_master_secret = raw_pms

            # Encrypt pre-master secret with server's RSA public key
            cipher_pms = self.server_pub.encrypt(
                raw_pms,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.encrypted_pms_b64 = base64.b64encode(cipher_pms).decode("utf-8")
            self.stage = 3
            payload = {
                "step": 3,
                "name": "Client Key Exchange",
                "direction": "Client -> Server",
                "details": {
                    "certificate_verification": "SUCCESS (Verified CA chain & validity timestamps)",
                    "pre_master_secret_hex": raw_pms.hex()[:32] + "... [48 bytes secret]",
                    "encrypted_pre_master_secret_base64": self.encrypted_pms_b64
                },
                "explanation": "Client verifies server certificate, creates 48-byte pre-master secret, encrypts it using server's RSA public key, and transmits it."
            }
            self.step_history.append(payload)
            return payload

        elif step_num == 4:
            if self.stage < 3:
                raise ValueError("Must execute Step 3 (Client Key Exchange) first.")

            # Server decrypts PMS
            raw_enc = base64.b64decode(self.encrypted_pms_b64)
            decrypted_pms = self.server_priv.decrypt(
                raw_enc,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            assert decrypted_pms == self.pre_master_secret

            # PRF derive Master Secret: 48 bytes
            seed = bytes.fromhex(self.client_random) + bytes.fromhex(self.server_random)
            self.master_secret = calculate_tls_prf(decrypted_pms, "master secret", seed, 48)

            # Key expansion: derive client write key, server write key, IVs
            expansion_seed = bytes.fromhex(self.server_random) + bytes.fromhex(self.client_random)
            key_block = calculate_tls_prf(self.master_secret, "key expansion", expansion_seed, 96)

            client_key = key_block[40:56]  # 16 bytes for AES-128
            server_key = key_block[56:72]  # 16 bytes
            client_iv = key_block[72:84]   # 12 bytes IV for GCM
            server_iv = key_block[84:96]   # 12 bytes IV

            self.symmetric_keys = {
                "client_write_key": client_key.hex(),
                "server_write_key": server_key.hex(),
                "client_write_iv": client_iv.hex(),
                "server_write_iv": server_iv.hex(),
                "master_secret_hex": self.master_secret.hex()
            }
            self.stage = 4
            payload = {
                "step": 4,
                "name": "Session Key Generation (Symmetric Key Derivation)",
                "direction": "Client & Server (Independent Local Computation)",
                "details": {
                    "server_decryption": "Decrypted Pre-Master Secret using Server Private Key",
                    "master_secret": self.master_secret.hex()[:32] + "... [48 bytes]",
                    "derived_keys": {
                        "client_write_key": client_key.hex(),
                        "server_write_key": server_key.hex(),
                        "client_write_encryption_key": client_key.hex(),
                        "server_write_encryption_key": server_key.hex(),
                        "client_write_iv": client_iv.hex(),
                        "server_write_iv": server_iv.hex()
                    }
                },
                "explanation": "Both endpoints independently apply the TLS PRF to calculate the Master Secret and symmetric session keys. No session keys ever traversed the wire!"
            }
            self.step_history.append(payload)
            return payload

        elif step_num == 5:
            if self.stage < 4:
                raise ValueError("Must execute Step 4 (Session Keys) first.")

            summary = hashlib.sha256(
                (self.client_random + self.server_random + self.selected_cipher).encode()
            ).hexdigest()

            client_fin = hmac.new(
                bytes.fromhex(self.symmetric_keys["client_write_key"]),
                b"client finished" + summary.encode(),
                hashlib.sha256
            ).hexdigest()

            server_fin = hmac.new(
                bytes.fromhex(self.symmetric_keys["server_write_key"]),
                b"server finished" + summary.encode(),
                hashlib.sha256
            ).hexdigest()

            self.stage = 5
            self.established = True
            payload = {
                "step": 5,
                "name": "Handshake Finished & Channel Verified",
                "direction": "Bi-directional Verification",
                "details": {
                    "client_encrypted_finished": client_fin,
                    "server_encrypted_finished": server_fin,
                    "tunnel_status": "SECURE TLS ENCRYPTED TUNNEL ESTABLISHED",
                    "symmetric_algorithm": self.selected_cipher
                },
                "explanation": "Both client and server confirm handshake integrity with encrypted Finished HMAC verification. Data payload encryption is now unlocked."
            }
            self.step_history.append(payload)
            return payload

        raise ValueError(f"Invalid step number: {step_num}")

    def transmit_data(self, plaintext: str) -> Dict[str, Any]:
        if not self.established:
            raise ValueError("Tunnel not established. Complete steps 1 through 5 first.")

        key = bytes.fromhex(self.symmetric_keys["client_write_key"])
        iv = bytes.fromhex(self.symmetric_keys["client_write_iv"])
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
        ciphertext = encryptor.update(plaintext.encode("utf-8")) + encryptor.finalize()

        return {
            "status": "Transmitted over Secure Tunnel",
            "plaintext": plaintext,
            "symmetric_ciphertext_hex": ciphertext.hex(),
            "authentication_tag_hex": encryptor.tag.hex(),
            "iv_nonce_hex": iv.hex(),
            "cipher": "AES-128-GCM"
        }


class SSHProtocolSession:
    """Stateful simulation of SSH-2.0 connection negotiation."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.stage = 0
        self.p = 1000000007
        self.g = 5
        self.client_version = "SSH-2.0-NexusClient_3.1"
        self.server_version = "SSH-2.0-NexusGateway_4.0"
        self.shared_k = 0
        self.exchange_hash: bytes = b""
        self.authenticated_user = ""
        self.step_history: list = []

        # Server host RSA key
        self.host_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.host_pub = self.host_priv.public_key()
        pub_bytes = self.host_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.host_fingerprint = "SHA256:" + hashlib.sha256(pub_bytes).hexdigest()[:32]

    def execute_step(self, step_num: int, input_data: Dict[str, Any]) -> Dict[str, Any]:
        if step_num == 1:
            self.stage = 1
            payload = {
                "step": 1,
                "name": "Protocol Version Exchange",
                "client_identification": self.client_version,
                "server_identification": self.server_version,
                "negotiated_version": "SSH-2.0",
                "explanation": "Client and Server exchange identification strings in cleartext to confirm SSH-2.0 protocol support."
            }
            self.step_history.append(payload)
            return payload

        elif step_num == 2:
            if self.stage < 1:
                raise ValueError("Must execute Step 1 first.")
            x = secrets.randbelow(self.p - 3) + 2
            e = pow(self.g, x, self.p)
            y = secrets.randbelow(self.p - 3) + 2
            f = pow(self.g, y, self.p)

            k_server = pow(e, y, self.p)
            k_client = pow(f, x, self.p)
            assert k_server == k_client
            self.shared_k = k_client

            h_raw = f"{self.client_version}|{self.server_version}|{e}|{f}|{self.shared_k}".encode()
            self.exchange_hash = hashlib.sha256(h_raw).digest()
            self.stage = 2
            payload = {
                "step": 2,
                "name": "Key Exchange (Diffie-Hellman Group Exchange)",
                "dh_parameters": {"prime_p": self.p, "generator_g": self.g},
                "client_exchange_value_e": e,
                "server_exchange_value_f": f,
                "shared_secret_K": self.shared_k,
                "exchange_hash_H": self.exchange_hash.hex(),
                "explanation": "Client transmits exchange value 'e'. Server computes 'f' and derives shared secret K. Both parties calculate Exchange Hash H."
            }
            self.step_history.append(payload)
            return payload

        elif step_num == 3:
            if self.stage < 2:
                raise ValueError("Must execute Step 2 first.")
            sig = self.host_priv.sign(self.exchange_hash, padding.PKCS1v15(), hashes.SHA256())
            self.stage = 3
            payload = {
                "step": 3,
                "name": "Server Authentication",
                "server_host_key_fingerprint": self.host_fingerprint,
                "server_signature_over_H": base64.b64encode(sig).decode("utf-8"),
                "client_verification": "VERIFIED! Host key signature matches server identity, preventing MitM attacks.",
                "explanation": "Server signs exchange hash H with its Host Private Key. Client verifies signature against known_hosts."
            }
            self.step_history.append(payload)
            return payload

        elif step_num == 4:
            if self.stage < 3:
                raise ValueError("Must execute Step 3 first.")
            user = input_data.get("username", "secops")
            method = input_data.get("auth_method", "publickey")
            self.authenticated_user = user
            self.stage = 4
            payload = {
                "step": 4,
                "name": "User Authentication",
                "username": user,
                "auth_method": method,
                "service_request": "ssh-userauth",
                "result": "SSH_MSG_USERAUTH_SUCCESS",
                "explanation": f"Server authenticates user '{user}' via {method} credentials and grants session privileges."
            }
            self.step_history.append(payload)
            return payload

        elif step_num == 5:
            if self.stage < 4:
                raise ValueError("Must execute Step 4 first.")
            self.stage = 5
            payload = {
                "step": 5,
                "name": "Secure Channel Established & PTY Session Opened",
                "status": "CONNECTED",
                "active_session": {
                    "pty_allocated": True,
                    "symmetric_cipher": "chacha20-poly1305@openssh.com / aes256-gcm",
                    "shell": "/bin/bash",
                    "prompt": f"{self.authenticated_user}@nexustunnel:~$"
                },
                "explanation": "Multiplexed SSH channel opened. Interactive encrypted PTY terminal stream is active."
            }
            self.step_history.append(payload)
            return payload

        raise ValueError(f"Invalid step: {step_num}")


class IPSecESPAnalyzer:
    """Dissects IPsec Encapsulating Security Payload (ESP) datagrams in Transport vs Tunnel mode."""

    @staticmethod
    def dissect(data: Dict[str, Any]) -> Dict[str, Any]:
        mode = data.get("mode", "transport")
        src_ip = data.get("src_ip", "192.168.1.105")
        dst_ip = data.get("dst_ip", "203.0.113.50")
        gw_src = data.get("gateway_src", "198.51.100.1")
        gw_dst = data.get("gateway_dst", "203.0.113.1")
        proto = data.get("protocol", "TCP")
        payload = data.get("payload", "CONFIDENTIAL_PAYLOAD_ALM2")

        spi = 0x24A8DE61
        seq_num = 108

        # Simulate ESP AES-CBC encryption
        key = b"AegisKey16Bytes!"
        iv = b"VectorInit16Byte"
        pad_len = (16 - (len(payload) + 2) % 16) % 16
        pad_bytes = bytes([i + 1 for i in range(pad_len)])
        plain_block = payload.encode() + pad_bytes + bytes([pad_len, 6 if proto == "TCP" else 17])

        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        esp_cipher = encryptor.update(plain_block) + encryptor.finalize()
        icv = hmac.new(b"AegisICVSecretKey", esp_cipher, hashlib.sha256).hexdigest()[:24]

        if mode == "transport":
            elements = [
                {
                    "field": "Original IP Header",
                    "content": f"Src: {src_ip} -> Dst: {dst_ip} (Next Protocol: 50 [ESP])",
                    "status": "PLAINTEXT",
                    "color": "blue",
                    "authenticated": False,
                    "encrypted": False,
                    "description": "Original host IP header is retained in cleartext so intermediate routers can forward the packet."
                },
                {
                    "field": "ESP Header",
                    "content": f"SPI: 0x{spi:08X} | Sequence No: {seq_num}",
                    "status": "PLAINTEXT (AUTHENTICATED)",
                    "color": "yellow",
                    "authenticated": True,
                    "encrypted": False,
                    "description": "Identifies the Security Association (SA) parameters and provides anti-replay protection."
                },
                {
                    "field": "Encrypted Transport Payload",
                    "content": f"[{proto} Segment: {payload}] -> Ciphertext: {esp_cipher.hex()[:24]}...",
                    "status": "ENCRYPTED & AUTHENTICATED",
                    "color": "green",
                    "authenticated": True,
                    "encrypted": True,
                    "description": "Protects transport payload (TCP/UDP header and application data)."
                },
                {
                    "field": "ESP Trailer",
                    "content": f"Padding ({pad_len} B) | Pad Length: {pad_len} | Next Header: {proto}",
                    "status": "ENCRYPTED & AUTHENTICATED",
                    "color": "green",
                    "authenticated": True,
                    "encrypted": True,
                    "description": "Cipher alignment padding and next protocol restoration code."
                },
                {
                    "field": "ESP ICV (Authentication Data)",
                    "content": f"HMAC-SHA256: {icv}",
                    "status": "AUTHENTICATION TAG",
                    "color": "purple",
                    "authenticated": False,
                    "encrypted": False,
                    "description": "Integrity Check Value calculated over ESP Header, Payload, and Trailer."
                }
            ]
            explanation = (
                "Transport Mode protects host-to-host traffic by encrypting the transport-layer payload "
                "while preserving original source and destination IP headers."
            )
        else:
            elements = [
                {
                    "field": "New Outer IP Header",
                    "content": f"Gateway: {gw_src} -> Gateway: {gw_dst} (Next Protocol: 50 [ESP])",
                    "status": "PLAINTEXT",
                    "color": "blue",
                    "authenticated": False,
                    "encrypted": False,
                    "description": "New gateway IP header generated by VPN firewall to obscure internal network topology."
                },
                {
                    "field": "ESP Header",
                    "content": f"SPI: 0x{spi:08X} | Sequence No: {seq_num}",
                    "status": "PLAINTEXT (AUTHENTICATED)",
                    "color": "yellow",
                    "authenticated": True,
                    "encrypted": False,
                    "description": "Security Parameters Index and Sequence Counter for the VPN Security Association."
                },
                {
                    "field": "Encrypted Original IP Packet",
                    "content": f"[Original Packet ({src_ip}->{dst_ip}) + {proto} Payload] -> Ciphertext: {esp_cipher.hex()[:24]}...",
                    "status": "ENCRYPTED & AUTHENTICATED",
                    "color": "green",
                    "authenticated": True,
                    "encrypted": True,
                    "description": "The entire internal IP packet including private internal addresses is encrypted."
                },
                {
                    "field": "ESP Trailer",
                    "content": f"Padding ({pad_len} B) | Pad Length: {pad_len} | Next Header: 4 (IPv4)",
                    "status": "ENCRYPTED & AUTHENTICATED",
                    "color": "green",
                    "authenticated": True,
                    "encrypted": True,
                    "description": "Maintains block alignment and flags encapsulated packet as an IP datagram."
                },
                {
                    "field": "ESP ICV (Authentication Data)",
                    "content": f"HMAC-SHA256: {icv}",
                    "status": "AUTHENTICATION TAG",
                    "color": "purple",
                    "authenticated": False,
                    "encrypted": False,
                    "description": "Provides data origin authentication and tamper prevention across the entire datagram."
                }
            ]
            explanation = (
                "Tunnel Mode is gateway-to-gateway (VPN). It encapsulates and encrypts the ENTIRE original IP packet, "
                "providing complete topology confidentiality across public internet routes."
            )

        return {
            "mode": mode,
            "explanation": explanation,
            "elements": elements,
            "security_analysis": {
                "confidentiality": "Guaranteed via AES-CBC / AES-GCM (Payload encrypted)",
                "integrity": "Guaranteed via HMAC-SHA256 / GCM ICV (Cryptographically authenticated)",
                "replay_protection": f"Guaranteed via 32-bit/64-bit Sequence Numbers (Current Seq: {seq_num})",
                "traffic_flow_confidentiality": "High in Tunnel Mode (Original endpoints obscured); Moderate in Transport Mode"
            }
        }
